//! The parts of the container firewall that change while it runs. The
//! blocklist, which the helper changes as it changes: the `blocked4` and
//! `blocked6` sets of the nftables table firewall.sh loads, or with legacy
//! iptables, the drop rules of its VPN_BLOCK chains. And the site-to-site
//! part, which `sites` plans and the helper and `ocpanel site-sync` load.

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(any(test, debug_assertions))]
use std::sync::{Arc, Mutex};

use crate::countries::RuleInput;
use crate::net::Network;
use crate::sites::Plan;

/// The firewall the helper changes.
pub trait Firewall: Send {
    /// Drops every packet from `network` from now on.
    fn block(&mut self, network: &Network) -> Result<(), String>;
    /// Admits packets from `network` again.
    fn unblock(&mut self, network: &Network) -> Result<(), String>;
    /// Makes the site-to-site part match the plan `plan` returns. `plan`
    /// runs under the lock that keeps two of these from interleaving, so the
    /// sessions it reads are still the sessions when the plan loads.
    fn sync_sites(&mut self, plan: &mut dyn FnMut() -> Result<Plan, String>) -> Result<(), String>;
    /// Makes the country rules match `input`, or removes them while it is
    /// none.
    fn load_countries(&mut self, input: Option<&RuleInput>) -> Result<(), String>;
    /// The firewall firewall.sh loaded.
    fn backend(&self) -> Backend;
}

/// The firewall firewall.sh loaded, as the entrypoint passes it in
/// PANEL_FIREWALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Nftables,
    Iptables,
}

impl Backend {
    pub fn parse(value: &str) -> Result<Backend, String> {
        match value {
            "nftables" => Ok(Backend::Nftables),
            "iptables" => Ok(Backend::Iptables),
            other => Err(format!("'{other}' is not nftables or iptables")),
        }
    }
}

/// The nftables tables firewall.sh loads, one for filtering and one for
/// each family's address translation.
pub const TABLE: &str = "vpn_gateway";

/// The container's own firewall, changed with nft or iptables-legacy.
#[cfg(unix)]
pub struct System {
    pub backend: Backend,
    /// The file whose lock keeps the helper's site syncs and those of
    /// ocserv's session scripts from interleaving.
    pub site_lock: PathBuf,
    /// The config directory, where an admin's MaxMind database lives.
    pub config_dir: PathBuf,
}

#[cfg(unix)]
impl System {
    fn change(&self, network: &Network, add: bool) -> Result<(), String> {
        let text = network.to_string();
        let (program, args): (&str, Vec<&str>) = match self.backend {
            Backend::Nftables => {
                let set = if network.is_ipv4() {
                    "blocked4"
                } else {
                    "blocked6"
                };
                let verb = if add { "add" } else { "delete" };
                (
                    "nft",
                    vec![verb, "element", "inet", TABLE, set, "{", &text, "}"],
                )
            }
            Backend::Iptables => {
                let program = if network.is_ipv4() {
                    "iptables-legacy"
                } else {
                    "ip6tables-legacy"
                };
                let verb = if add { "-A" } else { "-D" };
                (
                    program,
                    vec!["-w", verb, "VPN_BLOCK", "-s", &text, "-j", "DROP"],
                )
            }
        };
        run(program, &args, b"")?;
        Ok(())
    }

    /// Loads the site-to-site part `plan` describes: with nftables in one
    /// transaction, with iptables one family at a time.
    fn load_sites(&self, plan: &Plan) -> Result<(), String> {
        match self.backend {
            Backend::Nftables => {
                let sets = run("nft", &["list", "sets", "inet"], b"")?;
                let tables = run("nft", &["list", "tables"], b"")?;
                let (nat4, nat6) = crate::sites::nat_tables(&tables);
                let commands =
                    crate::sites::nft_commands(plan, &crate::sites::sets_in(&sets), nat4, nat6);
                run("nft", &["-f", "-"], commands.as_bytes())?;
            }
            Backend::Iptables => {
                for (v4, program) in [
                    (true, "iptables-legacy-restore"),
                    (false, "ip6tables-legacy-restore"),
                ] {
                    if !v4 && !std::path::Path::new("/proc/sys/net/ipv6").exists() {
                        continue;
                    }
                    let input = crate::sites::iptables_input(plan, v4);
                    run(program, &["--noflush"], input.as_bytes())?;
                }
            }
        }
        Ok(())
    }
}

/// Runs a firewall command and returns what it printed; an error when it
/// fails.
#[cfg(unix)]
fn run(program: &str, args: &[&str], input: &[u8]) -> Result<String, String> {
    let ran = crate::command::run(program, args, input)?;
    if !ran.status.success() {
        return Err(ran.failed(&format!("{program} {}", args.join(" "))));
    }
    Ok(ran.stdout)
}

#[cfg(unix)]
impl Firewall for System {
    fn block(&mut self, network: &Network) -> Result<(), String> {
        self.change(network, true)
    }

    fn unblock(&mut self, network: &Network) -> Result<(), String> {
        self.change(network, false)
    }

    fn sync_sites(&mut self, plan: &mut dyn FnMut() -> Result<Plan, String>) -> Result<(), String> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.site_lock)
            .map_err(|error| format!("{}: {error}", self.site_lock.display()))?;
        lock.lock()
            .map_err(|error| format!("{}: {error}", self.site_lock.display()))?;
        let loaded = plan().and_then(|plan| self.load_sites(&plan));
        drop(lock);
        loaded
    }

    fn load_countries(&mut self, input: Option<&RuleInput>) -> Result<(), String> {
        match (self.backend, input) {
            (Backend::Nftables, input) => {
                crate::countries::load(input, &crate::countries::database_path(&self.config_dir))
            }
            (Backend::Iptables, None) => Ok(()),
            (Backend::Iptables, Some(_input)) => Err(crate::countries::NEEDS_NFTABLES.to_owned()),
        }
    }

    fn backend(&self) -> Backend {
        self.backend
    }
}

/// A firewall that only records the networks it drops and the last
/// site-to-site plan it loaded, for the tests and the development server.
#[cfg(any(test, debug_assertions))]
#[derive(Clone, Default)]
pub struct Fake {
    pub blocked: Arc<Mutex<Vec<String>>>,
    pub sites: Arc<Mutex<Option<Plan>>>,
    /// The country rules each load asked for, in order.
    pub countries: Arc<Mutex<Vec<Option<RuleInput>>>>,
    /// Whether it stands for legacy iptables rather than nftables.
    pub iptables: bool,
}

#[cfg(any(test, debug_assertions))]
impl Fake {
    fn with_list<T>(&self, change: impl FnOnce(&mut Vec<String>) -> T) -> Result<T, String> {
        let mut blocked = self
            .blocked
            .lock()
            .map_err(|error| format!("the fake firewall is unusable: {error}"))?;
        Ok(change(&mut blocked))
    }
}

#[cfg(any(test, debug_assertions))]
impl Firewall for Fake {
    fn block(&mut self, network: &Network) -> Result<(), String> {
        self.with_list(|blocked| blocked.push(network.to_string()))
    }

    fn unblock(&mut self, network: &Network) -> Result<(), String> {
        let text = network.to_string();
        self.with_list(|blocked| blocked.retain(|known| *known != text))
    }

    fn sync_sites(&mut self, plan: &mut dyn FnMut() -> Result<Plan, String>) -> Result<(), String> {
        let plan = plan()?;
        let mut loaded = self
            .sites
            .lock()
            .map_err(|error| format!("the fake firewall is unusable: {error}"))?;
        *loaded = Some(plan);
        Ok(())
    }

    fn load_countries(&mut self, input: Option<&RuleInput>) -> Result<(), String> {
        let mut loads = self
            .countries
            .lock()
            .map_err(|error| format!("the fake firewall is unusable: {error}"))?;
        loads.push(input.cloned());
        Ok(())
    }

    fn backend(&self) -> Backend {
        if self.iptables {
            Backend::Iptables
        } else {
            Backend::Nftables
        }
    }
}
