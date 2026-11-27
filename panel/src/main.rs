//! ocpanel, the web administration panel of docker-openconnect.
//!
//! `check-config` validates the panel's settings and reports what they
//! enable; the entrypoint runs it before it starts the panel. `helper` is the
//! root side of the panel, and it starts `web`, the unprivileged side.
//!
//! The helper and the web process run only on Linux. Elsewhere only the tests
//! and the development server run, so the code that only those two processes
//! call is unused there.
#![cfg_attr(not(unix), allow(dead_code))]

mod alert_send;
mod alerts;
mod app;
mod assets;
mod audit;
mod blocklist;
mod client;
mod clientcerts;
mod clock;
mod command;
mod config;
mod countries;
#[cfg(debug_assertions)]
mod dev;
mod events;
mod exposure;
mod extras;
mod files;
mod firewall;
mod geoip;
#[cfg(unix)]
mod helper;
mod history;
mod icons;
mod kit;
#[cfg(unix)]
mod launch;
mod location;
mod net;
mod occtl;
mod otpfile;
mod overrides;
mod passkey;
mod passphrase;
mod password;
mod portal;
mod protocol;
mod qr;
mod secret;
mod server;
mod server_settings;
mod serverconf;
mod service;
mod sessions;
mod sites;
mod store;
#[cfg(test)]
mod testdir;
mod tls;
mod totp;
mod units;
mod vpnusers;
#[cfg(unix)]
mod web;

use std::process::ExitCode;

const USAGE: &str = "\
Usage: ocpanel <command>

Commands:
  check-config      Check the PANEL_* settings and report what they enable
  allowed-networks  Print the networks that may reach the panel, one per line
  port              Print the port the panel listens on
  blocked-networks  Print the networks the firewall blocklist holds, one per line
  check-address <address>
                    Exit with 1, naming the block, when the address is on the
                    firewall blocklist; ocserv's session script refuses it
  check-user <name> Exit with 1, saying why, when certificates sign users in
                    and the user is locked or not in the password file
  check-location    Exit with 1, saying why, when the location checks refuse
                    the VPN sign-in ocserv's session script reports; a check
                    that cannot run lets it in
  site-sync [connect | disconnect]
                    Bring the firewall's site-to-site part up to date: at
                    start, or for the session ocserv's session script reports
  country-sync      Load the country rules, the environment's or the panel's,
                    into the firewall, or remove them while the rule is off
  geoip-update      With a MaxMind key, download GeoLite2 Country when there is
                    no copy or the copy is three days old
  helper           Run the root side of the panel, which starts the web side
  web <socket>      Run the unprivileged side of the panel (started by the helper)
  log-relay         Copy ocserv's log from standard input to standard error, and
                    record its failed sign-ins and bans in $PANEL_EVENTS_DIR
  record-event      Record the connect or disconnect that ocserv's session
                    script reports in $PANEL_EVENTS_DIR
  --version         Print the version
  --help            Print this help
";

/// Exit status for a usage error or an invalid setting.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [command] if command == "--version" || command == "-V" => {
            println!("ocpanel {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [command] if command == "--help" || command == "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        [command] if command == "check-config" => check_config(),
        [command] if command == "allowed-networks" => allowed_networks(),
        [command] if command == "port" => port(),
        [command] if command == "portal-port" => portal_port(),
        [command] if command == "blocked-networks" => blocked_networks(),
        [command, address] if command == "check-address" => {
            check_address(&address.to_string_lossy())
        }
        [command, name] if command == "check-user" => check_user(&name.to_string_lossy()),
        #[cfg(unix)]
        [command] if command == "check-location" => check_location(),
        [command] if command == "portal-networks" => portal_networks(),
        [command] if command == "log-relay" => log_relay(),
        [command] if command == "record-event" => record_event(),
        #[cfg(unix)]
        [command] if command == "site-sync" => site_sync(None),
        #[cfg(unix)]
        [command, reason] if command == "site-sync" => site_sync(Some(&reason.to_string_lossy())),
        #[cfg(unix)]
        [command] if command == "country-sync" => {
            match countries::sync(&|name: &str| std::env::var_os(name)) {
                Ok(None) => ExitCode::SUCCESS,
                Ok(Some(warning)) => {
                    eprintln!("{warning}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ocpanel country-sync: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        #[cfg(unix)]
        [command] if command == "geoip-update" => geoip_update(),
        #[cfg(debug_assertions)]
        [command, port] if command == "dev-server" => dev::run(&port.to_string_lossy()),
        #[cfg(unix)]
        [command] if command == "helper" => helper::run(),
        #[cfg(unix)]
        [command, socket] if command == "web" => web::run(std::path::Path::new(socket)),
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Copies ocserv's log from standard input to standard error, line by line,
/// and records the failed sign-ins and bans it reports. Ends with ocserv's
/// log; the entrypoint stops the container if it ends sooner.
fn log_relay() -> ExitCode {
    let spool = match events::spool_dir(|name: &str| std::env::var_os(name)) {
        Ok(dir) => events::Spool::new(dir),
        Err(error) => {
            eprintln!("ocpanel log-relay: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stderr().lock();
    match events::relay(&mut input, &mut output, &spool, clock::now) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel log-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Records the connect or disconnect that ocserv's session script reports,
/// from the variables ocserv sets for it.
fn record_event() -> ExitCode {
    let variable =
        |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    let recorded = events::spool_dir(|name: &str| std::env::var_os(name)).and_then(|dir| {
        match events::What::from_script(variable)? {
            Some(what) => events::Spool::new(dir).write(
                &events::Event {
                    time: clock::now()?,
                    what,
                },
                0,
            ),
            None => Ok(()),
        }
    });
    match recorded {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel record-event: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the networks that may reach the panel, one per line: the list the
/// web process admits, for the container firewall's rules on the panel port.
fn allowed_networks() -> ExitCode {
    let listed = config::Settings::from_env(|name: &str| std::env::var_os(name))
        .map_err(|error| error.to_string())
        .and_then(|settings| exposure::on_this_host(&settings));
    match listed {
        Ok(networks) => {
            for network in networks {
                println!("{network}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Prints the port the panel listens on, in decimal, for the container
/// firewall's rules on it.
fn port() -> ExitCode {
    match config::Settings::from_env(|name: &str| std::env::var_os(name)) {
        Ok(settings) => {
            println!("{}", settings.port);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Prints the networks the firewall blocklist holds in force now, one per
/// line, for the container firewall to load at start.
fn blocked_networks() -> ExitCode {
    let listed = config::Settings::from_env(|name: &str| std::env::var_os(name))
        .map_err(|error| error.to_string())
        .and_then(|settings| {
            let list = blocklist::Blocklist::open(
                &settings.data_dir.join("blocklist.json"),
                settings.blocking,
            )?;
            let now = clock::now()?;
            Ok(list
                .active(now)
                .map(|block| block.network.clone())
                .collect::<Vec<String>>())
        });
    match listed {
        Ok(networks) => {
            for network in networks {
                println!("{network}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Exits with 0 when no block of the firewall blocklist in force covers
/// `address`, and with 1, printing the block, when one does. ocserv's session
/// script calls it with IP_REAL, the address a connecting client comes from,
/// which behind a load balancer only ocserv knows: the firewall sees the
/// balancer's address.
fn check_address(address: &str) -> ExitCode {
    let host = address
        .split_once('%')
        .map_or(address, |(host, _scope)| host);
    let verdict = host
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("'{address}' is not an IP address: {error}"))
        .and_then(|address| {
            let settings = config::Settings::from_env(|name: &str| std::env::var_os(name))
                .map_err(|error| error.to_string())?;
            let list = blocklist::Blocklist::open(
                &settings.data_dir.join("blocklist.json"),
                settings.blocking,
            )?;
            let now = clock::now()?;
            Ok(list
                .blocking(address, now)?
                .map(|block| format!("the admin panel's blocklist holds {}", block.network)))
        });
    match verdict {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(block)) => {
            println!("{block}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Exits with 0 when certificates do not sign users in, or when `name` is a
/// VPN user who is not locked, and with 1, printing why, otherwise. ocserv's
/// session script calls it with USERNAME: a certificate signs a user in
/// without ocserv reading the password file, where a user is locked or
/// removed.
fn check_user(name: &str) -> ExitCode {
    let verdict = config::Settings::from_env(|variable: &str| std::env::var_os(variable))
        .map_err(|error| error.to_string())
        .and_then(|settings| {
            if !serverconf::ServerConfig::read(&settings.ocserv_config)?.certificate_sign_in() {
                return Ok(None);
            }
            let path = &settings.passwd_file;
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let users = vpnusers::parse_passwd(&text, &[])?;
            Ok(match users.iter().find(|user| user.name == name) {
                None => Some(format!("{name} is not a VPN user")),
                Some(user) if user.locked => Some(format!("{name} is locked")),
                Some(_) => None,
            })
        });
    match verdict {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(reason)) => {
            println!("{reason}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Asks the helper whether the VPN sign-in ocserv's session script reports
/// fits where the user signs in from. Exits with 1, printing why, when the
/// location checks refuse it, and with 0 otherwise, printing a line for the
/// container log when the sign-in is unusual or was let in unchecked. A
/// check that gets no answer from the helper leaves an event for the panel
/// that says it could not run.
#[cfg(unix)]
fn check_location() -> ExitCode {
    use protocol::LocationVerdict;

    let variable =
        |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    let asked =
        protocol::VpnSignIn::from_script(variable).and_then(|sign_in| ask_location(&sign_in));
    match asked {
        Ok(None | Some(LocationVerdict::Allow)) => ExitCode::SUCCESS,
        Ok(Some(LocationVerdict::Flag { score, reasons })) => {
            println!(
                "unusual for the location checks, scored {score} of 100: {}",
                reasons.join("; ")
            );
            ExitCode::SUCCESS
        }
        Ok(Some(LocationVerdict::Refuse { score, reasons })) => {
            println!(
                "the location checks scored the sign-in {score} of 100: {}",
                reasons.join("; ")
            );
            ExitCode::FAILURE
        }
        Ok(Some(LocationVerdict::Unchecked { problem })) => {
            println!("let in without a location check, which could not run: {problem}");
            ExitCode::SUCCESS
        }
        Err(problem) => {
            println!("let in without a location check, which could not run: {problem}");
            let recorded = match variable("USERNAME") {
                Some(user) => record_unchecked(user, variable("IP_REAL"), problem),
                None => Err("ocserv named no user".to_owned()),
            };
            if let Err(error) = recorded {
                println!("the admin panel could not record that: {error}");
            }
            ExitCode::SUCCESS
        }
    }
}

/// Leaves an event in $PANEL_EVENTS_DIR saying that `user`'s VPN sign-in
/// was let in without a location check, which could not run.
#[cfg(unix)]
fn record_unchecked(user: String, from: Option<String>, problem: String) -> Result<(), String> {
    let dir = events::spool_dir(|name: &str| std::env::var_os(name))?;
    events::Spool::new(dir).write(
        &events::Event {
            time: clock::now()?,
            what: events::What::LocationUnchecked {
                user,
                from,
                problem,
            },
        },
        0,
    )
}

/// The helper's verdict on `sign_in`, asked on the location socket with
/// VPN_CHECK_WAIT_SECONDS to answer; none while the location checks are off,
/// when the helper is not asked.
#[cfg(unix)]
fn ask_location(
    sign_in: &protocol::VpnSignIn,
) -> Result<Option<protocol::LocationVerdict>, String> {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    let get = |name: &str| std::env::var_os(name);
    let settings = config::Settings::from_env(get).map_err(|error| error.to_string())?;
    let environment = location::Environment::from_env(&get)?;
    if !location::Stored::open(&settings.data_dir.join(location::STORED_FILE))?
        .in_force(&environment)
        .on
    {
        return Ok(None);
    }
    let path = settings.runtime_dir.join(helper::LOCATION_SOCKET_NAME);
    let wait = Duration::from_secs(location::VPN_CHECK_WAIT_SECONDS);
    let started = Instant::now();
    let mut stream = UnixStream::connect(&path)
        .map_err(|error| format!("the admin panel's helper is not reachable: {error}"))?;
    stream
        .set_read_timeout(Some(wait))
        .and_then(|()| stream.set_write_timeout(Some(wait)))
        .map_err(|error| format!("the connection to the helper could not be set up: {error}"))?;
    protocol::encode(sign_in).and_then(|bytes| protocol::write_message(&mut stream, &bytes))?;
    let answer = match protocol::read_message(&mut stream) {
        Ok(Some(answer)) => answer,
        Ok(None) => {
            return Err("the admin panel's helper closed the connection unanswered".to_owned());
        }
        Err(error) if started.elapsed() >= wait => {
            return Err(format!(
                "the admin panel's helper gave no answer within {} seconds: {error}",
                location::VPN_CHECK_WAIT_SECONDS
            ));
        }
        Err(error) => return Err(format!("the admin panel's helper did not answer: {error}")),
    };
    protocol::decode(&answer).map(Some)
}

/// Fetches MaxMind GeoLite2 at start when a key is set and the copy is
/// missing or due. What it did goes to standard output; a warning about a
/// copy nothing keeps current, or a download that failed, goes to standard
/// error with a failure status, and the firewall script reports it.
#[cfg(unix)]
fn geoip_update() -> ExitCode {
    let get = |name: &str| std::env::var_os(name);
    let updated = config::config_dir(&get)
        .map_err(|error| error.to_string())
        .and_then(|config_dir| geoip::update(&config_dir, geoip::environment_key(&get)?));
    match updated {
        Ok(geoip::Said::Nothing) => ExitCode::SUCCESS,
        Ok(geoip::Said::Done(done)) => {
            println!("{done}");
            ExitCode::SUCCESS
        }
        Ok(geoip::Said::Warning(warning)) => {
            eprintln!("{warning}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!(
                "MaxMind GeoLite2 was not downloaded, so the countries come from the copy in \
                 place or DB-IP Lite: {error}"
            );
            ExitCode::FAILURE
        }
    }
}

/// Brings the firewall's site-to-site part up to date: at start with no
/// `reason`, before ocserv runs, and from ocserv's session script with
/// `connect` or `disconnect`, for the session its variables describe.
#[cfg(unix)]
fn site_sync(reason: Option<&str>) -> ExitCode {
    match sync_sites(reason) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel site-sync: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn sync_sites(reason: Option<&str>) -> Result<(), String> {
    use firewall::Firewall;
    use occtl::Control;

    let settings = config::SiteSync::from_env(|name: &str| std::env::var_os(name))
        .map_err(|error| error.to_string())?;
    let event = match reason {
        Some(reason) => Some(sites::Event::from_script(reason, |name: &str| {
            std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
        })?),
        None => None,
    };
    let rules = sites::Sites::open(&settings.sites_file)?;
    if event.is_some() && rules.groups().is_empty() {
        return Ok(());
    }
    let config = serverconf::ServerConfig::read(&settings.ocserv_config)?;
    let directories = overrides::Directories::of(&config);
    let clients = sites::clients(&config, &directories)?;
    let published = directories.publishers()?;
    let mut system = firewall::System {
        backend: settings.firewall,
        site_lock: settings.site_lock,
        config_dir: config::config_dir(&|name: &str| std::env::var_os(name))
            .map_err(|error| error.to_string())?,
    };
    system.sync_sites(&mut || {
        let sessions = if event.is_some() {
            sites::Member::of_sessions(&occtl::Occtl.sessions()?)?
        } else {
            Vec::new()
        };
        Ok(sites::Plan::new(
            &rules,
            clients.clone(),
            &published,
            &sessions,
            event.as_ref(),
            settings.source_check,
        ))
    })
}

/// Prints the user portal's port, in decimal, when the portal is on, for the
/// container firewall's rules on it; nothing when it is off.
fn portal_port() -> ExitCode {
    match config::Settings::from_env(|name: &str| std::env::var_os(name)) {
        Ok(settings) => {
            if let Some(portal) = settings.portal {
                println!("{}", portal.port);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Prints the networks PANEL_PORTAL_NETWORKS narrows the user portal to, one
/// per line; nothing when the portal is off or open to every address.
fn portal_networks() -> ExitCode {
    match config::Settings::from_env(|name: &str| std::env::var_os(name)) {
        Ok(settings) => {
            for network in settings
                .portal
                .into_iter()
                .flat_map(|portal| portal.networks)
            {
                println!("{network}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ocpanel: {error}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Prints the panel's address and what its settings enable.
fn check_config() -> ExitCode {
    let settings = match config::Settings::from_env(|name: &str| std::env::var_os(name)) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("ocpanel: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    println!(
        "panel: https://{}:{}",
        settings.host.authority(),
        settings.port
    );
    match passkey::relying_party(
        &settings.host,
        settings.port,
        std::time::Duration::from_secs(settings.second_factor_minutes * 60),
    )
    .and_then(|party| party.self_test().map(|()| party))
    {
        Ok(party) => println!("passkeys: available, bound to {}", party.id),
        Err(reason) => println!("passkeys: unavailable, {reason}; TOTP is the second factor"),
    }
    if settings.lan_networks.is_empty() {
        println!("lan networks: none; a second factor is required from every address");
    } else {
        let networks: Vec<String> = settings
            .lan_networks
            .iter()
            .map(ToString::to_string)
            .collect();
        println!(
            "lan networks: {}; a password alone signs in from them",
            networks.join(", ")
        );
    }
    println!(
        "sessions: end after {} idle minutes or {} hours",
        settings.session_idle_minutes, settings.session_max_hours
    );
    println!(
        "sign-in: {} wrong passwords lock an account for {} minutes",
        settings.max_failures, settings.lockout_minutes
    );
    match &settings.portal {
        None => println!("user portal: off"),
        Some(portal) => {
            let reach = if portal.networks.is_empty() {
                "every address".to_owned()
            } else {
                let networks: Vec<String> =
                    portal.networks.iter().map(ToString::to_string).collect();
                networks.join(", ")
            };
            println!(
                "user portal: https://{}:{}, reachable from {reach}",
                settings.vpn_address.host.authority(),
                portal.port
            );
        }
    }
    ExitCode::SUCCESS
}
