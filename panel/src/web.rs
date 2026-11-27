//! `ocpanel web <socket>`, the unprivileged side of the panel. The helper
//! starts it as the panel's own account with an empty environment and writes
//! the launch message to its standard input. It refuses to run as root,
//! cannot gain privileges, and ends when the helper does. It reads the launch
//! message, checks the helper with a ping, and serves HTTPS on the panel's
//! port.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use nix::sys::prctl;
use nix::sys::signal::Signal;
use nix::unistd::{Pid, geteuid, getppid, getuid};
use tokio::task::JoinSet;

use crate::app::{self, App};
use crate::assets::Assets;
use crate::client;
use crate::launch::Launch;
use crate::net::Network;
use crate::protocol::{Request, Response};
use crate::{server, tls};

pub fn run(socket: &Path) -> ExitCode {
    match serve(socket) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel web: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve(socket: &Path) -> Result<(), String> {
    if getuid().is_root() || geteuid().is_root() {
        return Err("the web process must not run as root".to_owned());
    }
    prctl::set_no_new_privs().map_err(|error| format!("no_new_privs could not be set: {error}"))?;
    prctl::set_pdeathsig(Signal::SIGTERM)
        .map_err(|error| format!("the parent-death signal could not be set: {error}"))?;
    if getppid() == Pid::from_raw(1) {
        return Err("the helper exited before the web process started".to_owned());
    }
    let launch = Launch::read_from(std::io::stdin().lock())?;
    let tls = tls::server_config(
        &launch.chain_pem,
        &launch.key_pem,
        launch.client_ca_pem.as_deref(),
    )?;
    let allowed = launch
        .allowed
        .iter()
        .map(|text| Network::parse(text))
        .collect::<Result<Vec<_>, _>>()?;
    let helper = client::over_socket(socket.to_owned());
    let port = launch.port;
    let assets = Arc::new(Assets::new());
    let app = App {
        helper: helper.clone(),
        host: launch.host.clone(),
        other_hosts: Vec::new(),
        site: "panel",
        scheme: "https",
        assets: Arc::clone(&assets),
        ocserv_version: launch.ocserv_version.clone(),
        instance: launch.instance.clone(),
        min_password_length: launch.min_password_length,
    };
    let portal = match &launch.portal {
        None => None,
        Some(portal) => Some(Portal {
            port: portal.port,
            tls: tls::server_config(&portal.chain_pem, &portal.key_pem, None)?,
            allowed: portal_networks(&portal.allowed)?,
            app: App {
                helper: helper.clone(),
                host: portal.host.clone(),
                other_hosts: vec![launch.host.clone()],
                site: "portal",
                scheme: "https",
                assets,
                ocserv_version: launch.ocserv_version.clone(),
                instance: launch.instance.clone(),
                min_password_length: launch.min_password_length,
            },
        }),
    };
    drop(launch);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the runtime could not start: {error}"))?;
    runtime.block_on(async move {
        match helper.call(Request::Ping).await? {
            Response::Pong { version } => say(&format!(
                "panel: web process running as uid {}, connected to helper {version}",
                getuid()
            ))?,
            other => return Err(format!("the helper answered a ping with {other:?}")),
        }
        let listener = server::bind(port).await?;
        say(&format!("panel: serving https on port {port}"))?;
        let mut servers = JoinSet::new();
        servers.spawn(server::serve(listener, tls, allowed, app::router(app)));
        if let Some(portal) = portal {
            let listener = server::bind(portal.port).await?;
            say(&format!(
                "panel: serving the VPN user portal on port {}",
                portal.port
            ))?;
            servers.spawn(server::serve(
                listener,
                portal.tls,
                portal.allowed,
                app::portal_router(portal.app),
            ));
        }
        match servers.join_next().await {
            Some(Ok(ended)) => ended,
            Some(Err(error)) => Err(format!("a server stopped: {error}")),
            None => Err("no server was started".to_owned()),
        }
    })
}

/// The VPN user portal's listener and pages.
struct Portal {
    port: u16,
    tls: Arc<rustls::ServerConfig>,
    allowed: Vec<Network>,
    app: App,
}

/// The networks PANEL_PORTAL_NETWORKS lets reach the portal: every address
/// when it names none.
fn portal_networks(listed: &[String]) -> Result<Vec<Network>, String> {
    if listed.is_empty() {
        return ["0.0.0.0/0", "::/0"]
            .into_iter()
            .map(Network::parse)
            .collect();
    }
    listed.iter().map(|text| Network::parse(text)).collect()
}

/// Writes a line to standard output, the container log.
fn say(line: &str) -> Result<(), String> {
    writeln!(std::io::stdout(), "{line}")
        .map_err(|error| format!("standard output could not be written: {error}"))
}
