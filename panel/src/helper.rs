//! `ocpanel helper`, the root side of the panel. It owns the admin store,
//! the audit log and every session; it creates helper.sock for the web
//! process and answers only connections from the panel's own account; and it
//! starts the web process as that account, again whenever it exits.

use std::fs::{self, Permissions};
use std::io::{ErrorKind, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::stat::{Mode, umask};
use nix::unistd::{Gid, Uid, User, chown, geteuid};
use zeroize::Zeroizing;

use crate::alerts::Alerts;
use crate::audit::Audit;
use crate::blocklist::Blocklist;
use crate::config::Settings;
use crate::events::{self, EventLog, Spool};
use crate::history::History;
use crate::launch::{Launch, PortalLaunch};
use crate::occtl::Occtl;
use crate::password::Hasher;
use crate::protocol::{self, Request, Response, VpnSignIn};
use crate::server_settings;
use crate::service::{self, Bootstrap, Service, Vpn, VpnCheck};
use crate::sessions::Sessions;
use crate::store::Store;
use crate::vpnusers::Ocpasswd;
use crate::{
    alert_send, alerts, clientcerts, clock, countries, exposure, files, firewall, geoip, location,
    passkey, sites,
};

/// The socket the web process talks to, in the runtime directory.
pub const SOCKET_NAME: &str = "helper.sock";

/// The socket ocserv's session script asks for VPN sign-in location checks
/// on, in the runtime directory: root's alone, and it answers nothing else.
pub const LOCATION_SOCKET_NAME: &str = "location.sock";

/// The first wait before the web process is started again after it exits.
const FIRST_RESTART_DELAY: Duration = Duration::from_secs(1);

/// The longest wait before the web process is started again.
const MAX_RESTART_DELAY: Duration = Duration::from_secs(60);

/// A web process that ran this long resets the restart delay.
const STABLE_RUN: Duration = Duration::from_secs(60);

/// How often the event spool is read: the most an event waits before the
/// Live events page can show it.
const EVENT_POLL: Duration = Duration::from_secs(2);

pub fn run() -> ExitCode {
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel helper: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The location checks' state at start: the environment, the owner's
/// setting, what was learned, and the databases, read only while the checks
/// are on. A database that cannot be read is reported, and the checks wait
/// for the next download.
fn location_setup(
    settings: &Settings,
    config_dir: &Path,
    wake: mpsc::Sender<()>,
) -> Result<service::Locations, String> {
    let environment = location::Environment::from_env(&|name: &str| std::env::var_os(name))?;
    let stored = settings.data_dir.join(location::STORED_FILE);
    let on = location::Stored::open(&stored)?.in_force(&environment).on;
    let key_set = geoip::environment_key(&|name: &str| std::env::var_os(name))?.is_some()
        || geoip::saved_key(&geoip::key_file(config_dir))?.is_some();
    let atlas = match on {
        false => None,
        true => match location::load_atlas(config_dir, key_set) {
            Ok(atlas) => atlas,
            Err(error) => {
                eprintln!("ocpanel helper: location checks: {error}");
                None
            }
        },
    };
    Ok(service::Locations {
        environment,
        stored,
        atlas,
        learning: location::Learning::open(&settings.data_dir.join("locations.json"))?,
        wake: Some(wake),
        last: None,
        users_page: format!(
            "https://{}:{}/users",
            settings.host.authority(),
            settings.port
        ),
    })
}

/// Keeps the location databases current while the location checks are on:
/// checks FIRST_CHECK after the helper starts, then on the refresh schedule,
/// and at once when the service wakes it, as when an owner turns the checks
/// on. Downloads run outside the service's lock; a pass that installed a
/// database has the service read the databases again. What each pass did
/// goes to the container log.
fn keep_locations_current(service: &Mutex<Service>, woken: &Receiver<()>, config_dir: &Path) {
    let mut wait = geoip::FIRST_CHECK;
    loop {
        match woken.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        wait = geoip::CHECK_EVERY;
        let plan = match service.lock() {
            Ok(service) => service.location_plan(),
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        };
        let (key, refresh) = match plan {
            Ok(Some(plan)) => plan,
            Ok(None) => continue,
            Err(error) => {
                eprintln!("ocpanel helper: location databases: {error}");
                continue;
            }
        };
        wait = Duration::from_secs(refresh);
        let now = match clock::now() {
            Ok(now) => now,
            Err(error) => {
                eprintln!("ocpanel helper: location databases: {error}");
                continue;
            }
        };
        let done = geoip::update_locators(config_dir, key.as_ref(), now);
        let installed = match &done {
            Ok(installed) => {
                for copy in installed {
                    eprintln!("ocpanel helper: location databases: downloaded {copy}");
                }
                !installed.is_empty()
            }
            Err(error) => {
                eprintln!("ocpanel helper: the location database download failed: {error}");
                false
            }
        };
        let reloaded = match service.lock() {
            Ok(mut service) => {
                let reloaded = if installed || service.needs_atlas() {
                    service.reload_atlas(config_dir)
                } else {
                    Ok(())
                };
                let outcome = match (&reloaded, done) {
                    (Ok(()), done) => done,
                    (Err(problem), Ok(_installed)) => {
                        Err(format!("the databases could not be read: {problem}"))
                    }
                    (Err(problem), Err(download)) => Err(format!(
                        "{download}; and the databases could not be read: {problem}"
                    )),
                };
                service.note_location_check(now, outcome);
                reloaded
            }
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        };
        if let Err(error) = reloaded {
            eprintln!("ocpanel helper: location databases: {error}");
        }
    }
}

fn serve() -> Result<(), String> {
    if !geteuid().is_root() {
        return Err("the helper must run as root".to_owned());
    }
    let settings = Settings::from_env(|name: &str| std::env::var_os(name))
        .map_err(|error| error.to_string())?;
    let config_dir = crate::config::config_dir(&|name: &str| std::env::var_os(name))
        .map_err(|error| error.to_string())?;
    umask(Mode::from_bits_truncate(0o077));
    let account = User::from_name(&settings.service_user)
        .map_err(|error| {
            format!(
                "the user '{}' could not be looked up: {error}",
                settings.service_user
            )
        })?
        .ok_or_else(|| format!("the user '{}' does not exist", settings.service_user))?;

    files::create_private_dir(&settings.data_dir)?;
    let mut store = Store::open(&settings.data_dir.join("admins.json"))?;
    let mut audit = Audit::open(&settings.data_dir.join("audit.log"))?;
    let hasher = Hasher::new(settings.argon2_memory_kib, settings.argon2_passes)?;
    let policy = settings.policy();
    let created = service::bootstrap(
        &mut store,
        &mut audit,
        &hasher,
        &policy,
        &settings.admin_user,
        settings.admin_password_file.as_deref(),
        clock::now()?,
    )?;
    match created {
        Bootstrap::Existing => {}
        Bootstrap::FromFile { name } => say(&format!(
            "panel: first admin '{name}' created as owner with the password from PANEL_ADMIN_PASSWORD_FILE"
        ))?,
        Bootstrap::OneTime { name, password } => say(&format!(
            "panel: first admin '{name}' created as owner; one-time password: {password} \
             (shown only now; it must be replaced at the first sign-in)"
        ))?,
    }

    let spool = Spool::new(events::spool_dir(|name: &str| std::env::var_os(name))?);
    let (wake, woken) = mpsc::channel();
    let (alert_wake, alert_woken) = mpsc::channel();
    let alerts = Alerts::open(
        &settings.data_dir.join("alerts.json"),
        &settings.data_dir.join("country-drops.json"),
        alerts::environment_mail(&|name: &str| std::env::var_os(name))?,
        settings.host.authority(),
        Some(alert_wake),
        clock::now()?,
    )?;
    let (location_wake, location_woken) = mpsc::channel();
    let locations = location_setup(&settings, &config_dir, location_wake)?;
    let listener = bind_socket(&settings.runtime_dir, account.uid, account.gid)?;
    let location_listener = bind_location_socket(&settings.runtime_dir)?;
    let service = Arc::new(Mutex::new(Service::new(
        policy,
        store,
        audit,
        hasher,
        Sessions::new(
            settings.session_idle_minutes * 60,
            settings.session_max_hours * 3600,
        ),
        settings.second_factor_minutes * 60,
        Vpn {
            control: Box::new(Occtl),
            users: Box::new(Ocpasswd {
                passwd_file: settings.passwd_file.clone(),
                otp_file: settings.otp_file.clone(),
            }),
            history: History::new(settings.history_hours, settings.sample_seconds)?,
            ocserv_config: settings.ocserv_config.clone(),
            events: EventLog::new(settings.history_hours),
            address: settings.vpn_address.clone(),
            blocklist: Blocklist::open(
                &settings.data_dir.join("blocklist.json"),
                settings.blocking,
            )?,
            firewall: Box::new(firewall::System {
                backend: settings.firewall.ok_or(
                    "PANEL_FIREWALL is not set; the entrypoint sets it to the firewall it loaded",
                )?,
                site_lock: settings.site_lock.clone(),
                config_dir: config_dir.clone(),
            }),
            docker_hosts: docker_hosts()?,
            settings: server_settings::Files {
                state: settings.ocserv_config.with_file_name("panel-settings"),
                stored: settings.data_dir.join("settings.env"),
            },
            renderer: Box::new(server_settings::System),
            certificate_files: certificate_files(&settings)?,
            client_certificates: clientcerts::Records::open(
                &settings.data_dir.join("client-certificates.json"),
            )?,
            authority: Box::new(clientcerts::System {
                dir: settings.certs_dir.clone(),
                key_type: settings.key_type,
            }),
            client_cert_days: settings.client_cert_days,
            local_networks: exposure::local_networks(&read_text(Path::new("/proc/net/route"))?)?,
            sites: sites::Sites::open(&settings.data_dir.join("site-rules.json"))?,
            source_check: settings.source_check,
            countries: countries::Setup {
                environment: countries::Environment::from_env(&|name: &str| {
                    std::env::var_os(name)
                })?,
                stored: countries::stored_path(&config_dir),
                database: countries::Named::open(&countries::database_path(&config_dir)),
                maxmind: geoip::Maxmind {
                    environment: geoip::environment_key(&|name: &str| std::env::var_os(name))?,
                    key_file: geoip::key_file(&config_dir),
                    database_file: geoip::database_file(&config_dir),
                    candidate: None,
                    reread: false,
                    busy: false,
                    last: None,
                    wake: Some(wake),
                },
            },
            alerts,
            passkeys: passkey::relying_party(
                &settings.host,
                settings.port,
                Duration::from_secs(settings.second_factor_minutes * 60),
            )
            .and_then(|party| party.self_test().map(|()| party)),
            locations,
        },
    )));
    let sampled = Arc::clone(&service);
    let interval = Duration::from_secs(settings.sample_seconds);
    thread::Builder::new()
        .name("sampler".to_owned())
        .spawn(move || sample_every(&sampled, interval))
        .map_err(|error| format!("the sampling thread could not start: {error}"))?;
    let collected = Arc::clone(&service);
    thread::Builder::new()
        .name("events".to_owned())
        .spawn(move || collect_events(&collected, &spool))
        .map_err(|error| format!("the event thread could not start: {error}"))?;
    let downloads = Arc::clone(&service);
    let geoip_dir = config_dir.clone();
    thread::Builder::new()
        .name("geoip".to_owned())
        .spawn(move || keep_geoip_current(&downloads, &woken, &geoip_dir))
        .map_err(|error| format!("the GeoLite2 download thread could not start: {error}"))?;
    let located = Arc::clone(&service);
    let locations_dir = config_dir.clone();
    thread::Builder::new()
        .name("locations".to_owned())
        .spawn(move || keep_locations_current(&located, &location_woken, &locations_dir))
        .map_err(|error| {
            format!("the location database download thread could not start: {error}")
        })?;
    let sender = Arc::clone(&service);
    let hello = settings.host.clone();
    thread::Builder::new()
        .name("alerts".to_owned())
        .spawn(move || {
            alert_send::keep_sending(
                &sender,
                &alert_woken,
                &countries::reset_drop_counter,
                &|delivery| alert_send::send(delivery, &hello),
            );
        })
        .map_err(|error| format!("the alert thread could not start: {error}"))?;
    let checked = Arc::clone(&service);
    thread::Builder::new()
        .name("location-accept".to_owned())
        .spawn(move || accept_location_checks(&location_listener, &checked))
        .map_err(|error| format!("the location check thread could not start: {error}"))?;
    let web_uid = account.uid;
    let acceptor = thread::Builder::new()
        .name("accept".to_owned())
        .spawn(move || accept(&listener, &service, web_uid))
        .map_err(|error| format!("the connection thread could not start: {error}"))?;
    say(&format!(
        "panel: helper listening on {}",
        settings.runtime_dir.join(SOCKET_NAME).display()
    ))?;
    supervise_web(
        &settings,
        &settings.runtime_dir.join(SOCKET_NAME),
        account.uid,
        account.gid,
        &acceptor,
    )
}

/// Creates the runtime directory, root:<account> 0750, and the socket in
/// it, <account> 0600. Until the socket's owner and mode are set it is
/// root's under the 077 umask, so nobody else can connect in between.
fn bind_socket(runtime_dir: &Path, uid: Uid, gid: Gid) -> Result<UnixListener, String> {
    fs::create_dir_all(runtime_dir)
        .map_err(|error| format!("{}: {error}", runtime_dir.display()))?;
    chown(runtime_dir, Some(Uid::from_raw(0)), Some(gid))
        .map_err(|error| format!("{}: {error}", runtime_dir.display()))?;
    fs::set_permissions(runtime_dir, Permissions::from_mode(0o750))
        .map_err(|error| format!("{}: {error}", runtime_dir.display()))?;
    let path = runtime_dir.join(SOCKET_NAME);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    let listener =
        UnixListener::bind(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    chown(&path, Some(uid), Some(gid)).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(listener)
}

fn accept(listener: &UnixListener, service: &Arc<Mutex<Service>>, web_uid: Uid) {
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let service = Arc::clone(service);
                let started = thread::Builder::new()
                    .name("connection".to_owned())
                    .spawn(move || serve_connection(stream, &service, web_uid));
                if let Err(error) = started {
                    eprintln!("ocpanel helper: a connection thread could not start: {error}");
                }
            }
            Err(error) => eprintln!("ocpanel helper: a connection could not be accepted: {error}"),
        }
    }
}

/// Creates the location socket in the runtime directory, root's and mode
/// 0600, so the web process's account cannot connect to it.
fn bind_location_socket(runtime_dir: &Path) -> Result<UnixListener, String> {
    let path = runtime_dir.join(LOCATION_SOCKET_NAME);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    let listener =
        UnixListener::bind(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(listener)
}

/// Answers the VPN sign-in location checks ocserv's session script asks
/// for, one a connection.
fn accept_location_checks(listener: &UnixListener, service: &Arc<Mutex<Service>>) {
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let service = Arc::clone(service);
                let started = thread::Builder::new()
                    .name("location-check".to_owned())
                    .spawn(move || check_location(stream, &service));
                if let Err(error) = started {
                    eprintln!("ocpanel helper: a location check thread could not start: {error}");
                }
            }
            Err(error) => eprintln!(
                "ocpanel helper: a location check connection could not be accepted: {error}"
            ),
        }
    }
}

/// Answers one location check. A peer that is not root, or whose request
/// cannot be read, is disconnected without an answer, and the session
/// script lets its client in unchecked.
fn check_location(mut stream: UnixStream, service: &Mutex<Service>) {
    match getsockopt(&stream, PeerCredentials) {
        Ok(credentials) if credentials.uid() == 0 => {}
        Ok(credentials) => {
            eprintln!(
                "ocpanel helper: refused a location check from uid {} pid {}",
                credentials.uid(),
                credentials.pid()
            );
            return;
        }
        Err(error) => {
            eprintln!("ocpanel helper: a location check's credentials could not be read: {error}");
            return;
        }
    }
    let wait = Duration::from_secs(location::VPN_CHECK_WAIT_SECONDS);
    let read = stream
        .set_read_timeout(Some(wait))
        .and_then(|()| stream.set_write_timeout(Some(wait)))
        .map_err(|error| format!("its connection could not be set up: {error}"))
        .and_then(|()| protocol::read_message(&mut stream))
        .and_then(|message| match message {
            Some(message) => protocol::decode::<VpnSignIn>(&message),
            None => Err("the connection closed before the request".to_owned()),
        });
    let sign_in = match read {
        Ok(sign_in) => sign_in,
        Err(error) => {
            eprintln!("ocpanel helper: a location check could not be read: {error}");
            return;
        }
    };
    let mut service = match service.lock() {
        Ok(service) => service,
        Err(poisoned) => {
            eprintln!(
                "ocpanel helper: the location check of {}'s VPN sign-in could not run: the \
                 helper's state is unusable after a failure: {poisoned}",
                sign_in.user
            );
            return;
        }
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => {
            eprintln!(
                "ocpanel helper: the location check of {}'s VPN sign-in could not run: {error}",
                sign_in.user
            );
            return;
        }
    };
    let checked = service.check_vpn_sign_in(&sign_in, now, &mut |verdict| {
        protocol::encode(verdict).and_then(|bytes| protocol::write_message(&mut stream, &bytes))
    });
    drop(service);
    match checked {
        VpnCheck::Answered {
            unsaved: Some(problem),
        } => eprintln!(
            "ocpanel helper: what {}'s VPN sign-in showed could not be saved: {problem}",
            sign_in.user
        ),
        VpnCheck::Answered { unsaved: None } => {}
        VpnCheck::Undelivered { problem } => eprintln!(
            "ocpanel helper: the answer to the location check of {}'s VPN sign-in did not reach \
             the session script, which lets the client in unchecked: {problem}",
            sign_in.user
        ),
    }
}

/// Answers requests on one connection until the peer closes it. A peer that
/// is not the panel's account is disconnected without an answer.
fn serve_connection(mut stream: UnixStream, service: &Mutex<Service>, web_uid: Uid) {
    match getsockopt(&stream, PeerCredentials) {
        Ok(credentials) if credentials.uid() == web_uid.as_raw() => {}
        Ok(credentials) => {
            eprintln!(
                "ocpanel helper: refused a connection from uid {} pid {}",
                credentials.uid(),
                credentials.pid()
            );
            return;
        }
        Err(error) => {
            eprintln!("ocpanel helper: a connection's credentials could not be read: {error}");
            return;
        }
    }
    loop {
        let message = match protocol::read_message(&mut stream) {
            Ok(Some(message)) => Zeroizing::new(message),
            Ok(None) => return,
            Err(error) => {
                eprintln!("ocpanel helper: {error}");
                return;
            }
        };
        let response = match protocol::decode::<Request>(&message) {
            Ok(request) => handle(service, request),
            Err(message) => Response::Invalid { message },
        };
        drop(message);
        let sent = protocol::encode(&response)
            .and_then(|bytes| protocol::write_message(&mut stream, &bytes));
        if let Err(error) = sent {
            eprintln!("ocpanel helper: {error}");
            return;
        }
    }
}

/// The Docker host's address, from the default route, as the panel admits
/// it: the firewall blocklist never holds it.
/// The certificates the Certificates page shows besides the VPN server's:
/// the image's CA in CONFIG_DIR/certs, the panel's own, and the user
/// portal's when it has one of its own.
fn certificate_files(settings: &Settings) -> Result<Vec<(String, PathBuf)>, String> {
    let config_dir = settings
        .data_dir
        .parent()
        .ok_or_else(|| format!("{} has no parent", settings.data_dir.display()))?;
    let mut files = vec![(
        "Certificate authority".to_owned(),
        config_dir.join("certs").join("ca.pem"),
    )];
    files.push((
        "Admin panel".to_owned(),
        match &settings.own_certificate {
            Some((cert, _key)) => cert.clone(),
            None => settings.data_dir.join("tls").join("cert.pem"),
        },
    ));
    if let Some(portal) = &settings.portal
        && let Some((cert, _key)) = &portal.own_certificate
    {
        files.push(("User portal".to_owned(), cert.clone()));
    }
    Ok(files)
}

fn docker_hosts() -> Result<Vec<IpAddr>, String> {
    let table = fs::read_to_string("/proc/net/route")
        .map_err(|error| format!("/proc/net/route: {error}"))?;
    Ok(exposure::default_gateway(&table)?
        .map(IpAddr::V4)
        .into_iter()
        .collect())
}

/// Samples the VPN server into the dashboard's history every `interval`; a
/// failed sample is reported in the container log and sampling goes on.
fn sample_every(service: &Mutex<Service>, interval: Duration) {
    loop {
        thread::sleep(interval);
        let sampled = clock::now().and_then(|now| match service.lock() {
            Ok(mut service) => {
                if let Err(error) = service.expire_blocks(now) {
                    eprintln!("ocpanel helper: a block whose time ran out stays: {error}");
                }
                service.sample(now)
            }
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        });
        if let Err(error) = sampled {
            eprintln!("ocpanel helper: the VPN server could not be sampled: {error}");
        }
    }
}

/// Moves the events in the spool into the live events every `EVENT_POLL`.
/// A file or a step that fails is reported in the container log, and
/// collecting goes on.
fn collect_events(service: &Mutex<Service>, spool: &Spool) {
    loop {
        thread::sleep(EVENT_POLL);
        let drained = spool.drain();
        for problem in &drained.problems {
            eprintln!("ocpanel helper: an event file: {problem}");
        }
        let recorded = clock::now().and_then(|now| match service.lock() {
            Ok(mut service) => service.record_events(now, drained.events),
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        });
        if let Err(error) = recorded {
            eprintln!("ocpanel helper: the live events could not be updated: {error}");
        }
    }
}

/// Keeps MaxMind GeoLite2 current while a key is set, as docker-sftp does:
/// checks FIRST_CHECK after the helper starts and every CHECK_EVERY after
/// that, and at once when the service wakes it for a key an admin saved or
/// removed. Downloads run outside the service's lock; what each did goes to
/// the service, which shows it on the Bans page, and to the container log.
fn keep_geoip_current(service: &Mutex<Service>, woken: &Receiver<()>, config_dir: &Path) {
    let mut wait = geoip::FIRST_CHECK;
    loop {
        match woken.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        wait = geoip::CHECK_EVERY;
        let job = match service.lock() {
            Ok(mut service) => service.take_geoip_job(),
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        };
        let reread = || countries::Named::open(&countries::database_path(config_dir));
        let (outcome, database) = match job {
            Ok(geoip::Job::Idle) => continue,
            Ok(geoip::Job::Download { key, save }) => {
                let fetched = geoip::download(&key)
                    .and_then(|bytes| geoip::install(&geoip::database_file(config_dir), &bytes))
                    .and_then(|()| match save {
                        true => geoip::save_key(&geoip::key_file(config_dir), &key),
                        false => Ok(()),
                    })
                    .map(|()| "downloaded MaxMind GeoLite2 Country".to_owned());
                let database = fetched.is_ok().then(reread);
                (fetched, database)
            }
            Ok(geoip::Job::Reread) => (
                Ok("read the country database again".to_owned()),
                Some(reread()),
            ),
            Err(error) => {
                eprintln!("ocpanel helper: GeoLite2: {error}");
                continue;
            }
        };
        if let Err(why) = &outcome {
            eprintln!("ocpanel helper: the GeoLite2 download failed: {why}");
        }
        let finished = clock::now().and_then(|now| match service.lock() {
            Ok(mut service) => service.finish_geoip(now, outcome, database),
            Err(poisoned) => Err(format!(
                "the helper's state is unusable after a failure: {poisoned}"
            )),
        });
        if let Err(error) = finished {
            eprintln!("ocpanel helper: GeoLite2: {error}");
        }
    }
}

fn handle(service: &Mutex<Service>, request: Request) -> Response {
    let now = match clock::now() {
        Ok(now) => now,
        Err(message) => return Response::Error { message },
    };
    match service.lock() {
        Ok(mut service) => service.handle(request, now),
        Err(poisoned) => Response::Error {
            message: format!("the helper's state is unusable after a failure: {poisoned}"),
        },
    }
}

/// The file the image build writes the ocserv version into.
const OCSERV_VERSION_FILE: &str = "/usr/local/share/ocserv-docker/ocserv-version";

/// The kernel's host name, which inside a container is the container's.
const HOST_NAME_FILE: &str = "/proc/sys/kernel/hostname";

/// Runs the web process as the panel's account with an empty environment,
/// and starts it again whenever it exits, waiting longer after each quick
/// exit. Returns only when the socket stops accepting connections.
fn supervise_web(
    settings: &Settings,
    socket: &Path,
    uid: Uid,
    gid: Gid,
    acceptor: &JoinHandle<()>,
) -> Result<(), String> {
    let program: PathBuf = std::env::current_exe()
        .map_err(|error| format!("the helper's own program could not be found: {error}"))?;
    let mut delay = FIRST_RESTART_DELAY;
    loop {
        if acceptor.is_finished() {
            return Err("the socket stopped accepting connections".to_owned());
        }
        let started = Instant::now();
        let status = launch_message(settings)
            .and_then(|launch| run_web(&program, socket, uid, gid, &launch));
        if started.elapsed() >= STABLE_RUN {
            delay = FIRST_RESTART_DELAY;
        }
        match status {
            Ok(status) => say(&format!(
                "panel: the web process exited ({status}); starting it again in {} s",
                delay.as_secs()
            ))?,
            Err(error) => eprintln!(
                "ocpanel helper: the web process could not start ({error}); trying again in {} s",
                delay.as_secs()
            ),
        }
        thread::sleep(delay);
        delay = (delay * 2).min(MAX_RESTART_DELAY);
    }
}

/// Starts the web process, writes the launch message to its standard input,
/// closes it, and waits for the process to end.
fn run_web(
    program: &Path,
    socket: &Path,
    uid: Uid,
    gid: Gid,
    launch: &Launch,
) -> Result<std::process::ExitStatus, String> {
    let message = launch.encode()?;
    let mut child = Command::new(program)
        .arg("web")
        .arg(socket)
        .env_clear()
        .current_dir("/")
        .gid(gid.as_raw())
        .uid(uid.as_raw())
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(&message)
            .map_err(|error| format!("the launch message could not be written: {error}")),
        None => Err("the web process has no standard input".to_owned()),
    };
    if let Err(error) = written {
        eprintln!("ocpanel helper: {error}");
    }
    child
        .wait()
        .map_err(|error| format!("the web process could not be waited for: {error}"))
}

/// The launch message for the web process, read afresh at every start so a
/// renewed certificate is served from the next start on.
fn launch_message(settings: &Settings) -> Result<Launch, String> {
    let config_dir = settings
        .data_dir
        .parent()
        .ok_or("the panel's data directory has no parent")?;
    let ca_path = config_dir.join("certs").join("ca.pem");
    let (chain_pem, key_path) = match &settings.own_certificate {
        Some((cert, key)) => (read_text(cert)?, key.clone()),
        None => {
            let tls = settings.data_dir.join("tls");
            let leaf = read_text(&tls.join("cert.pem"))?;
            (
                format!("{leaf}\n{}", read_text(&ca_path)?),
                tls.join("key.pem"),
            )
        }
    };
    let client_ca_pem = if settings.require_client_cert {
        Some(read_text(&ca_path)?)
    } else {
        None
    };
    let allowed = exposure::on_this_host(settings)?
        .iter()
        .map(ToString::to_string)
        .collect();
    let portal = match &settings.portal {
        None => None,
        Some(portal) => {
            let (portal_chain, portal_key) = match &portal.own_certificate {
                Some((cert, key)) => (read_text(cert)?, read_text(key)?),
                None => (chain_pem.clone(), read_text(&key_path)?),
            };
            Some(PortalLaunch {
                port: portal.port,
                host: settings.vpn_address.host.authority(),
                allowed: portal.networks.iter().map(ToString::to_string).collect(),
                chain_pem: portal_chain,
                key_pem: portal_key,
            })
        }
    };
    Ok(Launch {
        port: settings.port,
        host: settings.host.authority(),
        allowed,
        chain_pem,
        key_pem: read_text(&key_path)?,
        client_ca_pem,
        ocserv_version: read_text(Path::new(OCSERV_VERSION_FILE))?.trim().to_owned(),
        instance: read_text(Path::new(HOST_NAME_FILE))?.trim().to_owned(),
        min_password_length: settings.min_password_length,
        portal,
    })
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Writes a line to standard output, the container log.
fn say(line: &str) -> Result<(), String> {
    writeln!(std::io::stdout(), "{line}")
        .map_err(|error| format!("standard output could not be written: {error}"))
}
