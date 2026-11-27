//! `ocpanel dev-server <port>`, in debug builds only: the real pages over
//! plain HTTP on localhost, answered by the real service in memory, with its
//! data in a new temporary directory and the first admin's one-time password
//! printed at start. Release builds have no such command.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::alerts::{self, Alerts, Counter, Delivery, Target, Topic, Tried};
use crate::app::{self, App};
use crate::assets::Assets;
use crate::audit::Audit;
use crate::blocklist::{AutoBlock, Blocklist};
use crate::client::{Helper, Reply};
use crate::config::{Host, VpnAddress};
use crate::events::{Event, EventLog, What};
use crate::history::{History, Sample};
use crate::net::Network;
use crate::occtl::Fake;
use crate::password::Hasher;
use crate::server::{self, Peer};
use crate::service::{self, Bootstrap, Policy, Service, Vpn};
use crate::sessions::Sessions;
use crate::sites::{End, Sites};
use crate::store::Store;
use crate::vpnusers::{FakeUsers, VpnUser};
use crate::{
    alert_send, clientcerts, clock, config, countries, files, firewall, geoip, kit, location,
    passkey, server_settings,
};

/// The entrypoint's record of the server settings at start, at the image's
/// defaults but for one setting the environment gives and one an extra
/// configuration file overrides.
const SAMPLE_SETTINGS_STATE: &str = "DNS_SERVERS\treload\tdefault\t9.9.9.9,1.1.1.1
SPLIT_DNS_DOMAINS\treload\tdefault\t
DEFAULT_DOMAIN\treload\tdefault\t
TUNNEL_ALL_DNS\treload\tdefault\ttrue
BANNER\treload\tdefault\t
PRE_LOGIN_BANNER\treload\tdefault\t
MAX_CLIENTS\treload\tenvironment\t64
MAX_SAME_CLIENTS\treload\tdefault\t4
IDLE_TIMEOUT\treload\t/config/ocserv-extra.conf\t
MOBILE_IDLE_TIMEOUT\treload\tdefault\t
SESSION_TIMEOUT\treload\tdefault\t
AUTH_TIMEOUT\treload\tdefault\t240
COOKIE_TIMEOUT\treload\tdefault\t300
KEEPALIVE\treload\tdefault\t32400
DPD\treload\tdefault\t90
MOBILE_DPD\treload\tdefault\t1800
SWITCH_TO_TCP_TIMEOUT\treload\tdefault\t25
MTU\treload\tdefault\t
RX_DATA_PER_SEC\treload\tdefault\t
TX_DATA_PER_SEC\treload\tdefault\t
MAX_BAN_SCORE\treload\tdefault\t80
BAN_TIME\treload\tdefault\t300
BAN_RESET_TIME\treload\tdefault\t1200
BAN_POINTS_WRONG_PASSWORD\treload\tdefault\t10
RATE_LIMIT_MS\treload\tdefault\t100
PROXY_PROTOCOL\treload\tdefault\tfalse
SERVER_DRAIN_MS\treload\tdefault\t
AUTH_MODE\tstart\tdefault\tpassword
DTLS\tstart\tdefault\ttrue
TUNNEL_MODE\tstart\tdefault\tall
TUNNEL_ROUTES\tstart\tdefault\t
NO_ROUTES\tstart\tdefault\t
RESTRICT_TO_ROUTES\tstart\tdefault\tauto
NAT\tstart\tdefault\ttrue
CLIENT_TO_CLIENT\tstart\tdefault\tfalse
CISCO_COMPAT\tstart\tdefault\ttrue
LOG_LEVEL\tstart\tdefault\t2
";

/// A configuration like the one the entrypoint builds from the defaults;
/// the server adds the settings directories in its own temporary directory.
const SAMPLE_OCSERV_CONFIG: &str =
    "auth = \"plain[passwd=/config/ocpasswd,otp=/config/users.oath]\"
cisco-client-compat = true
tcp-port = 4443
udp-port = 4443
ipv4-network = 192.168.255.0/24
dns = 9.9.9.9
dns = 1.1.1.1
route = default
max-ban-score = 80
ban-time = 300
ban-reset-time = 1200
ban-points-wrong-password = 10
";

/// A day of made-up samples every 10 seconds up to `now`, busier in the
/// working hours, so the dashboard's charts have something to draw.
fn sample_history(now: u64) -> Result<History, String> {
    let mut history = History::new(24, 10)?;
    let start = now - 24 * 3600;
    let samples = (0..8640u64)
        .map(|step| {
            let time = start + step * 10;
            let hour = (time / 3600) % 24;
            let busy = if (8..18).contains(&hour) { 3 } else { 1 };
            let wobble = (step / 30 * 7919) % 13;
            Sample {
                time,
                sessions: busy * 2 + wobble % 3,
                to_clients: Some(busy * 900_000 + wobble * 85_000),
                from_clients: Some(busy * 120_000 + wobble * 9_000),
            }
        })
        .collect();
    history.backfill(samples);
    Ok(history)
}

/// Where alex's session comes from: a cloud desktop, which the Sessions page
/// and the live events place in a country.
const ALEX_FROM: &str = "16.170.10.4";

/// A small server's recent events: scanners' refused sign-ins from five
/// countries over the hours before; then two connects, a disconnect, three
/// refused sign-ins for different reasons, the ban that the guessing at one
/// address earned, and a sign-in the location checks flagged, one they
/// refused and one they could not check.
fn sample_events(now: u64) -> Vec<Event> {
    let at = |ago: u64, what| Event {
        time: now - ago,
        what,
    };
    let failed = |user: &str, from: &str| What::SignInFailed {
        user: user.to_owned(),
        from: Some(from.to_owned()),
    };
    // Scanners on cloud servers in five countries, as the Bans page's
    // Countries card charts them, every ten minutes from an hour ago back.
    let scans = [
        ("47.92.18.36", 14),
        ("51.250.7.91", 6),
        ("18.228.40.12", 3),
        ("13.232.95.4", 2),
        ("116.202.33.8", 1),
    ];
    let mut events: Vec<Event> = scans
        .iter()
        .flat_map(|&(from, count)| (0..count).map(move |attempt| (from, attempt)))
        .map(|(from, attempt)| at(3600 + attempt * 600, failed("admin", from)))
        .collect();
    events.sort_by_key(|event| event.time);
    events.extend([
        at(
            1740,
            What::Connected {
                user: "alex".to_owned(),
                group: None,
                session: Some(245),
                from: Some(ALEX_FROM.to_owned()),
                vpn_ipv4: Some("192.168.255.2".to_owned()),
                vpn_ipv6: None,
                client: Some("Open AnyConnect VPN Agent v9.12".to_owned()),
            },
        ),
        at(1310, failed("riley", "198.51.100.23")),
        at(1250, failed("admin", "203.0.113.250")),
        at(1248, failed("root", "203.0.113.250")),
        at(
            1247,
            What::Banned {
                address: "203.0.113.250".to_owned(),
                score: 92,
            },
        ),
        at(
            905,
            What::Disconnected {
                user: "sam".to_owned(),
                session: Some(231),
                from: Some("198.51.100.7".to_owned()),
                seconds: Some(7380),
                received: Some(3_120_554),
                sent: Some(18_220_901),
            },
        ),
        at(
            640,
            What::Connected {
                user: "sam".to_owned(),
                group: Some("staff".to_owned()),
                session: Some(246),
                from: Some("198.51.100.7".to_owned()),
                vpn_ipv4: Some("192.168.255.3".to_owned()),
                vpn_ipv6: Some("fd3e:7a0c:5b19::3".to_owned()),
                client: Some("AnyConnect Windows 4.10.07073".to_owned()),
            },
        ),
        at(95, failed("alex", "203.0.113.9")),
        at(
            480,
            What::LocationFlagged {
                user: "sam".to_owned(),
                from: "13.232.95.4".to_owned(),
                score: 50,
                reasons: vec![
                    "a network not used before (AS16509)".to_owned(),
                    "a country not used before (IN)".to_owned(),
                    "a device not used before (AnyConnect Windows 4.10.08029)".to_owned(),
                ],
            },
        ),
        at(
            300,
            What::LocationRefused {
                user: "alex".to_owned(),
                from: "116.202.33.8".to_owned(),
                score: 100,
                reasons: vec![
                    "a session is open 1050 km away".to_owned(),
                    "1050 km from every usual place".to_owned(),
                    "a network not used before (AS24940)".to_owned(),
                    "a country not used before (DE)".to_owned(),
                ],
            },
        ),
        at(
            200,
            What::LocationUnchecked {
                user: "kai".to_owned(),
                from: Some("192.0.2.44".to_owned()),
                problem: "the admin panel's helper gave no answer within 5 seconds: a message \
                          could not be read: Resource temporarily unavailable (os error 11)"
                    .to_owned(),
            },
        ),
    ]);
    events.sort_by_key(|event| event.time);
    events
}

/// The dev server's stand-in for sending, which reaches nothing: ntfy, the
/// webhook and email count as sent, email without a mail server fails as
/// the real sender fails, and Telegram is refused, so the Alerts page shows
/// each state.
fn dev_send(delivery: &Delivery) -> Result<(), String> {
    match &delivery.target {
        Target::Email { .. } if delivery.mail.is_none() => {
            alert_send::send(delivery, &Host::Name("localhost".to_owned()))
        }
        Target::Telegram { .. } => {
            Err("Telegram answered with status 401: Unauthorized".to_owned())
        }
        Target::Ntfy { .. } | Target::Webhook { .. } | Target::Email { .. } => Ok(()),
    }
}

/// The dev admin's alerts: a channel of each kind, and a few messages gone
/// through them by the stand-in, so each status the Alerts page shows has a
/// sample.
fn sample_alerts(dir: &Path, now: u64, wake: Sender<()>) -> Result<Alerts, String> {
    let mut alerts = Alerts::open(
        &dir.join("alerts.json"),
        &dir.join("country-drops.json"),
        None,
        "vpn.example.com".to_owned(),
        Some(wake),
        now,
    )?;
    alerts.set_topics("admin", BTreeSet::from([Topic::Blocks, Topic::SignIns]))?;
    let added = now - 2 * 86_400;
    let ntfy = alerts::ntfy("", "openconnect-alerts-7f3k9q2m", "")?;
    alerts.add("admin", ntfy, added)??;
    let bot = alerts::telegram("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "123456789")?;
    alerts.add("admin", bot, added + 60)??;
    let hook = alerts::webhook("http://192.168.1.20:8123/api/webhook/openconnect-k2v9q")?;
    alerts.add("admin", hook, added + 120)??;
    alerts.add("admin", alerts::email("admin@example.com")?, added + 180)??;
    let first = now - 1800;
    alerts.raise(
        first,
        Topic::Blocks,
        "Blocked 47.92.18.36/32 (China) at the firewall for 1 day: banned 3 times within 1 day",
        &|_admin| true,
    );
    alerts.raise(
        first + 20,
        Topic::SignIns,
        &format!(
            "admin signed in to the panel from {ALEX_FROM} (Sweden), outside the trusted \
             networks, with a password and an authenticator code"
        ),
        &|_admin| true,
    );
    for at in [first + 20, first + 80, first + 620] {
        for delivery in alerts.take_due(at) {
            let tried = match dev_send(&delivery) {
                Ok(()) => Tried::Sent,
                Err(error) => Tried::Failed(error),
            };
            alerts.finish(at + 2, delivery.channel, tried);
        }
    }
    Ok(alerts)
}

pub fn run(port: &str) -> ExitCode {
    match serve(port) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ocpanel dev-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve(port: &str) -> Result<(), String> {
    let port: u16 = port
        .parse()
        .map_err(|error| format!("'{port}' is not a port: {error}"))?;
    let dir = std::env::temp_dir().join(format!("ocpanel-dev-{}", std::process::id()));
    files::create_private_dir(&dir)?;
    let mut store = Store::open(&dir.join("admins.json"))?;
    let mut audit = Audit::open(&dir.join("audit.log"))?;
    let hasher = Hasher::new(config::MIN_ARGON2_MEMORY_KIB, config::MIN_ARGON2_PASSES)?;
    // `OCPANEL_DEV_LAN_NETWORKS` replaces the trusted loopback network, so a
    // browser on this machine signs in as from outside and reaches the
    // second-factor pages.
    let lan_networks = match std::env::var_os("OCPANEL_DEV_LAN_NETWORKS") {
        Some(value) => crate::net::parse_list(
            value
                .to_str()
                .ok_or("`OCPANEL_DEV_LAN_NETWORKS` is not UTF-8 text")?,
        )?,
        None => vec![Network::parse("127.0.0.0/8")?],
    };
    let policy = Policy {
        lan_networks,
        max_failures: 5,
        lockout: 900,
        min_password_length: 12,
        reauth: 600,
    };
    let created = service::bootstrap(
        &mut store,
        &mut audit,
        &hasher,
        &policy,
        "admin",
        None,
        clock::now()?,
    )?;
    match created {
        Bootstrap::OneTime { name, password } => {
            println!("dev-server: admin '{name}', one-time password {password}");
        }
        Bootstrap::FromFile { name } => println!("dev-server: admin '{name}' created from a file"),
        Bootstrap::Existing => println!("dev-server: an admin already exists in {}", dir.display()),
    }
    let ocserv_config = dir.join("ocserv.conf");
    let users_dir = dir.join("config-per-user");
    let groups_dir = dir.join("config-per-group");
    files::create_private_dir(&users_dir)?;
    files::create_private_dir(&groups_dir)?;
    files::write_private(
        &groups_dir.join("contractors"),
        b"route = 10.20.0.0/16\ndns = 10.20.0.53\ntx-data-per-sec = 6250000\n\
          rx-data-per-sec = 1250000\nrestrict-user-to-routes = true\n",
    )?;
    files::write_private(
        &users_dir.join("branch-office"),
        b"iroute = 10.10.0.0/24\niroute = 10.10.1.0/24\n",
    )?;
    files::write_private(&users_dir.join("alex"), b"iroute = 192.168.50.0/24\n")?;
    let server_cert = dir.join("server-cert.pem");
    files::write_private(&server_cert, kit::SAMPLE_CERT.as_bytes())?;
    let config = format!(
        "{SAMPLE_OCSERV_CONFIG}config-per-user = {}\nconfig-per-group = {}\nserver-cert = {}\n",
        users_dir.display(),
        groups_dir.display(),
        server_cert.display()
    );
    std::fs::write(&ocserv_config, config)
        .map_err(|error| format!("{} could not be written: {error}", ocserv_config.display()))?;
    let settings_state = dir.join("panel-settings");
    std::fs::write(&settings_state, SAMPLE_SETTINGS_STATE)
        .map_err(|error| format!("{} could not be written: {error}", settings_state.display()))?;
    let renderer = server_settings::Fake {
        start: server_settings::read_state(&settings_state)?
            .ok_or_else(|| format!("{} vanished", settings_state.display()))?,
        config: ocserv_config.clone(),
        stored: dir.join("settings.env"),
    };
    let now = clock::now()?;
    let mut users = FakeUsers::sample();
    users.users.push(VpnUser {
        name: "branch-office".to_owned(),
        groups: Vec::new(),
        locked: false,
        otp: false,
    });
    let mut sites = Sites::open(&dir.join("site-rules.json"))?;
    let branch = End::Network(Network::parse("10.10.0.0/24")?);
    let staff = End::Group("staff".to_owned());
    sites.add(staff.clone(), branch.clone(), "admin", now - 2 * 86_400)?;
    sites.add(branch, staff, "admin", now - 2 * 86_400 + 60)?;
    sites.set_egress("branch-office", true)?;
    let mut control = Fake::sample(now - 3 * 86_400 - 4 * 3600);
    for vpn in &mut control.sessions {
        if vpn.user == "alex" {
            vpn.remote_ip = Some(ALEX_FROM.to_owned());
        }
    }
    let (alert_wake, alert_woken) = mpsc::channel();
    let alerts = sample_alerts(&dir, now, alert_wake)?;
    let mut service = Service::new(
        policy,
        store,
        audit,
        hasher,
        Sessions::new(1800, 43_200),
        300,
        Vpn {
            control: Box::new(control),
            users: Box::new(users),
            history: sample_history(now)?,
            ocserv_config,
            events: EventLog::new(24),
            address: VpnAddress {
                host: Host::Name("vpn.example.com".to_owned()),
                port: 4443,
            },
            blocklist: Blocklist::open(
                &dir.join("blocklist.json"),
                AutoBlock {
                    bans: 3,
                    window: 86_400,
                    duration: 86_400,
                },
            )?,
            firewall: Box::new(firewall::Fake::default()),
            docker_hosts: Vec::new(),
            settings: server_settings::Files {
                state: settings_state,
                stored: dir.join("settings.env"),
            },
            renderer: Box::new(renderer),
            certificate_files: vec![
                ("Certificate authority".to_owned(), server_cert.clone()),
                ("Admin panel".to_owned(), server_cert.clone()),
            ],
            client_certificates: clientcerts::Records::open(&dir.join("client-certificates.json"))?,
            authority: Box::new(clientcerts::Fake::new(now)),
            client_cert_days: 365,
            local_networks: Vec::new(),
            sites,
            source_check: true,
            countries: countries::Setup {
                environment: countries::Environment {
                    ports: vec![4443, 8443],
                    ..countries::Environment::default()
                },
                stored: dir.join("country-rules.json"),
                database: match std::env::var_os("OCPANEL_DEV_COUNTRY_DB") {
                    Some(path) => countries::Named::open(std::path::Path::new(&path)),
                    None => Err("OCPANEL_DEV_COUNTRY_DB names no country database".to_owned()),
                },
                maxmind: geoip::Maxmind {
                    environment: None,
                    key_file: geoip::key_file(&dir),
                    database_file: geoip::database_file(&dir),
                    candidate: None,
                    reread: false,
                    busy: false,
                    last: None,
                    wake: None,
                },
            },
            alerts,
            passkeys: passkey::local_relying_party(port, Duration::from_secs(300)),
            locations: service::Locations {
                environment: location::Environment::from_env(&|name: &str| std::env::var_os(name))?,
                stored: dir.join("location-checks.json"),
                // `OCPANEL_DEV_LOCATION_DIR` names a folder laid out as
                // CONFIG_DIR, whose geoip folder holds the city and network
                // copies the location checks read.
                atlas: match std::env::var_os("OCPANEL_DEV_LOCATION_DIR") {
                    Some(path) => location::load_atlas(std::path::Path::new(&path), false)?,
                    None => None,
                },
                learning: location::Learning::open(&dir.join("locations.json"))?,
                wake: None,
                last: Some((
                    now - 7200,
                    Ok(vec![
                        "DB-IP dbip-city-lite-2026-11".to_owned(),
                        "DB-IP dbip-asn-lite-2026-11".to_owned(),
                    ]),
                )),
                users_page: format!("http://localhost:{port}/users"),
            },
        },
    );
    service.record_events(now, sample_events(now))?;
    let service = Arc::new(Mutex::new(service));
    let sender = Arc::clone(&service);
    std::thread::Builder::new()
        .name("alerts".to_owned())
        .spawn(move || {
            alert_send::keep_sending(&sender, &alert_woken, &|| Counter::Absent, &dev_send);
        })
        .map_err(|error| format!("the alert thread could not start: {error}"))?;
    let helper = Helper::new(move |request| -> Reply {
        let service = Arc::clone(&service);
        Box::pin(async move {
            let now = clock::now()?;
            let mut service = service
                .lock()
                .map_err(|error| format!("the service is unusable after a failure: {error}"))?;
            Ok(service.handle(request, now))
        })
    });
    let portal_port = port
        .checked_add(1)
        .ok_or("the user portal needs the port after the panel's, and there is none")?;
    let assets = Arc::new(Assets::new());
    let app = |site: &'static str| App {
        helper: helper.clone(),
        host: "localhost".to_owned(),
        other_hosts: Vec::new(),
        site,
        scheme: "http",
        assets: Arc::clone(&assets),
        ocserv_version: "1.6.0".to_owned(),
        instance: "vpn1".to_owned(),
        min_password_length: 12,
    };
    let panel = app::router(app("panel"));
    let portal = app::portal_router(app("portal"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the runtime could not start: {error}"))?;
    runtime.block_on(async move {
        let panel_listener = bind_local(port).await?;
        let portal_listener = bind_local(portal_port).await?;
        println!("dev-server: http://localhost:{port}/");
        println!("dev-server: user portal at http://localhost:{portal_port}/");
        let mut servers = JoinSet::new();
        servers.spawn(serve_plain(panel_listener, panel));
        servers.spawn(serve_plain(portal_listener, portal));
        match servers.join_next().await {
            Some(Ok(())) | None => Ok(()),
            Some(Err(error)) => Err(format!("a server stopped: {error}")),
        }
    })
}

async fn bind_local(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .map_err(|error| format!("port {port} could not be bound: {error}"))
}

/// Serves plain HTTP connections to `router` for as long as the process runs.
async fn serve_plain(listener: TcpListener, router: Router) {
    loop {
        let (stream, address) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("ocpanel dev-server: a connection could not be accepted: {error}");
                continue;
            }
        };
        let peer = Peer(server::canonical(address.ip()));
        let service = TowerToHyperService::new(router.clone().layer(Extension(peer)));
        tokio::spawn(async move {
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("ocpanel dev-server: a connection failed: {error}");
            }
        });
    }
}
