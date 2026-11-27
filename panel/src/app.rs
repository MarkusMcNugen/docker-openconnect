//! The panel's pages and the browser rules around them. Every request must
//! name the panel's own host; every form must come from the panel's own
//! pages; every response carries the security headers; and the session lives
//! in a __Host- cookie that only the helper can turn into an admin.

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, Request, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::alerts::{self, Last, Security, Topic};
use crate::assets::Assets;
use crate::audit::{Outcome, Record};
use crate::blocklist::AutoBlock;
use crate::client::Helper;
use crate::clientcerts::{Cipher, Method as KeyOrigin};
use crate::events::{Logged, What};
use crate::extras::{self, Kind as ExtraKind};
use crate::kit::{Authenticator, Kit};
use crate::location::{self, Kind as AccountKind};
use crate::net::Network;
use crate::occtl::{Ban, BanPoints, Session as VpnSession, Status};
use crate::overrides::{self, Form as OverridesForm, Overrides, Owner};
use crate::portal::PortalScope;
use crate::protocol::{
    AdminChange, AdminSummary, AlertsView, CertificateEntry, ChannelEntry, ChannelView,
    ClientCertificate, CountryView, IssueHow, Located, LocationView, MailEntry, Place,
    PortalRequest, PortalResponse, Request as Ask, Response as Answer, Site, SitesView, UserChange,
};
use crate::server::Peer;
use crate::server_settings::{Kind, SPECS, Setting, Source as ServerSource, Spec};
use crate::serverconf::BanPolicy;
use crate::sessions::Scope;
use crate::sites::End;
use crate::store::{self, Role};
use crate::{clock, icons, passkey, qr, units};

/// The cookie that holds a session token.
pub const SESSION_COOKIE: &str = "__Host-ocpanel";

/// The cookie that holds a sign-in waiting for its second factor.
pub const PENDING_COOKIE: &str = "__Host-ocpanel-pending";

/// The cookie that holds a VPN user portal session token.
pub const PORTAL_COOKIE: &str = "__Host-ocportal";

/// The cookie that holds a portal sign-in waiting for its code.
pub const PORTAL_PENDING_COOKIE: &str = "__Host-ocportal-pending";

/// The largest form body accepted, in bytes.
const MAX_FORM: usize = 16 * 1024;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; \
     frame-ancestors 'none'; base-uri 'none'";

const PERMISSIONS_POLICY: &str =
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()";

/// What every page needs to know.
#[derive(Clone)]
pub struct App {
    pub helper: Helper,
    /// The host in URL authority form, without a port: the name pages show
    /// and refusals point to.
    pub host: String,
    /// Other names requests may use, in the same form.
    pub other_hosts: Vec<String>,
    /// What refusals call the site: "panel" or "portal".
    pub site: &'static str,
    /// "https", or "http" for the development server.
    pub scheme: &'static str,
    pub assets: Arc<Assets>,
    pub ocserv_version: String,
    /// The container's host name, which the dashboard names the server by.
    pub instance: String,
    pub min_password_length: usize,
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login))
        .route(
            "/second-factor",
            get(second_factor_page).post(second_factor),
        )
        .route("/second-factor/passkey/start", post(passkey_sign_in_begin))
        .route("/second-factor/passkey", post(passkey_sign_in))
        .route("/password", get(password_page).post(change_password))
        .route("/enroll", get(enroll_page).post(confirm_enrollment))
        .route("/enroll/start", post(start_enrollment))
        .route("/sessions", get(sessions_page))
        .route("/sessions/end", post(end_vpn_session))
        .route("/users", get(users_page))
        .route("/users/change", post(change_vpn_user))
        .route("/bans", get(bans_page))
        .route("/bans/unban", post(unban))
        .route("/bans/block", post(block))
        .route("/bans/unblock", post(unblock))
        .route("/bans/keep", post(keep_block))
        .route("/bans/countries", post(set_countries))
        .route("/bans/locations", post(set_locations))
        .route("/users/allow-place", post(allow_place))
        .route("/vacation", post(set_vacation))
        .route("/bans/maxmind", post(set_maxmind_key))
        .route("/bans/maxmind/remove", post(remove_maxmind_key))
        .route("/sites", get(sites_page))
        .route("/sites/rules/add", post(add_site_rule))
        .route("/sites/rules/remove", post(remove_site_rule))
        .route("/sites/egress", post(set_site_egress))
        .route("/events", get(events_page))
        .route("/api/events", get(events_json))
        .route("/alerts", get(alerts_page))
        .route("/alerts/topics", post(set_alert_topics))
        .route("/alerts/channels", post(add_alert_channel))
        .route("/alerts/channels/test", post(test_alert_channel))
        .route("/alerts/channels/remove", post(remove_alert_channel))
        .route("/alerts/mail", post(set_mail_server))
        .route("/alerts/mail/remove", post(remove_mail_server))
        .route("/audit", get(audit_page))
        .route(
            "/settings",
            get(server_settings_page).post(save_server_settings),
        )
        .route("/certificates", get(certificates_page))
        .route("/certificates/issue", post(issue_certificate))
        .route("/certificates/renew", post(renew_certificate))
        .route("/certificates/revoke", post(revoke_certificate))
        .route("/account", get(account_page))
        .route("/account/sessions/end", post(end_other_sessions))
        .route("/account/passkeys/start", post(add_passkey_begin))
        .route("/account/passkeys", post(add_passkey_finish))
        .route("/account/passkeys/remove", post(remove_passkey))
        .route("/admins", get(admins_page))
        .route("/admins/change", post(change_admin))
        .route("/groups", get(groups_page).post(create_group))
        .route(
            "/groups/{name}",
            get(group_settings_page).post(save_group_settings),
        )
        .route(
            "/users/{name}/settings",
            get(user_settings_page).post(save_user_settings),
        )
        .route("/api/history", get(history_json))
        .route("/logout", post(logout))
        .route("/assets/{name}", get(asset))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}

/// The VPN user portal, on its own port, under the same browser rules as
/// the panel.
pub fn portal_router(app: App) -> Router {
    Router::new()
        .route("/", get(portal_home))
        .route("/login", get(portal_login_page).post(portal_login))
        .route("/code", get(portal_code_page).post(portal_code))
        .route("/key", post(portal_key_begin))
        .route("/key/confirm", post(portal_key_confirm))
        .route("/account", get(portal_account))
        .route("/account/password", post(portal_change_password))
        .route("/account/sessions/end", post(portal_end_session))
        .route("/logout", post(portal_logout))
        .route("/assets/{name}", get(asset))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}

/// The links every page's head carries.
struct PageLinks {
    css: String,
    js: String,
    logo: String,
}

impl App {
    fn links(&self) -> PageLinks {
        PageLinks {
            css: self.assets.url("app.css"),
            js: self.assets.url("app.js"),
            logo: self.assets.url("logo.svg"),
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    title: &'static str,
    page: PageLinks,
    host: String,
    error: Option<String>,
    name: String,
    warning: &'static str,
}

#[derive(Template)]
#[template(path = "second_factor.html")]
struct SecondFactorPage {
    title: &'static str,
    page: PageLinks,
    intro: &'static str,
    /// Whether the account has an authenticator app, whose code completes
    /// the sign-in.
    code: bool,
    /// Whether the account has passkeys that work at the panel's address.
    passkey: bool,
    warning: &'static str,
    passkey_icon: &'static str,
}

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordPage {
    title: &'static str,
    page: PageLinks,
    heading: &'static str,
    intro: &'static str,
    error: Option<String>,
    warning: &'static str,
    csrf: String,
    min_length: usize,
    /// Whether the admin came by choice and may go back to their account.
    back: bool,
}

#[derive(Template)]
#[template(path = "enroll.html")]
struct EnrollPage {
    title: &'static str,
    page: PageLinks,
    heading: &'static str,
    intro: &'static str,
    error: Option<String>,
    warning: &'static str,
    csrf: String,
    key: Option<EnrollKey>,
    /// Whether the admin came by choice and may go back to their account.
    back: bool,
    /// Whether the page also offers a passkey as the first second factor.
    passkey: bool,
    name_chars: usize,
    passkey_icon: &'static str,
}

/// An issued authenticator key, as the enrollment page shows it.
struct EnrollKey {
    /// The key's otpauth URI as an inline SVG drawing.
    qr: String,
    /// The key in groups of four characters.
    grouped: String,
    uri: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    title: &'static str,
    page: PageLinks,
    host: String,
    instance: String,
    shell: Shell,
    stats: Vec<Stat>,
    /// The newest live events, newest first.
    events: Vec<EventRow>,
    /// Why the events show no countries, and whose data names them.
    countries_note: Option<String>,
    country_credit: &'static str,
}

/// The newest live events the dashboard shows, as the approved prototype
/// shows them; the Live events page has the rest.
const DASHBOARD_EVENTS: usize = 4;

/// One figure on the dashboard: what it is, its value, and a line about it.
struct Stat {
    label: &'static str,
    value: String,
    note: String,
    icon: &'static str,
    /// "stat-ic", or "stat-ic stat-ic-bad" for a figure that needs attention.
    tone: &'static str,
}

#[derive(Template)]
#[template(path = "sessions.html")]
struct SessionsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    summary: String,
    notice: Option<Notice>,
    rows: Vec<SessionRow>,
    can_operate: bool,
    csrf: String,
    arrow_down: &'static str,
    arrow_up: &'static str,
    end_icon: &'static str,
    /// Why the sessions show no countries, and whose data names them.
    countries_note: Option<String>,
    country_credit: &'static str,
}

/// A message at the top of a page after an action.
struct Notice {
    /// "callout-ok" or "callout-bad".
    class: &'static str,
    icon: &'static str,
    text: String,
}

impl Notice {
    fn done(text: &str) -> Notice {
        Notice {
            class: "callout-ok",
            icon: icons::CHECK_CIRCLE,
            text: text.to_owned(),
        }
    }

    fn refused(text: String) -> Notice {
        Notice {
            class: "callout-bad",
            icon: icons::WARNING,
            text,
        }
    }
}

/// A connected VPN session as the Sessions page shows it.
struct SessionRow {
    id: u64,
    user: String,
    initials: String,
    /// The group and session number under the user's name.
    detail: String,
    client: String,
    vpn: Vec<String>,
    remote: String,
    /// The country of the address the session comes from.
    place: Option<RowPlace>,
    connected: String,
    sent: String,
    received: String,
    channel: &'static str,
    channel_class: &'static str,
    channel_title: &'static str,
}

/// The sidebar and top bar around every signed-in page.
struct Shell {
    version: &'static str,
    ocserv_version: String,
    nav: Vec<NavGroup>,
    admin: String,
    initials: String,
    role: &'static str,
    sign_out: &'static str,
    sun: &'static str,
}

struct NavGroup {
    label: &'static str,
    items: Vec<NavItem>,
}

struct NavItem {
    label: &'static str,
    href: &'static str,
    icon: &'static str,
    current: bool,
}

/// A signed-in admin, as the helper describes the session.
struct Who {
    session: String,
    name: String,
    role: Role,
    scope: Scope,
    csrf: String,
    must_change_password: bool,
    /// Whether passkeys can be added and used at the panel's address.
    passkeys: bool,
}

impl Who {
    /// The page this admin must see before any other.
    fn landing(&self) -> &'static str {
        landing(self.must_change_password, self.scope)
    }
}

/// The page an admin must see before any other: replacing a one-time
/// password, then setting up a second factor, then the dashboard.
fn landing(must_change_password: bool, scope: Scope) -> &'static str {
    if must_change_password {
        "/password"
    } else if matches!(scope, Scope::Enrollment) {
        "/enroll"
    } else {
        "/"
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "Owner",
        Role::Operator => "Operator",
        Role::Viewer => "Viewer",
    }
}

fn shell(app: &App, who: &Who, current: &str) -> Shell {
    let owner = matches!(who.role, Role::Owner);
    let item = |label, href, icon| NavItem {
        label,
        href,
        icon,
        current: href == current,
    };
    let mut nav = vec![
        NavGroup {
            label: "Monitor",
            items: vec![
                item("Dashboard", "/", icons::GAUGE),
                item("Sessions", "/sessions", icons::PLUGS),
                item("Live events", "/events", icons::PULSE),
                item("Alerts", "/alerts", icons::BELL_RINGING),
            ],
        },
        NavGroup {
            label: "Access",
            items: vec![
                item("VPN users", "/users", icons::USERS),
                item("Groups", "/groups", icons::USERS_THREE),
                item("Bans", "/bans", icons::PROHIBIT),
                item("Sites", "/sites", icons::TREE_STRUCTURE),
            ],
        },
    ];
    let mut server = vec![item("Certificates", "/certificates", icons::CERTIFICATE)];
    if owner {
        server.insert(0, item("Settings", "/settings", icons::SLIDERS));
        nav.push(NavGroup {
            label: "Server",
            items: server,
        });
        nav.push(NavGroup {
            label: "Panel",
            items: vec![
                item("Admins", "/admins", icons::SHIELD_STAR),
                item("Audit log", "/audit", icons::SCROLL),
            ],
        });
    } else {
        nav.push(NavGroup {
            label: "Server",
            items: server,
        });
    }
    Shell {
        version: env!("CARGO_PKG_VERSION"),
        ocserv_version: app.ocserv_version.clone(),
        nav,
        initials: who.name.chars().take(2).collect::<String>().to_uppercase(),
        admin: who.name.clone(),
        role: role_name(who.role),
        sign_out: icons::SIGN_OUT,
        sun: icons::SUN,
    }
}

async fn dashboard(State(app): State<App>, headers: HeaderMap) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let answer = app
        .helper
        .call(Ask::ServerStatus {
            session: who.session.clone(),
        })
        .await;
    let server = match answer {
        Ok(Answer::Server { server }) => server,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a status request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::ListEvents {
            session: who.session.clone(),
            after: None,
        })
        .await;
    let (events, places) = match answer {
        Ok(Answer::Events { events, places, .. }) => (events, Places::of(places)),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered an event list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    html(&DashboardPage {
        title: "Dashboard - OpenConnect admin",
        page: app.links(),
        host: app.host.clone(),
        instance: app.instance.clone(),
        shell: shell(&app, &who, "/"),
        stats: stats(&server, now),
        events: events
            .iter()
            .rev()
            .take(DASHBOARD_EVENTS)
            .map(|logged| event_row(logged, &places, &app.assets))
            .collect(),
        countries_note: places.note(),
        country_credit: places.credit,
    })
}

/// The dashboard's figures for the server as occtl reports it.
fn stats(server: &Status, now: u64) -> Vec<Stat> {
    let stat = |label, value: String, note: String, icon| Stat {
        label,
        value,
        note,
        icon,
        tone: "stat-ic",
    };
    match server {
        Status::Online {
            up_since,
            active_sessions,
            total_sessions,
            auth_failures,
            banned_addresses,
        } => vec![
            stat(
                "VPN server",
                "Running".to_owned(),
                format!("For {}", span(now.saturating_sub(*up_since))),
                icons::POWER,
            ),
            stat(
                "Connected sessions",
                active_sessions.to_string(),
                format!("{total_sessions} ended since the statistics were last reset"),
                icons::PLUGS,
            ),
            stat(
                "Failed sign-ins",
                auth_failures.to_string(),
                "Since the VPN server started".to_owned(),
                icons::WARNING,
            ),
            stat(
                "Banned addresses",
                banned_addresses.to_string(),
                "Blocked for a while after too many failed sign-ins".to_owned(),
                icons::PROHIBIT,
            ),
        ],
        Status::Offline => vec![Stat {
            label: "VPN server",
            value: "Not answering".to_owned(),
            note: "occtl cannot reach ocserv; the container log says why".to_owned(),
            icon: icons::POWER,
            tone: "stat-ic stat-ic-bad",
        }],
    }
}

#[derive(Deserialize)]
struct SessionsQuery {
    ended: Option<u8>,
}

async fn sessions_page(
    State(app): State<App>,
    Query(query): Query<SessionsQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = query
        .ended
        .is_some()
        .then(|| Notice::done("The session has ended. The user must sign in again to reconnect."));
    sessions_view(&app, &who, notice).await
}

/// The Sessions page: every connected VPN session, with a button to end
/// each one for owners and operators.
async fn sessions_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::ListSessions {
            session: who.session.clone(),
        })
        .await;
    let (sessions, places) = match answer {
        Ok(Answer::Sessions { sessions, places }) => (sessions, Places::of(places)),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a session list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    let summary = match sessions.len() {
        0 => "No one is connected right now".to_owned(),
        1 => "1 session connected".to_owned(),
        count => format!("{count} sessions connected"),
    };
    html(&SessionsPage {
        title: "Sessions - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/sessions"),
        summary,
        notice,
        rows: sessions
            .iter()
            .map(|vpn| session_row(vpn, now, &places, &app.assets))
            .collect(),
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        arrow_down: icons::ARROW_DOWN,
        arrow_up: icons::ARROW_UP,
        end_icon: icons::SIGN_OUT,
        countries_note: places.note(),
        country_credit: places.credit,
    })
}

fn session_row(vpn: &VpnSession, now: u64, places: &Places, assets: &Assets) -> SessionRow {
    let reported = |value: &Option<String>| match value {
        Some(value) => value.clone(),
        None => "Not reported".to_owned(),
    };
    let counted = |bytes: Option<u64>| match bytes {
        Some(bytes) => units::amount(bytes),
        None => "Not reported".to_owned(),
    };
    let (channel, channel_class, channel_title) = if vpn.udp {
        (
            "UDP and TCP",
            "pill-ok",
            "Traffic goes over DTLS on UDP, with TCP as the fallback",
        )
    } else {
        (
            "TCP only",
            "pill-mute",
            "DTLS is not in use, so all traffic goes over TCP",
        )
    };
    SessionRow {
        id: vpn.id,
        user: vpn.user.clone(),
        initials: vpn.user.chars().take(2).collect::<String>().to_uppercase(),
        detail: match &vpn.group {
            Some(group) => format!("Group {group}, session {}", vpn.id),
            None => format!("Session {}", vpn.id),
        },
        client: reported(&vpn.user_agent),
        vpn: [&vpn.vpn_ipv4, &vpn.vpn_ipv6]
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        remote: reported(&vpn.remote_ip),
        place: vpn
            .remote_ip
            .as_deref()
            .and_then(|address| places.of_address(address, assets)),
        connected: span(now.saturating_sub(vpn.connected_at)),
        sent: counted(vpn.sent),
        received: counted(vpn.received),
        channel,
        channel_class,
        channel_title,
    }
}

#[derive(Deserialize)]
struct EndForm {
    csrf: String,
    id: u64,
}

async fn end_vpn_session(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<EndForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::EndSession {
            session: who.session.clone(),
            csrf: form.csrf,
            id: form.id,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/sessions?ended=1", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            sessions_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a request to end a session with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    summary: String,
    notice: Option<Notice>,
    rows: Vec<UserRow>,
    /// Whether the VPN asks every user for a code after the password.
    codes: bool,
    can_operate: bool,
    csrf: String,
    /// The shortest password an admin may type for a VPN user.
    min_length: usize,
    /// The sign-ins the location checks refused, newest first.
    refused: Vec<RefusedRow>,
    location_icon: &'static str,
    /// Whether the location checks are on, which the vacation actions
    /// need, and the first and last day a vacation may end on.
    locations_on: bool,
    vacation_from: String,
    vacation_to: String,
}

/// A sign-in the location checks refused, as the VPN users page lists it.
struct RefusedRow {
    user: String,
    from: String,
    /// The country of the address.
    place: Option<RowPlace>,
    /// What it scored and why.
    why: String,
    /// When, as an RFC 3339 UTC timestamp and as the page shows it before
    /// its script turns it to local time.
    stamp: String,
    text: String,
    /// Whether the place is usual for the user now, as once allowed.
    known: bool,
}

/// The icons the onboarding kit draws.
struct KitIcons {
    warning: &'static str,
    printer: &'static str,
    done: &'static str,
    connection: &'static str,
    phone: &'static str,
    laptop: &'static str,
    copy: &'static str,
}

#[derive(Template)]
#[template(path = "kit.html")]
struct KitPage {
    title: String,
    page: PageLinks,
    shell: Shell,
    icons: KitIcons,
    /// What the page shows only once, and how to replace it.
    warning: &'static str,
    user: String,
    groups_label: &'static str,
    groups: String,
    address: String,
    pin: String,
    password: Option<String>,
    key: Option<EnrollKey>,
    setup: Setup,
}

/// How to set up a client, as the onboarding kit and the portal give it.
struct Setup {
    /// The address with the camouflage secret, when ocserv hides behind one.
    secret_url: Option<String>,
    cisco: bool,
    /// What a client connects to: the address, or the URL with the
    /// camouflage secret.
    server: String,
    /// The openconnect command line, one argument per line.
    command: String,
    /// The sign-in step, with the code when the VPN asks for one.
    sign_in: String,
}

/// How `kit`'s user sets up a client. `whose` goes before the password and
/// the app in the sign-in step: "the" in an admin's kit, "your" in the
/// portal.
fn setup_of(kit: &Kit, whose: &str) -> Setup {
    let secret_url = kit.camouflage.as_ref().map(|_| kit.url());
    let server = match &secret_url {
        Some(url) => url.clone(),
        None => kit.address.clone(),
    };
    let sign_in = if kit.codes {
        format!(
            "Sign in as {} with {whose} password, then the six-digit code from {whose} \
             authenticator app.",
            kit.user
        )
    } else {
        format!("Sign in as {} with {whose} password.", kit.user)
    };
    Setup {
        command: format!(
            "openconnect --user={} \\\n  --servercert={} \\\n  {}",
            shell_word(&kit.user),
            shell_word(&kit.pin),
            shell_word(&server)
        ),
        secret_url,
        cisco: kit.cisco,
        server,
        sign_in,
    }
}

/// `text` as one shell word: as it is when no shell treats any of its
/// characters specially, else in single quotes.
fn shell_word(text: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// An issued authenticator key as a page shows it.
fn enroll_key(authenticator: &Authenticator) -> Result<EnrollKey, String> {
    Ok(EnrollKey {
        qr: qr::svg(&authenticator.uri)?,
        grouped: grouped(&authenticator.key),
        uri: authenticator.uri.clone(),
    })
}

fn kit_icons() -> KitIcons {
    KitIcons {
        warning: icons::WARNING,
        printer: icons::PRINTER,
        done: icons::CHECK_CIRCLE,
        connection: icons::ID_CARD,
        phone: icons::PHONE,
        laptop: icons::LAPTOP,
        copy: icons::COPY,
    }
}

/// The onboarding kit, shown once in answer to the change that made it.
fn kit_view(app: &App, who: &Who, kit: &Kit) -> Response {
    let key = match kit.authenticator.as_ref().map(enroll_key).transpose() {
        Ok(key) => key,
        Err(error) => return failure(&error),
    };
    let warning = match (kit.password.is_some(), key.is_some()) {
        (true, true) => {
            "The password and the authenticator key are shown on this page once. The panel \
             does not keep them, so print the page or copy them now. To replace them later, \
             set a new password or reset the authenticator."
        }
        (true, false) => {
            "The password is shown on this page once. The panel does not keep it, so print \
             the page or copy it now. To replace it later, set a new password."
        }
        (false, true | false) => {
            "The authenticator key is shown on this page once. The panel does not keep it, so \
             print the page or scan it now. To replace it later, reset the authenticator."
        }
    };
    let (groups_label, groups) = groups_of(kit);
    html(&KitPage {
        title: format!("Onboarding kit for {} - OpenConnect admin", kit.user),
        page: app.links(),
        shell: shell(app, who, "/users"),
        icons: kit_icons(),
        warning,
        user: kit.user.clone(),
        groups_label,
        groups,
        address: kit.address.clone(),
        pin: kit.pin.clone(),
        password: kit.password.clone(),
        key,
        setup: setup_of(kit, "the"),
    })
}

/// The label and the text of a kit's groups.
fn groups_of(kit: &Kit) -> (&'static str, String) {
    match kit.groups.as_slice() {
        [] => ("Group", "None".to_owned()),
        [one] => ("Group", one.clone()),
        many => ("Groups", many.join(", ")),
    }
}

/// A VPN user as the VPN users page shows it.
struct UserRow {
    name: String,
    initials: String,
    groups: String,
    /// The groups as the form that changes them takes: comma-separated.
    group_list: String,
    locked: bool,
    otp: bool,
    sessions: String,
    /// The last day of the user's vacation, while it lasts.
    vacation: Option<String>,
}

#[derive(Deserialize)]
struct UsersQuery {
    done: Option<String>,
}

async fn users_page(
    State(app): State<App>,
    Query(query): Query<UsersQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("lock") => Some(Notice::done(
            "Locked the user. Their sessions have ended, and they cannot sign in until unlocked.",
        )),
        Some("unlock") => Some(Notice::done("Unlocked the user.")),
        Some("groups") => Some(Notice::done(
            "Changed the user's groups. ocserv uses them from the user's next connection.",
        )),
        Some("remove") => Some(Notice::done("Removed the user. Their sessions have ended.")),
        Some("allowed") => Some(Notice::done(
            "Allowed the place. The user's next sign-in from there goes through, unless a \
             session of theirs is still open far away.",
        )),
        Some("vacation") => Some(Notice::done("Saved the vacation.")),
        Some(_) | None => None,
    };
    users_view(&app, &who, notice).await
}

#[derive(Deserialize)]
struct VacationForm {
    csrf: String,
    /// "vpn" or "admin".
    kind: String,
    name: String,
    /// The vacation's last day, YYYY-MM-DD; empty to end it.
    until: String,
    /// The page the form is on: "users", "admins" or "account".
    back: String,
}

/// Puts a VPN user or an admin on vacation, or ends it, and goes back to
/// the page the form is on.
async fn set_vacation(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<VacationForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let kind = match form.kind.as_str() {
        "vpn" => AccountKind::Vpn,
        "admin" => AccountKind::Admin,
        other => return bad_request(&format!("'{other}' is not a kind of account")),
    };
    let (back, done) = match form.back.as_str() {
        "users" => ("/users", "/users?done=vacation"),
        "admins" => ("/admins", "/admins?done=vacation"),
        "account" => ("/account", "/account?done=vacation"),
        other => return bad_request(&format!("'{other}' is not a page with vacations")),
    };
    let until = if form.until.is_empty() {
        None
    } else {
        Some(form.until)
    };
    let answer = app
        .helper
        .call(Ask::SetVacation {
            session: who.session.clone(),
            csrf: form.csrf,
            kind,
            name: form.name,
            until,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            let notice = Some(Notice::refused(sentence(&message)));
            match back {
                "/users" => users_view(&app, &who, notice).await,
                "/admins" => admins_view(&app, &who, notice, None).await,
                _account => account_view(&app, &who, notice).await,
            }
        }
        Ok(other) => failure(&format!(
            "the helper answered a vacation change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct AllowPlaceForm {
    csrf: String,
    user: String,
    from: String,
}

/// Makes the place of a refused sign-in usual for its VPN user, for an
/// owner or operator.
async fn allow_place(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<AllowPlaceForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::AllowPlace {
            session: who.session.clone(),
            csrf: form.csrf,
            user: form.user,
            from: form.from,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/users?done=allowed", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            users_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered Allow this place with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The VPN users page: every user in the password file, with the sessions
/// each has now.
async fn users_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let listed = app
        .helper
        .call(Ask::ListVpnUsers {
            session: who.session.clone(),
        })
        .await;
    let (users, codes, refused, places, locations_on, vacations) = match listed {
        Ok(Answer::VpnUsers {
            users,
            codes,
            refused,
            places,
            locations_on,
            vacations,
        }) => (
            users,
            codes,
            refused,
            Places::of(places),
            locations_on,
            vacations,
        ),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a user list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let connected = app
        .helper
        .call(Ask::ListSessions {
            session: who.session.clone(),
        })
        .await;
    let sessions = match connected {
        Ok(Answer::Sessions { sessions, .. }) => sessions,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a session list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let rows: Vec<UserRow> = users
        .iter()
        .map(|user| {
            let count = sessions.iter().filter(|vpn| vpn.user == user.name).count();
            UserRow {
                name: user.name.clone(),
                initials: user.name.chars().take(2).collect::<String>().to_uppercase(),
                groups: match user.groups.as_slice() {
                    [] => "No group".to_owned(),
                    [one] => format!("Group {one}"),
                    many => format!("Groups {}", many.join(", ")),
                },
                group_list: user.groups.join(", "),
                locked: user.locked,
                otp: user.otp,
                sessions: match count {
                    0 => "Not connected".to_owned(),
                    1 => "1 session".to_owned(),
                    count => format!("{count} sessions"),
                },
                vacation: vacations
                    .iter()
                    .find(|(name, _until)| *name == user.name)
                    .map(|(_name, until)| vacation_last_day(*until)),
            }
        })
        .collect();
    let (vacation_from, vacation_to) = match clock::now() {
        Ok(now) => vacation_range(now),
        Err(error) => return failure(&error),
    };
    let locked = rows.iter().filter(|row| row.locked).count();
    let mut summary = match (rows.len(), locked) {
        (0, _) => "No users yet".to_owned(),
        (1, 0) => "1 user".to_owned(),
        (count, 0) => format!("{count} users"),
        (count, locked) => format!("{count} users, {locked} of them locked"),
    };
    let keyless = rows.iter().filter(|row| !row.otp).count();
    if codes && keyless > 0 {
        summary.push_str(&match keyless {
            1 => "; 1 has no authenticator key and cannot sign in".to_owned(),
            count => format!("; {count} have no authenticator key and cannot sign in"),
        });
    }
    html(&UsersPage {
        title: "VPN users - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/users"),
        summary,
        notice,
        rows,
        codes,
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        min_length: app.min_password_length,
        refused: refused
            .into_iter()
            .map(|sign_in| {
                let stamp = clock::rfc3339(sign_in.time);
                RefusedRow {
                    place: places.of_address(&sign_in.from, &app.assets),
                    why: capitalized(&format!(
                        "scored {} of 100: {}",
                        sign_in.score,
                        sign_in.reasons.join("; ")
                    )),
                    text: stamp.replace('T', " ").replace('Z', ""),
                    stamp,
                    known: sign_in.known,
                    user: sign_in.user,
                    from: sign_in.from,
                }
            })
            .collect(),
        location_icon: icons::MAP_PIN,
        locations_on,
        vacation_from,
        vacation_to,
    })
}

#[derive(Deserialize)]
struct UserForm {
    csrf: String,
    change: String,
    name: String,
    #[serde(default)]
    groups: String,
    /// `generate` for a generated password, `type` for the typed one.
    #[serde(default)]
    password_choice: String,
    #[serde(default)]
    password: String,
}

/// The password a user form asks for: none to generate one. A typed
/// password with the generated choice is refused rather than dropped.
fn form_password(choice: &str, password: String) -> Result<Option<String>, String> {
    match (choice, password.is_empty()) {
        ("generate", true) => Ok(None),
        ("generate", false) => Err(
            "a password was typed, but the form asked to generate one; choose Type a \
             password to use it"
                .to_owned(),
        ),
        ("type" | "", _) => Ok(Some(password)),
        (other, _) => Err(format!("'{other}' is not a way to choose a password")),
    }
}

async fn change_vpn_user(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<UserForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let UserForm {
        csrf,
        change,
        name,
        groups,
        password_choice,
        password,
    } = form;
    let password = match change.as_str() {
        "add" | "password" => match form_password(&password_choice, password) {
            Ok(password) => password,
            Err(message) => {
                return users_view(&app, &who, Some(Notice::refused(sentence(&message)))).await;
            }
        },
        _ => None,
    };
    let (change, done) = match change.as_str() {
        "add" => (
            UserChange::Add {
                name,
                groups,
                password,
            },
            "/users",
        ),
        "password" => (UserChange::SetPassword { name, password }, "/users"),
        "groups" => (UserChange::SetGroups { name, groups }, "/users?done=groups"),
        "reset_otp" => (UserChange::ResetOtp { name }, "/users"),
        "lock" => (UserChange::Lock { name }, "/users?done=lock"),
        "unlock" => (UserChange::Unlock { name }, "/users?done=unlock"),
        "remove" => (UserChange::Remove { name }, "/users?done=remove"),
        other => return bad_request(&format!("'{other}' is not a change to a user")),
    };
    let answer = app
        .helper
        .call(Ask::ChangeVpnUser {
            session: who.session.clone(),
            csrf,
            change,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Kit { kit }) => kit_view(&app, &who, &kit),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            users_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a change to a user with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Template)]
#[template(path = "bans.html")]
struct BansPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    /// How ocserv scores and bans addresses, in a sentence or two.
    policy: String,
    bans_off: bool,
    notice: Option<Notice>,
    banned: Vec<BanRow>,
    points: Vec<PointsRow>,
    can_operate: bool,
    csrf: String,
    ban_icon: &'static str,
    points_icon: &'static str,
    /// The firewall's blocklist and when it blocks by itself.
    blocks: Vec<BlockRow>,
    auto_block: String,
    block_icon: &'static str,
    countries: CountriesCard,
    database: DatabaseCard,
    locations: LocationsCard,
    /// Whose data names the countries: "dbip", "maxmind" or empty.
    country_credit: &'static str,
}

/// The Country database card of the Bans page.
struct DatabaseCard {
    /// The database in use, or why none could be read, and when it was
    /// built, as a date.
    name: &'static str,
    unread: Option<String>,
    built: String,
    /// The account ID of the MaxMind key in force, empty without one, and
    /// whether the environment sets the key.
    account: String,
    from_env: bool,
    /// Whether a GeoLite2 download is under way.
    busy: bool,
    /// How the last download ended.
    last: Option<Notice>,
    /// Whether this admin may change the key here: an owner, while the
    /// environment sets none and no download is under way.
    can_change: bool,
    icon: &'static str,
}

/// The Country database card for `view`, as `who` may use it at `now`.
fn database_card(view: &CountryView, who: &Who, now: u64) -> DatabaseCard {
    let (name, unread) = match &view.database {
        Ok(kind) if credit_of(kind) == "maxmind" => ("MaxMind GeoLite2 Country", None),
        Ok(_kind) => ("DB-IP IP to Country Lite", None),
        Err(problem) => ("No country database", Some(problem.clone())),
    };
    let built = clock::rfc3339(view.built);
    let last = view.maxmind_last.as_ref().map(|(when, outcome)| {
        let ago = span(now.saturating_sub(*when));
        match outcome {
            Ok(done) => Notice::done(&format!("{} {ago} ago.", capitalized(done))),
            Err(why) => Notice::refused(format!("The GeoLite2 download {ago} ago failed: {why}.")),
        }
    });
    DatabaseCard {
        name,
        unread,
        built: match built.get(..10) {
            Some(date) => date.to_owned(),
            None => built.clone(),
        },
        account: match &view.maxmind_account {
            Some(account) => account.clone(),
            None => String::new(),
        },
        from_env: view.maxmind_from_env,
        busy: view.maxmind_busy,
        last,
        can_change: matches!(who.role, Role::Owner) && !view.maxmind_from_env && !view.maxmind_busy,
        icon: icons::GLOBE_HEMISPHERE_WEST,
    }
}

/// The Location checks card of the Bans page.
struct LocationsCard {
    on: bool,
    /// The pill beside the title: its class and its text.
    pill: (&'static str, &'static str),
    refresh_hours: u64,
    /// Whether the environment sets the checks, or their schedule, which
    /// the form then shows and keeps.
    on_locked: bool,
    refresh_locked: bool,
    /// Whether this admin may change them here: an owner.
    can_change: bool,
    /// Which data the checks read, in a sentence.
    data: String,
    /// Whose data the checks read: "dbip", "maxmind" or empty, which the
    /// card credits.
    credit: &'static str,
    /// How the last check for newer data ended, while the checks are on.
    last: Option<Notice>,
    icon: &'static str,
}

/// A location database as the panel names it, from what it calls itself:
/// "DB-IP City Lite" for `DBIP-City-Lite`, "MaxMind GeoLite2 ASN" for
/// `GeoLite2-ASN`.
fn edition_name(kind: &str) -> String {
    let kind = match kind.split_once(" (") {
        Some((name, _compatible)) => name,
        None => kind,
    };
    match (kind.strip_prefix("DBIP-"), kind.strip_prefix("GeoLite2-")) {
        (Some(rest), _maxmind) => format!("DB-IP {}", rest.replace('-', " ")),
        (None, Some(rest)) => format!("MaxMind GeoLite2 {}", rest.replace('-', " ")),
        (None, None) => kind.to_owned(),
    }
}

/// The first and the last day a vacation may end on at `now`, as a date
/// field's min and max.
fn vacation_range(now: u64) -> (String, String) {
    (
        date_of(now),
        date_of(now + location::MAX_VACATION_DAYS * 86_400),
    )
}

/// The last day of a vacation that ends at `until`.
fn vacation_last_day(until: u64) -> String {
    date_of(until.saturating_sub(1))
}

/// The UTC date of a Unix time.
fn date_of(seconds: u64) -> String {
    let stamp = clock::rfc3339(seconds);
    match stamp.get(..10) {
        Some(date) => date.to_owned(),
        None => stamp,
    }
}

/// The Location checks card for `view`, as `who` may use it at `now`.
fn locations_card(view: &LocationView, who: &Who, now: u64) -> LocationsCard {
    let data = if !view.on {
        "While the checks are off, no city or network data is downloaded or read. Turning them \
         on downloads DB-IP City Lite and ASN Lite, about 65 MB, which take about 140 MB in \
         /config/geoip and in the helper's memory; while a MaxMind key is set, MaxMind \
         GeoLite2 City and ASN instead."
            .to_owned()
    } else {
        match (&view.city, &view.networks) {
            (Some(city), Some(networks)) => format!(
                "Places come from {}, built {}, and networks from {}, built {}.",
                edition_name(&city.kind),
                date_of(city.built),
                edition_name(&networks.kind),
                date_of(networks.built)
            ),
            (Some(city), None) => format!(
                "Places come from {}, built {}. No network data is read yet, so a new network \
                 does not count.",
                edition_name(&city.kind),
                date_of(city.built)
            ),
            (None, _networks) => "Until the city and network data are read, sign-ins go through \
                                  unchecked; the panel downloads and reads them in the \
                                  background."
                .to_owned(),
        }
    };
    let pill = match (view.on, &view.city) {
        (false, _city) => ("pill-mute", "Off"),
        (true, Some(_city)) => ("pill-ok", "On"),
        (true, None) => ("pill-warn", "Waiting for data"),
    };
    let credit = match &view.city {
        Some(city) if view.on => credit_of(&city.kind),
        _shown => "",
    };
    let last = match &view.last {
        Some((when, outcome)) if view.on => {
            let ago = span(now.saturating_sub(*when));
            Some(match outcome {
                Ok(installed) if installed.is_empty() => Notice::done(&format!(
                    "Looked for newer data {ago} ago: the copies in use are the newest."
                )),
                Ok(installed) => Notice::done(&format!(
                    "Downloaded {} {ago} ago.",
                    installed.join(" and ")
                )),
                Err(why) => {
                    Notice::refused(format!("The check for newer data {ago} ago failed: {why}."))
                }
            })
        }
        _shown => None,
    };
    LocationsCard {
        on: view.on,
        pill,
        refresh_hours: view.refresh_hours,
        on_locked: view.on_from_env,
        refresh_locked: view.refresh_from_env,
        can_change: matches!(who.role, Role::Owner),
        data,
        credit,
        last,
        icon: icons::MAP_PIN,
    }
}

/// The Countries card of the Bans page.
struct CountriesCard {
    /// off, block or allow: the rule in force, and in words.
    rule: String,
    rule_text: &'static str,
    /// The pill beside the title: its class and its text.
    pill: (&'static str, String),
    listed: Vec<CountryName>,
    /// The countries the database knows that are not listed, by name.
    others: Vec<CountryName>,
    rule_locked: bool,
    list_locked: bool,
    /// Whether this admin may change the rules here: an owner, while the
    /// firewall carries them and the country database could be read.
    can_change: bool,
    /// What keeps the rules from working or from being changed here.
    problem: Option<String>,
    /// Failed sign-ins by country, most first.
    failed: Vec<CountryBar>,
    /// The time the events kept span, as "the last 24 hours".
    period: String,
    suggestion: Option<CountrySuggestion>,
    /// Whose data names the countries: "dbip", "maxmind" or empty, which
    /// the page credits below the card.
    credit: &'static str,
    icon: &'static str,
    warning_icon: &'static str,
}

/// A country by its ISO code, its name and its flag.
struct CountryName {
    code: String,
    name: String,
    flag: String,
}

/// A country's failed sign-ins as the Countries card charts them.
struct CountryBar {
    /// The country's name, "No country", or how many other countries.
    label: String,
    /// The country's flag; none for no country or several.
    flag: Option<String>,
    count: u64,
    /// The count as a share of the largest, in percent from 0 to 100.
    share: u64,
    /// Whether the country rules list it.
    listed: bool,
}

/// The country the failed sign-ins suggest listing.
struct CountrySuggestion {
    code: String,
    name: String,
    flag: String,
    /// Its share of the failed sign-ins, in percent.
    share: u64,
}

/// A blocked address or network as the Bans page shows it.
struct BlockRow {
    network: String,
    /// How long the block has left, or that it stays.
    lifts: String,
    reason: String,
    /// Whether the block lifts by itself, so it can be made to stay.
    timed: bool,
}

/// A banned address as the Bans page shows it.
struct BanRow {
    address: String,
    score: u64,
    time_left: String,
}

/// An address with ban points and no ban, as the Bans page shows it.
struct PointsRow {
    address: String,
    score: u64,
    /// The points as a share of the ban score, in percent from 0 to 100.
    share: u64,
    /// The points against the ban score, for assistive technology.
    label: String,
}

#[derive(Deserialize)]
struct BansQuery {
    done: Option<u8>,
}

async fn bans_page(
    State(app): State<App>,
    Query(query): Query<BansQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = query.done.map(|done| {
        Notice::done(match done {
            5 => "Saved the country rules. The firewall applies them to new connections.",
            6 => {
                "Downloading MaxMind GeoLite2 with the key, which is kept once MaxMind accepts it. \
                 Reload this page in a minute to see how the download ended."
            }
            7 => "Removed the MaxMind key and its GeoLite2 copy. Countries come from DB-IP Lite again.",
            8 => {
                "Saved the location checks. While they are on, the panel downloads the city and \
                 network data they lack, which can take a few minutes."
            }
            9 => "The location checks are off. No city or network data is read.",
            2 => "Blocked. The firewall now drops everything from it on every port.",
            3 => "Lifted the block. The firewall admits it again.",
            4 => "The block stays until it is lifted.",
            _ => "Lifted the ban and cleared the address's points. It can connect again.",
        })
    });
    bans_view(&app, &who, notice).await
}

/// The Bans page: the addresses ocserv has banned, with a button to lift
/// each ban for owners and operators, and the addresses gathering points.
async fn bans_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::ListBans {
            session: who.session.clone(),
        })
        .await;
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    let (banned, points, policy, blocks, auto, countries, locations) = match answer {
        Ok(Answer::Bans {
            banned,
            points,
            policy,
            blocks,
            auto,
            countries,
            locations,
        }) => (banned, points, policy, blocks, auto, countries, locations),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a ban list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let database = database_card(&countries, who, now);
    let countries = countries_card(*countries, who, &app.assets);
    let locations = locations_card(&locations, who, now);
    html(&BansPage {
        title: "Bans - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/bans"),
        policy: ban_policy(&policy),
        bans_off: policy.max_score == 0,
        notice,
        points: points_rows(&points, &banned, &policy),
        banned: ban_rows(banned),
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        ban_icon: icons::PROHIBIT,
        points_icon: icons::WARNING,
        blocks: blocks
            .into_iter()
            .map(|block| BlockRow {
                lifts: match block.until {
                    Some(until) => format!("Lifts in {}", span(until.saturating_sub(now))),
                    None => "Stays until lifted".to_owned(),
                },
                timed: block.until.is_some(),
                network: block.network,
                reason: capitalized(&block.reason),
            })
            .collect(),
        auto_block: auto_block_policy(auto),
        block_icon: icons::SHIELD_STAR,
        country_credit: countries.credit,
        countries,
        database,
        locations,
    })
}

/// The countries the Countries card charts one by one; the rest are summed.
const COUNTRIES_CHARTED: usize = 9;

/// The Countries card for `view`, as `who` may use it. It suggests listing
/// the country with the most failed sign-ins that is not listed and that no
/// VPN user connected from, when it has at least 10 of them and a tenth of
/// them all.
fn countries_card(view: CountryView, who: &Who, assets: &Assets) -> CountriesCard {
    let names: BTreeMap<String, String> = view.names.into_iter().collect();
    let name_of = |code: &str| match names.get(code) {
        Some(name) => name.clone(),
        None => code.to_owned(),
    };
    let listed: Vec<CountryName> = view
        .listed
        .iter()
        .map(|code| CountryName {
            code: code.clone(),
            name: name_of(code),
            flag: assets.flag(code),
        })
        .collect();
    let mut others: Vec<CountryName> = names
        .iter()
        .filter(|(code, _name)| !view.listed.contains(code))
        .map(|(code, name)| CountryName {
            code: code.clone(),
            name: name.clone(),
            flag: assets.flag(code),
        })
        .collect();
    others.sort_by(|a, b| a.name.cmp(&b.name));
    let countries = |count: usize| match count {
        1 => "1 country".to_owned(),
        count => format!("{count} countries"),
    };
    let pill = match view.rule.as_str() {
        "block" => ("pill-bad", format!("Blocking {}", countries(listed.len()))),
        "allow" => (
            "pill-warn",
            format!("Allowing only {}", countries(listed.len())),
        ),
        _ => ("pill-mute", "Off".to_owned()),
    };
    let (credit, mut problem) = match &view.database {
        Ok(kind) => (credit_of(kind), None),
        Err(problem) => (
            "",
            Some(format!(
                "No country database could be read, so countries cannot be named or chosen \
                 here: {problem}."
            )),
        ),
    };
    if problem.is_none() && !view.enforceable {
        problem = Some(
            "This firewall is legacy iptables, which cannot carry country rules, so they are \
             off."
                .to_owned(),
        );
    }
    let total: u64 = view.failed.iter().map(|(_code, count)| count).sum();
    let largest = view.failed.first().map_or(0, |(_code, count)| *count);
    let bar = |label: String, flag: Option<String>, count: u64, listed: bool| CountryBar {
        label,
        flag,
        count,
        share: (count * 100 / largest.max(1)).min(100),
        listed,
    };
    let mut failed: Vec<CountryBar> = view
        .failed
        .iter()
        .take(COUNTRIES_CHARTED)
        .map(|(code, count)| match code {
            Some(code) => bar(
                name_of(code),
                Some(assets.flag(code)),
                *count,
                view.listed.contains(code),
            ),
            None => bar("No country".to_owned(), None, *count, false),
        })
        .collect();
    if let Some(rest) = view.failed.get(COUNTRIES_CHARTED..)
        && !rest.is_empty()
    {
        let label = match rest.len() {
            1 => "1 other country".to_owned(),
            count => format!("{count} other countries"),
        };
        failed.push(bar(
            label,
            None,
            rest.iter().map(|(_code, count)| count).sum(),
            false,
        ));
    }
    let suggestion = if view.rule == "allow" {
        None
    } else {
        view.failed
            .iter()
            .find_map(|(code, count)| match code {
                Some(code)
                    if *count >= 10
                        && !view.listed.contains(code)
                        && !view.connected.contains(code) =>
                {
                    Some((code, count * 100 / total.max(1)))
                }
                Some(_code) => None,
                None => None,
            })
            .filter(|(_code, share)| *share >= 10)
            .map(|(code, share)| CountrySuggestion {
                code: code.clone(),
                name: name_of(code),
                flag: assets.flag(code),
                share,
            })
    };
    let period = match view.hours {
        1 => "the last hour".to_owned(),
        hours if hours > 24 && hours % 24 == 0 => format!("the last {} days", hours / 24),
        hours => format!("the last {hours} hours"),
    };
    CountriesCard {
        can_change: matches!(who.role, Role::Owner)
            && view.enforceable
            && view.database.is_ok()
            && !(view.rule_from_env && view.list_from_env),
        rule_text: match view.rule.as_str() {
            "block" => "Block the listed countries",
            "allow" => "Allow only the listed countries",
            _ => "Off",
        },
        rule: view.rule,
        pill,
        listed,
        others,
        rule_locked: view.rule_from_env,
        list_locked: view.list_from_env,
        problem,
        failed,
        period,
        suggestion,
        credit,
        icon: icons::GLOBE_HEMISPHERE_WEST,
        warning_icon: icons::WARNING,
    }
}

/// When the firewall blocks an address by itself, as the Bans page explains
/// it.
fn auto_block_policy(auto: AutoBlock) -> String {
    if auto.bans == 0 {
        return "Addresses are blocked only by hand: PANEL_BLOCK_AFTER_BANS is 0.".to_owned();
    }
    format!(
        "An address ocserv bans {} times within {} is blocked at the firewall for {}, on every \
         port: the VPN, this panel and the user portal.",
        auto.bans,
        span(auto.window),
        span(auto.duration),
    )
}

#[derive(Deserialize)]
struct BlockForm {
    csrf: String,
    network: String,
    /// Hours, or "lifted" for a block that stays until it is lifted.
    duration: String,
}

async fn block(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<BlockForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let hours = match form.duration.as_str() {
        "lifted" => None,
        text => match text.parse::<u64>() {
            Ok(hours) => Some(hours),
            Err(error) => return bad_request(&format!("'{text}' is not a duration: {error}")),
        },
    };
    let answer = app
        .helper
        .call(Ask::Block {
            session: who.session.clone(),
            csrf: form.csrf,
            network: form.network,
            hours,
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=2").await
}

#[derive(Deserialize)]
struct BlockTargetForm {
    csrf: String,
    network: String,
}

async fn unblock(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<BlockTargetForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::Unblock {
            session: who.session.clone(),
            csrf: form.csrf,
            network: form.network,
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=3").await
}

async fn keep_block(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<BlockTargetForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::KeepBlock {
            session: who.session.clone(),
            csrf: form.csrf,
            network: form.network,
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=4").await
}

#[derive(Deserialize)]
struct MaxmindKeyForm {
    csrf: String,
    account: String,
    license: String,
}

/// Hands a MaxMind key to the helper, which downloads GeoLite2 with it and
/// keeps the key once MaxMind accepts it.
async fn set_maxmind_key(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<MaxmindKeyForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::SetMaxmindKey {
            session: who.session.clone(),
            csrf: form.csrf,
            account: form.account,
            license: form.license,
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=6").await
}

#[derive(Deserialize)]
struct MaxmindRemoveForm {
    csrf: String,
}

/// Removes the MaxMind key the panel keeps and its GeoLite2 copy.
async fn remove_maxmind_key(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<MaxmindRemoveForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RemoveMaxmindKey {
            session: who.session.clone(),
            csrf: form.csrf,
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=7").await
}

/// Saves the Countries card: the rule, which the form leaves out while the
/// environment sets it, and the countries kept and added, which it marks
/// with `list` unless the environment sets them.
async fn set_countries(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let mut csrf = String::new();
    let mut rule = None;
    let mut list = false;
    let mut countries = Vec::new();
    for (name, value) in form {
        match name.as_str() {
            "csrf" => csrf = value,
            "rule" => rule = Some(value),
            "list" => list = true,
            "country" => {
                if !value.is_empty() {
                    countries.push(value);
                }
            }
            other => {
                return bad_request(&format!("'{other}' is not a field of the country rules"));
            }
        }
    }
    let answer = app
        .helper
        .call(Ask::SetCountries {
            session: who.session.clone(),
            csrf,
            rule,
            countries: list.then_some(countries),
        })
        .await;
    block_answer(&app, &who, answer, "/bans?done=5").await
}

#[derive(Deserialize)]
struct LocationsForm {
    csrf: String,
    /// "on" or "off".
    on: String,
    refresh_hours: String,
}

/// Saves the Location checks card, for an owner. The form carries a value
/// the environment sets as it is, which the helper then keeps.
async fn set_locations(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<LocationsForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let on = match form.on.as_str() {
        "on" => true,
        "off" => false,
        other => return bad_request(&format!("'{other}' is not on or off")),
    };
    let answer = app
        .helper
        .call(Ask::SetLocationChecks {
            session: who.session.clone(),
            csrf: form.csrf,
            on,
            refresh_hours: form.refresh_hours,
        })
        .await;
    let done = if on { "/bans?done=8" } else { "/bans?done=9" };
    block_answer(&app, &who, answer, done).await
}

/// The page after a change to the blocklist: `done` when it was made, else
/// the Bans page with the reason.
async fn block_answer(
    app: &App,
    who: &Who,
    answer: Result<Answer, String>,
    done: &'static str,
) -> Response {
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            bans_view(app, who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a blocklist change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// How ocserv bans, as the Bans page explains it.
fn ban_policy(policy: &BanPolicy) -> String {
    let points = |count: u64| match count {
        1 => "1 point".to_owned(),
        count => format!("{count} points"),
    };
    if policy.max_score == 0 {
        return "Bans are off: the VPN server's max-ban-score is 0, so no address is ever banned."
            .to_owned();
    }
    format!(
        "An address is banned for {} when its points reach {}. A wrong password adds {} and \
         each connection {}; points start over after {}.",
        span(policy.ban_seconds),
        policy.max_score,
        points(policy.wrong_password_points),
        points(policy.connection_points),
        span(policy.reset_seconds),
    )
}

/// The bans, highest score first.
fn ban_rows(mut banned: Vec<Ban>) -> Vec<BanRow> {
    banned.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.address.cmp(&b.address))
    });
    banned
        .into_iter()
        .map(|ban| BanRow {
            time_left: match ban.lifts_in {
                Some(seconds) => span(seconds),
                None => "Not reported".to_owned(),
            },
            address: ban.address,
            score: ban.score,
        })
        .collect()
}

/// The addresses with points and no ban, most points first. ocserv keeps an
/// unbanned address at 0 points for a while, which is left out.
fn points_rows(points: &[BanPoints], banned: &[Ban], policy: &BanPolicy) -> Vec<PointsRow> {
    let mut rows: Vec<PointsRow> = points
        .iter()
        .filter(|entry| entry.score > 0)
        .filter(|entry| !banned.iter().any(|ban| ban.address == entry.address))
        .map(|entry| PointsRow {
            address: entry.address.clone(),
            score: entry.score,
            share: match policy.max_score {
                0 => 0,
                max => (entry.score.saturating_mul(100) / max).min(100),
            },
            label: format!(
                "{} of the {} points that ban an address",
                entry.score, policy.max_score
            ),
        })
        .collect();
    rows.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.address.cmp(&b.address))
    });
    rows
}

#[derive(Deserialize)]
struct UnbanForm {
    csrf: String,
    address: String,
}

async fn unban(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<UnbanForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::Unban {
            session: who.session.clone(),
            csrf: form.csrf,
            address: form.address,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/bans?done=1", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            bans_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a request to lift a ban with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The Sites page: the users and groups that publish networks, the rules
/// between VPN clients and those networks, and why the rules may not do
/// what they say.
#[derive(Template)]
#[template(path = "sites.html")]
struct SitesPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    notes: Vec<SiteNote>,
    sites: Vec<SiteRow>,
    /// The number of sites, with its noun.
    sites_count: String,
    rules: Vec<RuleRow>,
    /// The number of rules, with its noun.
    rules_count: String,
    /// Where a rule starts and where it leads, in the form that adds one.
    ends: Vec<EndPicker>,
    can_operate: bool,
    csrf: String,
    site_icon: &'static str,
    rule_icon: &'static str,
    warning_icon: &'static str,
}

/// A reason the rules may not do what they say.
struct SiteNote {
    class: &'static str,
    text: &'static str,
}

/// A user or group that publishes networks, as the Sites page lists it.
struct SiteRow {
    name: String,
    /// "VPN user" or "Group".
    kind: &'static str,
    /// The settings page that holds its networks.
    settings: String,
    networks: Vec<String>,
    connected: bool,
    egress: bool,
    /// Whether it is a user, whose egress the page can set.
    user: bool,
}

/// A rule as the Sites page lists it.
struct RuleRow {
    id: u64,
    from: String,
    to: String,
    /// Who added it and how long ago.
    added: String,
}

/// One end of the form that adds a rule, with the choice to show selected.
struct EndPicker {
    /// The form field's name: "from" or "to".
    name: &'static str,
    label: &'static str,
    /// Whether every VPN client is offered, as it is where a rule starts.
    clients: bool,
    clients_selected: bool,
    groups: Vec<EndChoice>,
    networks: Vec<EndChoice>,
    /// Whether another network, typed beside the list, is selected.
    other: bool,
    typed: String,
}

/// A choice in the list of a rule's end.
struct EndChoice {
    value: String,
    label: String,
    selected: bool,
}

#[derive(Deserialize)]
struct SitesQuery {
    done: Option<u8>,
}

async fn sites_page(
    State(app): State<App>,
    Query(query): Query<SitesQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = query.done.map(|done| {
        Notice::done(match done {
            2 => {
                "Removed the rule. The firewall refuses the new connections it let through; \
                 open ones last until they end."
            }
            3 => "Turned on: the site's networks reach beyond the VPN.",
            4 => "Turned off: the site's networks stay inside the VPN.",
            _ => "Added the rule. The firewall lets its new connections through from now on.",
        })
    });
    sites_view(&app, &who, notice, None).await
}

/// The Sites page, with `kept`, a refused rule form, filled in again.
async fn sites_view(
    app: &App,
    who: &Who,
    notice: Option<Notice>,
    kept: Option<&SiteRuleForm>,
) -> Response {
    let answer = app
        .helper
        .call(Ask::SiteRules {
            session: who.session.clone(),
        })
        .await;
    let view = match answer {
        Ok(Answer::SiteRules { view }) => view,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a site rules request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    let count = |number: usize, noun: &str| match number {
        1 => format!("1 {noun}"),
        number => format!("{number} {noun}s"),
    };
    html(&SitesPage {
        title: "Sites - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/sites"),
        notice,
        notes: site_notes(&view),
        sites_count: count(view.sites.len(), "site"),
        rules_count: count(view.rules.len(), "rule"),
        rules: view
            .rules
            .iter()
            .map(|rule| RuleRow {
                id: rule.id,
                from: end_text(&rule.from, &view.sites),
                to: end_text(&rule.to, &view.sites),
                added: format!(
                    "By {}, {} ago",
                    rule.by,
                    span(now.saturating_sub(rule.created))
                ),
            })
            .collect(),
        ends: end_pickers(&view, kept),
        sites: view
            .sites
            .iter()
            .map(|site| SiteRow {
                name: site.name.clone(),
                kind: match site.owner {
                    Owner::User => "VPN user",
                    Owner::Group => "Group",
                },
                settings: match site.owner {
                    Owner::User => format!("/users/{}/settings", site.name),
                    Owner::Group => format!("/groups/{}", site.name),
                },
                networks: site.networks.clone(),
                connected: site.connected,
                egress: site.egress,
                user: site.owner == Owner::User,
            })
            .collect(),
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        site_icon: icons::TREE_STRUCTURE,
        rule_icon: icons::SHIELD_STAR,
        warning_icon: icons::WARNING,
    })
}

/// Why the rules on the Sites page may not do what they say.
fn site_notes(view: &SitesView) -> Vec<SiteNote> {
    let mut notes = Vec::new();
    if !view.checked {
        notes.push(SiteNote {
            class: "callout-bad",
            text: "This kernel cannot check where tunnel traffic comes from, so a VPN client \
                   could send as another, and no rule here opens anything.",
        });
    }
    if view.iptables {
        notes.push(SiteNote {
            class: "callout-warn",
            text: "The firewall is legacy iptables, which carries out the rules between \
                   networks only, so a rule cannot name a group.",
        });
    }
    if view.client_to_client {
        notes.push(SiteNote {
            class: "callout-warn",
            text: "CLIENT_TO_CLIENT is on, so every VPN client reaches every other and every \
                   site's networks, whatever the rules say.",
        });
    }
    if view.split {
        notes.push(SiteNote {
            class: "callout-warn",
            text: "Clients send only the networks the server routes to them through the \
                   tunnel, so a site's networks are reached only by the users and groups whose \
                   routes include them.",
        });
    }
    notes
}

/// A rule's end as the Sites page names it, with the site behind a
/// published network.
fn end_text(end: &End, sites: &[Site]) -> String {
    let End::Network(network) = end else {
        return capitalized(&end.describe());
    };
    let text = network.to_string();
    match sites.iter().find(|site| site.networks.contains(&text)) {
        Some(site) => format!("{text} behind {}", site.name),
        None => text,
    }
}

/// The two ends of the rule form: groups only where the firewall can follow
/// them, each site's networks, and another network typed beside the list.
/// `kept`, a refused form, is shown as it was sent; otherwise a rule starts
/// at every VPN client and leads to the first network or group.
fn end_pickers(view: &SitesView, kept: Option<&SiteRuleForm>) -> Vec<EndPicker> {
    let groups: &[String] = if view.iptables { &[] } else { &view.groups };
    let networks: Vec<(String, String)> = view
        .sites
        .iter()
        .flat_map(|site| {
            site.networks
                .iter()
                .map(move |network| (network.clone(), format!("{network} behind {}", site.name)))
        })
        .collect();
    let first = match (networks.first(), groups.first()) {
        (Some((network, _label)), _group) => format!("network:{network}"),
        (None, Some(group)) => format!("group:{group}"),
        (None, None) => "other".to_owned(),
    };
    let (from, from_typed, to, to_typed) = match kept {
        Some(form) => (
            form.from.as_str(),
            form.from_network.as_str(),
            form.to.as_str(),
            form.to_network.as_str(),
        ),
        None => ("clients", "", first.as_str(), ""),
    };
    let picker = |name, label, chosen: &str, typed: &str, clients| EndPicker {
        name,
        label,
        clients,
        clients_selected: clients && chosen == "clients",
        groups: groups
            .iter()
            .map(|group| {
                let value = format!("group:{group}");
                EndChoice {
                    selected: value == chosen,
                    label: group.clone(),
                    value,
                }
            })
            .collect(),
        networks: networks
            .iter()
            .map(|(network, label)| {
                let value = format!("network:{network}");
                EndChoice {
                    selected: value == chosen,
                    label: label.clone(),
                    value,
                }
            })
            .collect(),
        other: chosen == "other",
        typed: typed.to_owned(),
    };
    vec![
        picker("from", "From", from, from_typed, true),
        picker("to", "To", to, to_typed, false),
    ]
}

/// The rule end a form names: "clients"; "group:" with a group's name;
/// "network:" with a network; or "other" with the network typed beside the
/// list, whose label is `field`.
fn chosen_end(choice: &str, typed: &str, field: &str) -> Result<End, String> {
    let typed = typed.trim();
    if choice == "other" {
        if typed.is_empty() {
            return Err(format!(
                "{field} is set to another network, but no network is typed"
            ));
        }
        return Network::parse(typed).map(End::Network);
    }
    if !typed.is_empty() {
        return Err(format!(
            "a network is typed for {field}, but {field} is not set to another network"
        ));
    }
    let unknown = || Err(format!("'{choice}' is not a choice for {field}"));
    match choice.split_once(':') {
        Some(("group", name)) => Ok(End::Group(name.to_owned())),
        Some(("network", text)) => Network::parse(text).map(End::Network),
        Some(_kind) => unknown(),
        None if choice == "clients" => Ok(End::Clients),
        None => unknown(),
    }
}

#[derive(Deserialize)]
struct SiteRuleForm {
    csrf: String,
    from: String,
    #[serde(default)]
    from_network: String,
    to: String,
    #[serde(default)]
    to_network: String,
}

async fn add_site_rule(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<SiteRuleForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let ends = chosen_end(&form.from, &form.from_network, "From")
        .and_then(|from| chosen_end(&form.to, &form.to_network, "To").map(|to| (from, to)));
    let (from, to) = match ends {
        Ok(ends) => ends,
        Err(message) => {
            let notice = Notice::refused(sentence(&message));
            return sites_view(&app, &who, Some(notice), Some(&form)).await;
        }
    };
    let answer = app
        .helper
        .call(Ask::AddSiteRule {
            session: who.session.clone(),
            csrf: form.csrf.clone(),
            from,
            to,
        })
        .await;
    site_answer(&app, &who, answer, "/sites?done=1", Some(&form)).await
}

#[derive(Deserialize)]
struct SiteRuleRemoveForm {
    csrf: String,
    id: u64,
}

async fn remove_site_rule(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<SiteRuleRemoveForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RemoveSiteRule {
            session: who.session.clone(),
            csrf: form.csrf,
            id: form.id,
        })
        .await;
    site_answer(&app, &who, answer, "/sites?done=2", None).await
}

#[derive(Deserialize)]
struct SiteEgressForm {
    csrf: String,
    user: String,
    /// "on" or "off".
    on: String,
}

async fn set_site_egress(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<SiteEgressForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let (on, done) = match form.on.as_str() {
        "on" => (true, "/sites?done=3"),
        "off" => (false, "/sites?done=4"),
        other => return bad_request(&format!("'{other}' is neither on nor off")),
    };
    let answer = app
        .helper
        .call(Ask::SetSiteEgress {
            session: who.session.clone(),
            csrf: form.csrf,
            user: form.user,
            on,
        })
        .await;
    site_answer(&app, &who, answer, done, None).await
}

/// The page after a change on the Sites page: `done` once it is made, or
/// the Sites page again with why it was refused or failed, and with `kept`,
/// the rule form as it was sent.
async fn site_answer(
    app: &App,
    who: &Who,
    answer: Result<Answer, String>,
    done: &'static str,
    kept: Option<&SiteRuleForm>,
) -> Response {
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message } | Answer::Error { message }) => {
            sites_view(app, who, Some(Notice::refused(sentence(&message))), kept).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a site-to-site change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// An event as the Live events page, the dashboard and the page's script
/// show it.
#[derive(Serialize)]
struct EventRow {
    number: u64,
    /// "connection", "failure", "ban" or "location", which the page filters
    /// by.
    kind: &'static str,
    /// The icon's tone class.
    tone: &'static str,
    icon: &'static str,
    text: String,
    /// The details under the text; empty when there are none.
    meta: String,
    /// When it happened, as an RFC 3339 UTC timestamp.
    stamp: String,
    /// The time of day in UTC, hh:mm:ss, which the page's script replaces
    /// with the browser's local time.
    clock: String,
    /// The country of the address the event names.
    place: Option<RowPlace>,
}

/// A country as a row shows it: its flag and its name.
#[derive(Serialize)]
struct RowPlace {
    flag: String,
    name: String,
}

/// The countries an answer placed addresses in and whose data placed them,
/// or why it placed none when the helper has no country database.
struct Places {
    known: Vec<Place>,
    /// Whose data names the countries: "dbip", "maxmind" or empty.
    credit: &'static str,
    problem: Option<String>,
}

impl Places {
    fn of(answer: Result<Located, String>) -> Places {
        match answer {
            Ok(located) => Places {
                credit: credit_of(&located.database),
                known: located.places,
                problem: None,
            },
            Err(problem) => Places {
                known: Vec::new(),
                credit: "",
                problem: Some(problem),
            },
        }
    }

    /// No countries, for a page that does not show them.
    fn none() -> Places {
        Places {
            known: Vec::new(),
            credit: "",
            problem: None,
        }
    }

    /// The country of `address`, with its flag.
    fn of_address(&self, address: &str, assets: &Assets) -> Option<RowPlace> {
        self.known
            .iter()
            .find(|place| place.address == address)
            .map(|place| RowPlace {
                flag: assets.flag(&place.code),
                name: place.name.clone(),
            })
    }

    /// Why the page shows no countries, as a sentence.
    fn note(&self) -> Option<String> {
        self.problem.as_ref().map(|problem| {
            format!("Countries are not shown: no country database could be read: {problem}.")
        })
    }
}

/// Whose data a country database of the type `database` holds, which a
/// page showing countries credits: "maxmind" for GeoLite2, else "dbip".
fn credit_of(database: &str) -> &'static str {
    if database.starts_with("GeoLite2") {
        "maxmind"
    } else {
        "dbip"
    }
}

/// A text with its first letter capitalized.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn event_row(logged: &Logged, places: &Places, assets: &Assets) -> EventRow {
    let of_day = logged.event.time % 86_400;
    let address = match &logged.event.what {
        What::Connected { from, .. }
        | What::Disconnected { from, .. }
        | What::SignInFailed { from, .. }
        | What::LocationUnchecked { from, .. } => from.as_deref(),
        What::Banned { address, .. } => Some(address.as_str()),
        What::LocationRefused { from, .. } | What::LocationFlagged { from, .. } => {
            Some(from.as_str())
        }
    };
    let (kind, tone, icon, text, details) = match &logged.event.what {
        What::Connected {
            user,
            group,
            session,
            from,
            vpn_ipv4,
            vpn_ipv6,
            client,
        } => {
            let vpn: Vec<&str> = [vpn_ipv4, vpn_ipv6]
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            let mut details = Vec::new();
            if let Some(client) = client {
                details.push(format!("using {client}"));
            }
            if !vpn.is_empty() {
                details.push(format!("with the VPN address {}", vpn.join(" and ")));
            }
            if let Some(group) = group {
                details.push(format!("in group {group}"));
            }
            if let Some(session) = session {
                details.push(format!("session {session}"));
            }
            let text = match from {
                Some(from) => format!("{user} connected from {from}"),
                None => format!("{user} connected"),
            };
            ("connection", "ev-ok", icons::PLUGS, text, details)
        }
        What::Disconnected {
            user,
            session,
            from,
            seconds,
            received,
            sent,
        } => {
            let mut details = Vec::new();
            if let Some(received) = received {
                details.push(format!("received {}", units::amount(*received)));
            }
            if let Some(sent) = sent {
                details.push(format!("sent {}", units::amount(*sent)));
            }
            if let Some(from) = from {
                details.push(format!("connected from {from}"));
            }
            if let Some(session) = session {
                details.push(format!("session {session}"));
            }
            let text = match seconds {
                Some(seconds) => format!("{user} disconnected after {}", span(*seconds)),
                None => format!("{user} disconnected"),
            };
            ("connection", "ev-mute", icons::SIGN_OUT, text, details)
        }
        What::SignInFailed { user, from } => {
            let who = if user.is_empty() {
                "A sign-in without a user name".to_owned()
            } else {
                format!("A sign-in as {user}")
            };
            let text = match &logged.reason {
                Some(reason) => format!("{who} was refused: {reason}"),
                None => format!("{who} was refused"),
            };
            let details = from.iter().map(|from| format!("from {from}")).collect();
            ("failure", "ev-warn", icons::WARNING, text, details)
        }
        What::Banned { address, score } => (
            "ban",
            "ev-bad",
            icons::PROHIBIT,
            format!("Banned {address}"),
            vec![format!(
                "its points from wrong passwords and connections reached {score}"
            )],
        ),
        What::LocationRefused {
            user,
            from,
            score,
            reasons,
        } => (
            "location",
            "ev-bad",
            icons::MAP_PIN,
            format!(
                "Refused {user}'s sign-in from {from}, which does not fit where this account \
                 signs in"
            ),
            vec![format!("scored {score} of 100: {}", reasons.join("; "))],
        ),
        What::LocationFlagged {
            user,
            from,
            score,
            reasons,
        } => (
            "location",
            "ev-warn",
            icons::MAP_PIN,
            format!("{user} signed in from {from}, which is unusual for this account"),
            vec![format!("scored {score} of 100: {}", reasons.join("; "))],
        ),
        What::LocationUnchecked {
            user,
            from,
            problem,
        } => (
            "location",
            "ev-warn",
            icons::WARNING,
            match from {
                Some(from) => format!("{user} signed in from {from} without a location check"),
                None => format!("{user} signed in without a location check"),
            },
            vec![format!("the check could not run: {problem}")],
        ),
    };
    EventRow {
        number: logged.number,
        kind,
        tone,
        icon,
        text,
        meta: capitalized(&details.join(", ")),
        stamp: clock::rfc3339(logged.event.time),
        clock: format!(
            "{:02}:{:02}:{:02}",
            of_day / 3600,
            of_day % 3600 / 60,
            of_day % 60
        ),
        place: address.and_then(|address| places.of_address(address, assets)),
    }
}

/// The kinds of event the Live events page can show alone.
const EVENT_FILTERS: [(&str, &str); 5] = [
    ("all", "All"),
    ("connection", "Connections"),
    ("failure", "Failed sign-ins"),
    ("ban", "Bans"),
    ("location", "Location checks"),
];

#[derive(Template)]
#[template(path = "events.html")]
struct EventsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    filter: &'static str,
    filters: Vec<EventFilter>,
    /// Newest first.
    rows: Vec<EventRow>,
    /// The number of the newest event, from which the page's script asks
    /// for more.
    last: u64,
    /// How long events are kept, in words.
    kept: String,
    /// Why the events show no countries, and whose data names them.
    countries_note: Option<String>,
    country_credit: &'static str,
}

struct EventFilter {
    label: &'static str,
    href: String,
    current: bool,
}

#[derive(Deserialize)]
struct EventsQuery {
    kind: Option<String>,
}

async fn events_page(
    State(app): State<App>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let filter = match EVENT_FILTERS
        .iter()
        .find(|(kind, _)| query.kind.as_deref() == Some(kind))
    {
        Some((kind, _)) => *kind,
        None => "all",
    };
    let answer = app
        .helper
        .call(Ask::ListEvents {
            session: who.session.clone(),
            after: None,
        })
        .await;
    let (events, keep_hours, places) = match answer {
        Ok(Answer::Events {
            events,
            hours,
            places,
        }) => (events, hours, Places::of(places)),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered an event list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let last = events.last().map_or(0, |logged| logged.number);
    let rows = events
        .iter()
        .rev()
        .map(|logged| event_row(logged, &places, &app.assets))
        .filter(|row| filter == "all" || row.kind == filter)
        .collect();
    html(&EventsPage {
        title: "Live events - OpenConnect admin",
        page: app.links(),
        shell: shell(&app, &who, "/events"),
        filter,
        filters: EVENT_FILTERS
            .iter()
            .map(|(kind, label)| EventFilter {
                label,
                href: match *kind {
                    "all" => "/events".to_owned(),
                    kind => format!("/events?kind={kind}"),
                },
                current: *kind == filter,
            })
            .collect(),
        rows,
        last,
        kept: span(keep_hours.saturating_mul(3600)),
        countries_note: places.note(),
        country_credit: places.credit,
    })
}

#[derive(Deserialize)]
struct EventsAfter {
    after: Option<u64>,
}

/// The live events after `after`, oldest first, as the rows the page shows,
/// for its script.
async fn events_json(
    State(app): State<App>,
    Query(query): Query<EventsAfter>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) if who.landing() == "/" => who,
        Ok(Some(_) | None) => {
            return plain(StatusCode::UNAUTHORIZED, "Sign in to see the events.");
        }
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::ListEvents {
            session: who.session.clone(),
            after: query.after,
        })
        .await;
    let (events, places) = match answer {
        Ok(Answer::Events { events, places, .. }) => (events, Places::of(places)),
        Ok(Answer::Denied) => {
            return plain(StatusCode::UNAUTHORIZED, "Sign in to see the events.");
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered an event list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let rows: Vec<EventRow> = events
        .iter()
        .map(|logged| event_row(logged, &places, &app.assets))
        .collect();
    match serde_json::to_string(&rows) {
        Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Err(error) => failure(&format!("the events could not be written as JSON: {error}")),
    }
}

/// Routes in words: "every network" for the default route or none.
fn routes_text(routes: &[String]) -> String {
    if routes.is_empty() || routes.iter().any(|route| route == "default") {
        "every network".to_owned()
    } else {
        routes.join(", ")
    }
}

/// Download and upload limits with their unit: "Down 50 Mbps, up 10 Mbps".
fn bandwidth_text(download: Option<u64>, upload: Option<u64>) -> String {
    match (download, upload) {
        (None, None) => "No limit".to_owned(),
        (Some(down), Some(up)) => {
            format!("Down {}, up {}", overrides::rate(down), overrides::rate(up))
        }
        (Some(down), None) => format!("Down {}; no upload limit", overrides::rate(down)),
        (None, Some(up)) => format!("Up {}; no download limit", overrides::rate(up)),
    }
}

/// A limit in words.
fn limit_text(limit: Option<u64>) -> String {
    match limit {
        Some(bytes) => overrides::rate(bytes),
        None => "no limit".to_owned(),
    }
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    cards: Vec<GroupCard>,
    can_operate: bool,
    csrf: String,
    readable: bool,
    group_icon: &'static str,
}

/// A group as the Groups page shows it.
struct GroupCard {
    name: String,
    members: String,
    own: bool,
    tunnel: String,
    dns: String,
    bandwidth: String,
    restricted: &'static str,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    /// Newest first.
    rows: Vec<AuditRow>,
    /// The link to the newest entries, when this page shows older ones.
    newer: Option<&'static str>,
    /// The link to the next older entries, if there are any.
    older: Option<String>,
}

/// An audit log line as the Audit log page shows it.
struct AuditRow {
    /// RFC 3339 UTC, for the page's script.
    stamp: String,
    /// The date and time in UTC, for a browser without the script.
    clock: String,
    /// Shortened to the longest name an account can have.
    actor: String,
    /// How long the name was, when it is shortened.
    actor_note: Option<String>,
    from: String,
    action: String,
    result: &'static str,
    result_class: &'static str,
    detail: String,
}

#[derive(Deserialize)]
struct AuditQuery {
    before: Option<usize>,
}

/// The Audit log page: a page of the helper's audit log, newest first, for
/// owners.
async fn audit_page(
    State(app): State<App>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let answer = app
        .helper
        .call(Ask::ListAudit {
            session: who.session.clone(),
            before: query.before,
        })
        .await;
    let (records, older) = match answer {
        Ok(Answer::Audit { records, older }) => (records, older),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return plain(StatusCode::FORBIDDEN, &sentence(&message));
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered an audit log request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    html(&AuditPage {
        title: "Audit log - OpenConnect admin",
        page: app.links(),
        shell: shell(&app, &who, "/audit"),
        rows: records.into_iter().map(audit_row).collect(),
        newer: query.before.map(|_| "/audit"),
        older: older.map(|before| format!("/audit?before={before}")),
    })
}

fn audit_row(record: Record) -> AuditRow {
    let (result, result_class) = match record.result {
        Outcome::Allowed => ("Allowed", "pill-ok"),
        Outcome::Denied => ("Denied", "pill-bad"),
    };
    let length = record.actor.chars().count();
    let (actor, actor_note) = if length > store::MAX_NAME_LEN {
        let start: String = record.actor.chars().take(store::MAX_NAME_LEN).collect();
        (
            format!("{start}\u{2026}"),
            Some(format!("Shortened from {length} characters")),
        )
    } else {
        (record.actor, None)
    };
    AuditRow {
        clock: utc_text(&record.time),
        stamp: record.time,
        actor,
        actor_note,
        from: record.from,
        action: record.action,
        result,
        result_class,
        detail: capitalized(&record.detail),
    }
}

/// An RFC 3339 UTC time as a page shows it before its script runs.
fn utc_text(rfc3339: &str) -> String {
    rfc3339
        .replacen('T', " ", 1)
        .trim_end_matches('Z')
        .to_owned()
}

/// A time on a page: RFC 3339 for the page's script, which shows it in the
/// browser's time zone, and the date and time in UTC until it runs.
struct Stamp {
    iso: String,
    text: String,
}

fn stamp(time: u64) -> Stamp {
    let iso = clock::rfc3339(time);
    Stamp {
        text: utc_text(&iso),
        iso,
    }
}

#[derive(Template)]
#[template(path = "admins.html")]
struct AdminsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    summary: String,
    notice: Option<Notice>,
    /// The one-time password a change set, shown once.
    handover: Option<Handover>,
    rows: Vec<AdminRow>,
    roles: &'static [RoleOption],
    csrf: String,
    warning_icon: &'static str,
    copy_icon: &'static str,
    /// Whether the location checks are on, which the vacation action
    /// needs, and the first and last day a vacation may end on.
    locations_on: bool,
    vacation_from: String,
    vacation_to: String,
}

struct Handover {
    name: String,
    password: String,
}

struct RoleOption {
    value: &'static str,
    label: &'static str,
}

/// The roles in the order the Admins page offers them, least first.
const ROLE_OPTIONS: [RoleOption; 3] = [
    RoleOption {
        value: "viewer",
        label: "Viewer",
    },
    RoleOption {
        value: "operator",
        label: "Operator",
    },
    RoleOption {
        value: "owner",
        label: "Owner",
    },
];

fn role_value(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
    }
}

fn role_of(value: &str) -> Option<Role> {
    match value {
        "owner" => Some(Role::Owner),
        "operator" => Some(Role::Operator),
        "viewer" => Some(Role::Viewer),
        _ => None,
    }
}

/// An admin as the Admins page shows it.
struct AdminRow {
    name: String,
    initials: String,
    /// Whether this is the signed-in admin, whose account only another
    /// owner changes.
    is_self: bool,
    role: &'static str,
    role_value: &'static str,
    status: &'static str,
    status_class: &'static str,
    status_note: Option<String>,
    locked: bool,
    second_factor: bool,
    /// The admin's second factors in words: "App", "2 passkeys", "App and
    /// 1 passkey".
    factors: String,
    added: Stamp,
    last_login: Option<Stamp>,
    /// The last day of the admin's vacation, while it lasts.
    vacation: Option<String>,
}

/// An admin's second factors in words, for the Admins page.
fn factors_text(app: bool, passkeys: usize) -> String {
    let keys = match passkeys {
        1 => "1 passkey".to_owned(),
        count => format!("{count} passkeys"),
    };
    match (app, passkeys) {
        (true, 0) => "App".to_owned(),
        (true, _) => format!("App and {keys}"),
        (false, 0) => "None".to_owned(),
        (false, _) => keys,
    }
}

fn admin_row(admin: AdminSummary, me: &str, now: u64) -> AdminRow {
    let (status, status_class, status_note) = match admin.locked_until {
        Some(until) => (
            "Locked",
            "pill-bad",
            Some(format!("Lifts in {}", span(until.saturating_sub(now)))),
        ),
        None if admin.must_change_password => (
            "One-time password",
            "pill-warn",
            Some("Not replaced yet".to_owned()),
        ),
        None => ("Active", "pill-ok", None),
    };
    AdminRow {
        initials: admin
            .name
            .chars()
            .take(2)
            .collect::<String>()
            .to_uppercase(),
        is_self: admin.name == me,
        role: role_name(admin.role),
        role_value: role_value(admin.role),
        status,
        status_class,
        status_note,
        locked: admin.locked_until.is_some(),
        second_factor: admin.second_factor,
        factors: factors_text(admin.authenticator_app, admin.passkeys),
        added: stamp(admin.created),
        last_login: admin.last_login.map(stamp),
        vacation: admin.vacation_until.map(vacation_last_day),
        name: admin.name,
    }
}

/// How many admins of each role there are, in words.
fn admins_summary(admins: &[AdminSummary]) -> String {
    let counted: Vec<String> = [Role::Owner, Role::Operator, Role::Viewer]
        .into_iter()
        .filter_map(|role| {
            let word = role_value(role);
            match admins.iter().filter(|admin| admin.role == role).count() {
                0 => None,
                1 => Some(format!("1 {word}")),
                count => Some(format!("{count} {word}s")),
            }
        })
        .collect();
    match counted.split_last() {
        None => "No admins".to_owned(),
        Some((last, [])) => capitalized(last),
        Some((last, rest)) => capitalized(&format!("{} and {last}", rest.join(", "))),
    }
}

#[derive(Deserialize)]
struct AdminsQuery {
    done: Option<String>,
}

async fn admins_page(
    State(app): State<App>,
    Query(query): Query<AdminsQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("role") => Some(Notice::done(
            "Changed the role. It applies from the admin's next click.",
        )),
        Some("second_factor") => Some(Notice::done(
            "Removed the admin's authenticator app and passkeys and ended their sessions. Their \
             password alone now opens a session that can only set up a new second factor.",
        )),
        Some("unlock") => Some(Notice::done("Unlocked the admin.")),
        Some("remove") => Some(Notice::done("Removed the admin and ended their sessions.")),
        Some("vacation") => Some(Notice::done("Saved the vacation.")),
        Some(_) | None => None,
    };
    admins_view(&app, &who, notice, None).await
}

/// The Admins page: every admin account, with the changes an owner can
/// make to each other one.
async fn admins_view(
    app: &App,
    who: &Who,
    notice: Option<Notice>,
    handover: Option<Handover>,
) -> Response {
    let answer = app
        .helper
        .call(Ask::ListAdmins {
            session: who.session.clone(),
        })
        .await;
    let (admins, locations_on) = match answer {
        Ok(Answer::Admins {
            admins,
            locations_on,
        }) => (admins, locations_on),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return plain(StatusCode::FORBIDDEN, &sentence(&message));
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered an admin list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    let (vacation_from, vacation_to) = vacation_range(now);
    html(&AdminsPage {
        title: "Admins - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/admins"),
        summary: admins_summary(&admins),
        notice,
        handover,
        rows: admins
            .into_iter()
            .map(|admin| admin_row(admin, &who.name, now))
            .collect(),
        roles: &ROLE_OPTIONS,
        csrf: who.csrf.clone(),
        warning_icon: icons::WARNING,
        copy_icon: icons::COPY,
        locations_on,
        vacation_from,
        vacation_to,
    })
}

#[derive(Deserialize)]
struct AdminForm {
    csrf: String,
    change: String,
    name: String,
    #[serde(default)]
    role: String,
}

async fn change_admin(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<AdminForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let AdminForm {
        csrf,
        change,
        name,
        role,
    } = form;
    let target = name.to_ascii_lowercase();
    let (change, done) = match (change.as_str(), role_of(&role)) {
        ("add", Some(role)) => (AdminChange::Add { name, role }, "/admins"),
        ("role", Some(role)) => (AdminChange::SetRole { name, role }, "/admins?done=role"),
        ("add" | "role", None) => return bad_request(&format!("'{role}' is not a role")),
        ("password", _) => (AdminChange::ResetPassword { name }, "/admins"),
        ("second_factor", _) => (
            AdminChange::ResetSecondFactor { name },
            "/admins?done=second_factor",
        ),
        ("unlock", _) => (AdminChange::Unlock { name }, "/admins?done=unlock"),
        ("remove", _) => (AdminChange::Remove { name }, "/admins?done=remove"),
        (other, _) => return bad_request(&format!("'{other}' is not a change to an admin")),
    };
    let added = matches!(change, AdminChange::Add { .. });
    let answer = app
        .helper
        .call(Ask::ChangeAdmin {
            session: who.session.clone(),
            csrf,
            change,
        })
        .await;
    match answer {
        Ok(Answer::AdminChanged {
            one_time_password: Some(password),
        }) => {
            let notice = Notice::done(&if added {
                format!("Added {target}.")
            } else {
                format!("Replaced {target}'s password and ended their sessions.")
            });
            let handover = Handover {
                name: target,
                password: password.0,
            };
            admins_view(&app, &who, Some(notice), Some(handover)).await
        }
        Ok(Answer::AdminChanged {
            one_time_password: None,
        }) => see_other(done, &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            admins_view(&app, &who, Some(Notice::refused(sentence(&message))), None).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a change to an admin with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Template)]
#[template(path = "certificates.html")]
struct CertificatesPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    cards: Vec<CertificateCard>,
    icon: &'static str,
    /// The VPN users' client certificates, newest first.
    clients: Vec<ClientRow>,
    /// The VPN users a certificate can be issued for; none for a viewer.
    users: Vec<String>,
    /// The validity of a new certificate, in days.
    days: u64,
    can_operate: bool,
    csrf: String,
}

/// A VPN user's client certificate as the Certificates page lists it.
struct ClientRow {
    serial: String,
    /// The first eight digits of the serial number, enough to tell the
    /// certificates on the page apart.
    serial_short: String,
    user: String,
    groups: String,
    key: &'static str,
    until: Stamp,
    state: String,
    state_class: &'static str,
    /// Whether it still signs in, so that it can be renewed or revoked.
    active: bool,
}

fn client_row(certificate: ClientCertificate, now: u64) -> ClientRow {
    let days = |seconds: u64| match seconds / 86_400 {
        1 => "1 day".to_owned(),
        count => format!("{count} days"),
    };
    let (state, state_class) = match &certificate.revoked {
        Some(revocation) => (format!("Revoked by {}", revocation.by), "pill-bad"),
        None if certificate.not_after <= now => ("Expired".to_owned(), "pill-bad"),
        None if certificate.not_after - now <= EXPIRY_WARNING_DAYS * 86_400 => (
            format!("Expires in {}", days(certificate.not_after - now)),
            "pill-warn",
        ),
        None => ("Valid".to_owned(), "pill-ok"),
    };
    ClientRow {
        serial_short: certificate.serial.chars().take(8).collect(),
        user: certificate.user,
        groups: certificate.groups.join(", "),
        key: match certificate.method {
            KeyOrigin::KeyFile => "Key file",
            KeyOrigin::Request => "Signing request",
        },
        until: stamp(certificate.not_after),
        active: certificate.revoked.is_none() && now < certificate.not_after,
        state,
        state_class,
        serial: certificate.serial,
    }
}

#[derive(Template)]
#[template(path = "certificate_issued.html")]
struct CertificateIssuedPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    user: String,
    serial: String,
    until: Stamp,
    /// The URL a client opens and the server key's pin.
    url: String,
    pin: String,
    /// The certificate in PEM, in base64 for its download link.
    certificate_base64: String,
    key_file: Option<KeyFileView>,
    copy_icon: &'static str,
}

/// A key file as the page that hands it out once shows it; both are wiped
/// when the page is dropped.
struct KeyFileView {
    p12_base64: String,
    passphrase: String,
    encryption: &'static str,
}

impl Drop for KeyFileView {
    fn drop(&mut self) {
        self.p12_base64.zeroize();
        self.passphrase.zeroize();
    }
}

/// The encryption a key file form field names.
fn cipher_of(text: &str) -> Option<Cipher> {
    match text {
        "aes256" => Some(Cipher::Aes256),
        "triple_des" => Some(Cipher::TripleDes),
        _ => None,
    }
}

/// A certificate as the Certificates page shows it.
struct CertificateCard {
    role: String,
    path: String,
    subject: String,
    issuer: String,
    names: String,
    from: Option<Stamp>,
    until: Option<Stamp>,
    /// How long until it expires, or since it did, and the pill's class.
    left: Option<String>,
    left_class: &'static str,
    pin: Option<String>,
    problem: Option<String>,
}

/// Days before expiry from which the Certificates page warns.
const EXPIRY_WARNING_DAYS: u64 = 30;

fn certificate_card(entry: CertificateEntry, now: u64) -> CertificateCard {
    let days = |seconds: u64| match seconds / 86_400 {
        1 => "1 day".to_owned(),
        count => format!("{count} days"),
    };
    let mut card = CertificateCard {
        role: entry.role,
        path: entry.path,
        subject: String::new(),
        issuer: String::new(),
        names: String::new(),
        from: None,
        until: None,
        left: None,
        left_class: "pill-ok",
        pin: None,
        problem: entry
            .problem
            .map(|problem| sentence(&format!("this certificate could not be read: {problem}"))),
    };
    if let Some(facts) = entry.facts {
        let (left, class) = if facts.not_after <= now {
            (
                format!("Expired {} ago", days(now - facts.not_after)),
                "pill-bad",
            )
        } else if facts.not_after - now <= EXPIRY_WARNING_DAYS * 86_400 {
            (
                format!("Expires in {}", days(facts.not_after - now)),
                "pill-warn",
            )
        } else {
            (
                format!("Expires in {}", days(facts.not_after - now)),
                "pill-ok",
            )
        };
        card.left = Some(left);
        card.left_class = class;
        card.pin = (card.role == "VPN server").then_some(facts.pin);
        card.subject = facts.subject;
        card.issuer = facts.issuer;
        card.names = facts.names.join(", ");
        card.from = Some(stamp(facts.not_before));
        card.until = Some(stamp(facts.not_after));
    }
    card
}

#[derive(Deserialize)]
struct CertificatesQuery {
    done: Option<String>,
}

async fn certificates_page(
    State(app): State<App>,
    Query(query): Query<CertificatesQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("revoked") => Some(Notice::done(
            "The certificate is revoked, and its user's VPN sessions have ended.",
        )),
        Some(_) | None => None,
    };
    certificates_view(&app, &who, notice).await
}

/// The Certificates page: the server's and the panel's certificates, then
/// the VPN users' client certificates with the form that issues one.
async fn certificates_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::Certificates {
            session: who.session.clone(),
        })
        .await;
    let certificates = match answer {
        Ok(Answer::Certificates { certificates }) => certificates,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a certificates request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::ClientCertificates {
            session: who.session.clone(),
        })
        .await;
    let (clients, days) = match answer {
        Ok(Answer::ClientCertificates { certificates, days }) => (certificates, days),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a client certificates request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let can_operate = !matches!(who.role, Role::Viewer);
    let users = if can_operate {
        let answer = app
            .helper
            .call(Ask::ListVpnUsers {
                session: who.session.clone(),
            })
            .await;
        match answer {
            Ok(Answer::VpnUsers { users, .. }) => users.into_iter().map(|user| user.name).collect(),
            Ok(Answer::Denied) => return see_other("/login", &[]),
            Ok(other) => {
                return failure(&format!(
                    "the helper answered a VPN user list request with {other:?}"
                ));
            }
            Err(error) => return failure(&error),
        }
    } else {
        Vec::new()
    };
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    html(&CertificatesPage {
        title: "Certificates - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/certificates"),
        notice,
        cards: certificates
            .into_iter()
            .map(|entry| certificate_card(entry, now))
            .collect(),
        icon: icons::CERTIFICATE,
        clients: clients
            .into_iter()
            .map(|certificate| client_row(certificate, now))
            .collect(),
        users,
        days,
        can_operate,
        csrf: who.csrf.clone(),
    })
}

#[derive(Deserialize)]
struct IssueForm {
    csrf: String,
    user: String,
    how: String,
    cipher: String,
    #[serde(default)]
    request: String,
}

async fn issue_certificate(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<IssueForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let Some(cipher) = cipher_of(&form.cipher) else {
        return bad_request(&format!("'{}' is not a key file encryption", form.cipher));
    };
    let how = match form.how.as_str() {
        "key_file" => IssueHow::KeyFile { cipher },
        "request" => IssueHow::Request { pem: form.request },
        other => return bad_request(&format!("'{other}' is not a way to issue a certificate")),
    };
    let answer = app
        .helper
        .call(Ask::IssueClientCertificate {
            session: who.session.clone(),
            csrf: form.csrf,
            user: form.user,
            how,
        })
        .await;
    issued_answer(&app, &who, answer).await
}

#[derive(Deserialize)]
struct CertificateForm {
    csrf: String,
    serial: String,
}

async fn renew_certificate(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<CertificateForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RenewClientCertificate {
            session: who.session.clone(),
            csrf: form.csrf,
            serial: form.serial,
        })
        .await;
    issued_answer(&app, &who, answer).await
}

async fn revoke_certificate(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<CertificateForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RevokeClientCertificate {
            session: who.session.clone(),
            csrf: form.csrf,
            serial: form.serial,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/certificates?done=revoked", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            certificates_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a certificate revocation with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The page after a certificate is issued or renewed: the certificate and
/// any key file, once; else the Certificates page with the reason.
async fn issued_answer(app: &App, who: &Who, answer: Result<Answer, String>) -> Response {
    let issued = match answer {
        Ok(Answer::ClientCertificateIssued { issued }) => issued,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return certificates_view(app, who, Some(Notice::refused(sentence(&message)))).await;
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered a certificate request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let key_file = issued.key_file.as_ref().map(|key| KeyFileView {
        p12_base64: key.p12_base64.clone(),
        passphrase: key.passphrase.clone(),
        encryption: match key.cipher {
            Cipher::Aes256 => "AES-256",
            Cipher::TripleDes => "3DES, for older devices",
        },
    });
    html(&CertificateIssuedPage {
        title: "Certificate issued - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/certificates"),
        user: issued.user.clone(),
        serial: issued.serial.clone(),
        until: stamp(issued.not_after),
        url: issued.url.clone(),
        pin: issued.pin.clone(),
        certificate_base64: data_encoding::BASE64.encode(issued.certificate.as_bytes()),
        key_file,
        copy_icon: icons::COPY,
    })
}

#[derive(Template)]
#[template(path = "server_settings.html")]
struct ServerSettingsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    /// None when the server runs the operator's own configuration file.
    sections: Option<Vec<SettingsSection>>,
    /// How many stored values wait for the next start, and that in words.
    pending: usize,
    pending_text: String,
    csrf: String,
    warning_icon: &'static str,
}

struct SettingsSection {
    id: String,
    title: &'static str,
    note: &'static str,
    fields: Vec<SettingField>,
}

/// A server setting as the Settings page asks for it.
struct SettingField {
    /// The variable, which is also the form field's name.
    name: &'static str,
    id: String,
    label: &'static str,
    value: String,
    /// Whether the panel may change it; otherwise what sets it, in words.
    open: bool,
    locked: Option<String>,
    pending: bool,
    numeric: bool,
    /// The unit shown beside the number: a symbol for a measure, as "s" or
    /// "Mbps", a noun for a count; empty for a field without one.
    unit: &'static str,
    hint: String,
    choices: Option<Vec<SettingChoice>>,
}

struct SettingChoice {
    value: String,
    label: String,
    selected: bool,
}

/// The options of a choice, with the current value selected. A current
/// value the choice does not list is offered too, so that saving the page
/// never changes a setting nobody touched.
fn setting_choices(options: &[(&str, &str)], current: &str) -> Vec<SettingChoice> {
    let mut choices: Vec<SettingChoice> = options
        .iter()
        .map(|(value, label)| SettingChoice {
            value: (*value).to_owned(),
            label: (*label).to_owned(),
            selected: *value == current,
        })
        .collect();
    if !choices.iter().any(|choice| choice.selected) {
        choices.push(SettingChoice {
            value: current.to_owned(),
            label: format!("{current} (not one of the listed values)"),
            selected: true,
        });
    }
    choices
}

/// What a section of the Settings page tells about when its changes apply.
fn section_note(title: &str) -> &'static str {
    match title {
        "Sign-in" | "Tunnel and firewall" => "Changes wait for the next container start",
        "Load balancer" => "Changes apply at once; connected users stay connected",
        _ => "Changes reach new connections at once",
    }
}

fn setting_field(spec: &'static Spec, setting: &Setting) -> SettingField {
    let value = match &setting.stored {
        Some(stored) => stored.clone(),
        None => setting.running.clone(),
    };
    let open = setting.source.is_open();
    let locked = match &setting.source {
        ServerSource::Environment => Some("Set by the container's environment".to_owned()),
        ServerSource::Override(by) => Some(format!("Set by {by}")),
        ServerSource::Panel | ServerSource::Default => None,
    };
    let mut unreadable = None;
    let (value, unit) = match spec.kind {
        Kind::Number(unit) => (value, unit),
        Kind::Rate if value.is_empty() => (value, "Mbps"),
        Kind::Rate => match value.parse::<u64>() {
            Ok(bytes) => (overrides::megabits(bytes), "Mbps"),
            Err(error) => {
                unreadable = Some(format!(
                    "{value} is not a whole number of bytes per second ({error}); type the limit \
                     in Mbps"
                ));
                (value, "Mbps")
            }
        },
        Kind::Switch
        | Kind::Choice(_)
        | Kind::Text
        | Kind::Addresses
        | Kind::Domains
        | Kind::SearchDomains
        | Kind::Routes => (value, ""),
    };
    let (choices, hint, numeric) = match spec.kind {
        Kind::Switch => (
            Some(setting_choices(&[("true", "On"), ("false", "Off")], &value)),
            String::new(),
            false,
        ),
        Kind::Choice(options) => (Some(setting_choices(options, &value)), String::new(), false),
        Kind::Number(_) => (None, "Empty for the default".to_owned(), true),
        Kind::Rate => (
            None,
            match unreadable {
                Some(problem) => problem,
                None => "Kept in bytes per second; empty for the default".to_owned(),
            },
            false,
        ),
        Kind::Addresses => (None, "Separate several with commas".to_owned(), false),
        Kind::Domains | Kind::Routes => (
            None,
            "Separate several with commas; empty for none".to_owned(),
            false,
        ),
        Kind::SearchDomains => (
            None,
            "Separate several with spaces; empty for none".to_owned(),
            false,
        ),
        Kind::Text => (None, "Empty for none".to_owned(), false),
    };
    SettingField {
        name: spec.name,
        id: format!("s-{}", spec.name.to_ascii_lowercase().replace('_', "-")),
        label: spec.label,
        value,
        open,
        locked,
        pending: setting.pending(),
        numeric,
        unit,
        hint,
        choices,
    }
}

/// The Settings page, from the helper's answer.
async fn server_settings_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::ServerSettings {
            session: who.session.clone(),
        })
        .await;
    let settings = match answer {
        Ok(Answer::ServerSettings { settings }) => settings,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return plain(StatusCode::FORBIDDEN, &sentence(&message));
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered a settings request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let mut pending = 0;
    let sections = match settings {
        None => None,
        Some(settings) => {
            let mut sections: Vec<SettingsSection> = Vec::new();
            for spec in SPECS {
                let Some(setting) = settings.iter().find(|setting| setting.name == spec.name)
                else {
                    return failure(&format!("the server's record has no {}", spec.name));
                };
                let field = setting_field(spec, setting);
                if field.pending {
                    pending += 1;
                }
                match sections
                    .iter_mut()
                    .find(|section| section.title == spec.section)
                {
                    Some(section) => section.fields.push(field),
                    None => sections.push(SettingsSection {
                        id: format!("section-{}", sections.len()),
                        title: spec.section,
                        note: section_note(spec.section),
                        fields: vec![field],
                    }),
                }
            }
            Some(sections)
        }
    };
    html(&ServerSettingsPage {
        title: "Settings - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/settings"),
        notice,
        sections,
        pending,
        pending_text: match pending {
            1 => "1 saved setting waits for the next container start.".to_owned(),
            count => format!("{count} saved settings wait for the next container start."),
        },
        csrf: who.csrf.clone(),
        warning_icon: icons::WARNING,
    })
}

async fn server_settings_page(
    State(app): State<App>,
    Query(query): Query<DoneQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("reloaded") => Some(Notice::done(
            "Saved. ocserv reloaded, so new connections get the new settings; connected users \
             keep their sessions.",
        )),
        Some("saved") => Some(Notice::done(
            "Saved. Settings marked as waiting take effect when the container next starts.",
        )),
        Some(_) | None => None,
    };
    server_settings_view(&app, &who, notice).await
}

async fn save_server_settings(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let mut csrf = None;
    let mut values = Vec::new();
    for (name, value) in form {
        if name == "csrf" {
            csrf = Some(value);
        } else {
            values.push((name, value));
        }
    }
    let Some(csrf) = csrf else {
        return bad_request("the form carried no CSRF token");
    };
    let answer = app
        .helper
        .call(Ask::SetServerSettings {
            session: who.session.clone(),
            csrf,
            values,
        })
        .await;
    match answer {
        Ok(Answer::ServerSettingsSaved { reloaded: true }) => {
            see_other("/settings?done=reloaded", &[])
        }
        Ok(Answer::ServerSettingsSaved { reloaded: false }) => {
            see_other("/settings?done=saved", &[])
        }
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            server_settings_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a settings change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Template)]
#[template(path = "alerts.html")]
struct AlertsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    csrf: String,
    topics: Vec<TopicChoice>,
    /// How many topics the admin chose, as the card's pill says it; none
    /// when they chose none.
    chosen: Option<String>,
    channels: Vec<ChannelRow>,
    /// How many channels the admin has of the most they may, and whether
    /// that is all they may have.
    count: String,
    full: bool,
    max_channels: usize,
    /// Why email alerts cannot go out yet, while no mail server is set.
    email_note: Option<&'static str>,
    /// The mail server card, for an owner.
    mail: Option<MailCard>,
    bell_icon: &'static str,
    send_icon: &'static str,
    mail_icon: &'static str,
    warning_icon: &'static str,
}

/// A topic on the Alerts page, with what it covers for this admin.
struct TopicChoice {
    key: &'static str,
    title: &'static str,
    hint: String,
    checked: bool,
}

/// One of the admin's channels as the Alerts page lists it.
struct ChannelRow {
    id: u32,
    kind: String,
    icon: &'static str,
    label: String,
    unencrypted: bool,
    /// The pill's class and words, and what it says of the last or next
    /// message: the words before its time, the time, and the words after.
    pill: (&'static str, &'static str),
    before: String,
    at: Option<Stamp>,
    after: String,
}

/// The mail server card an owner sees.
struct MailCard {
    from_env: bool,
    /// Whether the panel saved one, which may be removed.
    saved: bool,
    /// The server in words, when one is set.
    summary: Option<String>,
    host: String,
    /// The port typed, empty when it is the security's usual one.
    port: String,
    user: String,
    from: String,
    password_set: bool,
    securities: Vec<SecurityChoice>,
}

struct SecurityChoice {
    key: &'static str,
    words: &'static str,
    selected: bool,
}

fn topic_choice(topic: Topic, view: &AlertsView) -> TopicChoice {
    let (title, hint) = match topic {
        Topic::Blocks => (
            "Automatic blocks",
            "An address blocked at the firewall after repeated bans, as it happens.".to_owned(),
        ),
        Topic::SignIns => (
            "Sign-ins from outside",
            match view.owner {
                true => "Any admin's sign-in to this panel from outside the trusted networks, \
                         PANEL_LAN_NETWORKS, as it happens."
                    .to_owned(),
                false => "Your own sign-ins to this panel from outside the trusted networks, \
                          PANEL_LAN_NETWORKS, as they happen. Owners hear of every admin's."
                    .to_owned(),
            },
        ),
        Topic::CountryDrops => (
            "Country rule drops",
            match view.country_rules_on {
                true => "Once a day, just after midnight UTC: how many packets the country \
                         rules dropped the day before."
                    .to_owned(),
                false => "Once a day, just after midnight UTC: how many packets the country \
                          rules dropped the day before. The country rules are off, so there is \
                          nothing to count yet."
                    .to_owned(),
            },
        ),
        Topic::Locations => (
            "Location checks",
            "A sign-in to the VPN or this panel that the location checks refused, or let in \
             but found unusual, as it happens, with the reasons; and a VPN sign-in let in \
             because its check could not run."
                .to_owned(),
        ),
    };
    TopicChoice {
        key: topic.key(),
        title,
        hint,
        checked: view.topics.contains(&topic),
    }
}

fn alert_count(alerts: usize) -> String {
    match alerts {
        1 => "1 alert".to_owned(),
        count => format!("{count} alerts"),
    }
}

fn channel_row(channel: &ChannelView) -> ChannelRow {
    let tries = alerts::RETRY_AFTER.len() + 1;
    let status = &channel.status;
    let pending = alert_count(status.pending);
    let (pill, before, at, after) = match (status.trying, status.due, &status.last) {
        (Some(attempt), None, _) => (
            ("pill-info", "Sending"),
            format!("{pending}, try {attempt} of {tries} under way"),
            None,
            String::new(),
        ),
        (Some(attempt), Some(due), _) => (
            ("pill-warn", "Retrying"),
            format!("{pending}, try {attempt} of {tries} at"),
            Some(stamp(due)),
            String::new(),
        ),
        (None, Some(due), _) => (
            ("pill-info", "Waiting"),
            format!("{pending}, going at"),
            Some(stamp(due)),
            String::new(),
        ),
        (None, None, Some(Last::Sent { time, alerts })) => (
            ("pill-ok", "Sent"),
            format!("{} at", alert_count(*alerts)),
            Some(stamp(*time)),
            String::new(),
        ),
        (
            None,
            None,
            Some(Last::Failed {
                time,
                alerts,
                error,
            }),
        ) => (
            ("pill-bad", "Failed"),
            format!("Gave up on {} at", alert_count(*alerts)),
            Some(stamp(*time)),
            format!(", after {tries} tries: {}", sentence(error)),
        ),
        (None, None, None) => (
            ("pill-mute", "Nothing sent"),
            "No message yet. Send a test to check that it works.".to_owned(),
            None,
            String::new(),
        ),
    };
    let icon = match channel.kind.as_str() {
        "ntfy" => icons::BELL_SIMPLE,
        "Telegram" => icons::TELEGRAM_LOGO,
        "webhook" => icons::WEBHOOKS_LOGO,
        "email" => icons::ENVELOPE_SIMPLE,
        _other => icons::PAPER_PLANE_TILT,
    };
    ChannelRow {
        id: channel.id,
        kind: channel.kind.clone(),
        icon,
        label: channel.label.clone(),
        unencrypted: channel.unencrypted,
        pill,
        before,
        at,
        after,
    }
}

fn mail_card(view: &AlertsView) -> Option<MailCard> {
    if !view.owner {
        return None;
    }
    let mail = view.mail.as_ref();
    let security = match mail {
        Some(server) => server.security,
        None => Security::Starttls,
    };
    let (host, port, user, from) = match mail {
        Some(server) => (
            server.host.clone(),
            match server.port == server.security.default_port() {
                true => String::new(),
                false => server.port.to_string(),
            },
            match &server.user {
                Some(user) => user.clone(),
                None => String::new(),
            },
            server.from.clone(),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    };
    Some(MailCard {
        from_env: view.mail_from_env,
        saved: mail.is_some() && !view.mail_from_env,
        summary: mail.map(|server| server.label.clone()),
        host,
        port,
        user,
        from,
        password_set: mail.is_some_and(|server| server.password_set),
        securities: Security::ALL
            .iter()
            .map(|choice| SecurityChoice {
                key: choice.key(),
                words: match choice {
                    Security::Tls => "TLS, usually port 465",
                    Security::Starttls => "STARTTLS, usually port 587",
                    Security::Plain => "None, to a relay without a password, usually port 25",
                },
                selected: *choice == security,
            })
            .collect(),
    })
}

fn alerts_page_of(app: &App, who: &Who, notice: Option<Notice>, view: AlertsView) -> AlertsPage {
    let chosen = match view.topics.len() {
        0 => None,
        count => Some(format!("{count} of {}", Topic::ALL.len())),
    };
    let email_note = match (view.mail_set, view.owner) {
        (true, _) => None,
        (false, true) => Some("Email needs a mail server; set one on the card below."),
        (false, false) => Some("Email needs a mail server, which an owner sets on this page."),
    };
    AlertsPage {
        title: "Alerts - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/alerts"),
        notice,
        csrf: who.csrf.clone(),
        topics: Topic::ALL
            .iter()
            .map(|topic| topic_choice(*topic, &view))
            .collect(),
        chosen,
        channels: view.channels.iter().map(channel_row).collect(),
        count: format!("{} of {}", view.channels.len(), view.max_channels),
        full: view.channels.len() >= view.max_channels,
        max_channels: view.max_channels,
        email_note,
        mail: mail_card(&view),
        bell_icon: icons::BELL_RINGING,
        send_icon: icons::PAPER_PLANE_TILT,
        mail_icon: icons::ENVELOPE_SIMPLE,
        warning_icon: icons::WARNING,
    }
}

async fn alerts_page(
    State(app): State<App>,
    Query(query): Query<DoneQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("topics") => Some(Notice::done("Saved what alerts you.")),
        Some("added") => Some(Notice::done(
            "Added the channel. Send a test to check that it works.",
        )),
        Some("test") => Some(Notice::done(
            "A test message is on its way. Reload this page to see how it went.",
        )),
        Some("removed") => Some(Notice::done("Removed the channel.")),
        Some("mail") => Some(Notice::done(
            "Saved the mail server. Send a test to an email channel to check it.",
        )),
        Some("mail_removed") => Some(Notice::done("Removed the mail server.")),
        Some(_) | None => None,
    };
    alerts_view(&app, &who, notice).await
}

async fn alerts_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::Alerts {
            session: who.session.clone(),
        })
        .await;
    match answer {
        Ok(Answer::Alerts { view }) => html(&alerts_page_of(app, who, notice, *view)),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(other) => failure(&format!(
            "the helper answered an alerts request with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The page after a change on the Alerts page: `done` when it was made,
/// else the Alerts page with the reason.
async fn alerts_answer(
    app: &App,
    who: &Who,
    answer: Result<Answer, String>,
    done: &'static str,
) -> Response {
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            alerts_view(app, who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!(
            "the helper answered a change to alerts with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// Saves the topics ticked on the Alerts page.
async fn set_alert_topics(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let mut csrf = String::new();
    let mut topics = Vec::new();
    for (name, value) in form {
        match name.as_str() {
            "csrf" => csrf = value,
            "topic" => match Topic::parse(&value) {
                Some(topic) => topics.push(topic),
                None => return bad_request(&format!("'{value}' is not an alert")),
            },
            other => return bad_request(&format!("'{other}' is not a field of the alerts")),
        }
    }
    let answer = app
        .helper
        .call(Ask::SetAlertTopics {
            session: who.session.clone(),
            csrf,
            topics,
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=topics").await
}

/// One of the Alerts page's forms for a new channel; each sends the fields
/// of its kind only.
#[derive(Deserialize)]
struct ChannelForm {
    csrf: String,
    kind: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    topic: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    chat: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    address: String,
}

async fn add_alert_channel(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<ChannelForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let channel = match form.kind.as_str() {
        "ntfy" => ChannelEntry::Ntfy {
            server: form.server,
            topic: form.topic,
            token: form.token,
        },
        "telegram" => ChannelEntry::Telegram {
            token: form.token,
            chat: form.chat,
        },
        "webhook" => ChannelEntry::Webhook { url: form.url },
        "email" => ChannelEntry::Email {
            address: form.address,
        },
        other => return bad_request(&format!("'{other}' is not a kind of channel")),
    };
    let answer = app
        .helper
        .call(Ask::AddAlertChannel {
            session: who.session.clone(),
            csrf: form.csrf,
            channel,
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=added").await
}

#[derive(Deserialize)]
struct ChannelIdForm {
    csrf: String,
    id: u32,
}

async fn test_alert_channel(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<ChannelIdForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::TestAlertChannel {
            session: who.session.clone(),
            csrf: form.csrf,
            id: form.id,
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=test").await
}

async fn remove_alert_channel(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<ChannelIdForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RemoveAlertChannel {
            session: who.session.clone(),
            csrf: form.csrf,
            id: form.id,
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=removed").await
}

#[derive(Deserialize)]
struct MailForm {
    csrf: String,
    host: String,
    #[serde(default)]
    port: String,
    security: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    from: String,
}

async fn set_mail_server(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<MailForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::SetMailServer {
            session: who.session.clone(),
            csrf: form.csrf,
            server: MailEntry {
                host: form.host,
                port: form.port,
                security: form.security,
                user: form.user,
                password: form.password,
                from: form.from,
            },
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=mail").await
}

#[derive(Deserialize)]
struct MailRemoveForm {
    csrf: String,
}

async fn remove_mail_server(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<MailRemoveForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RemoveMailServer {
            session: who.session.clone(),
            csrf: form.csrf,
        })
        .await;
    alerts_answer(&app, &who, answer, "/alerts?done=mail_removed").await
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    notice: Option<Notice>,
    name: String,
    role: &'static str,
    /// What the role lets the admin do, in words.
    role_scope: &'static str,
    added: Stamp,
    last_login: Option<Stamp>,
    authenticator_app: bool,
    passkeys: Vec<PasskeyRow>,
    /// Why passkeys cannot be added here, as a sentence, when they cannot.
    passkeys_unavailable: Option<String>,
    /// Whether the admin has room for another passkey.
    passkey_room: bool,
    max_passkeys: usize,
    name_chars: usize,
    other_sessions: usize,
    /// Where else the admin is signed in, in words.
    elsewhere: String,
    csrf: String,
    id_icon: &'static str,
    key_icon: &'static str,
    phone_icon: &'static str,
    passkey_icon: &'static str,
    laptop_icon: &'static str,
    warning: &'static str,
    /// Whether the location checks are on, which the vacation card needs;
    /// the last day of the admin's vacation, while it lasts; and the first
    /// and last day a vacation may end on.
    locations_on: bool,
    vacation: Option<String>,
    vacation_from: String,
    vacation_to: String,
    location_icon: &'static str,
}

/// One of the admin's passkeys as the Account page lists it.
struct PasskeyRow {
    name: String,
    added: Stamp,
    last_used: Option<Stamp>,
}

fn role_scope(role: Role) -> &'static str {
    match role {
        Role::Owner => "everything, including settings, certificates, admins and the audit log",
        Role::Operator => "VPN users, groups, sessions and bans",
        Role::Viewer => "every page, without changing anything",
    }
}

async fn account_page(
    State(app): State<App>,
    Query(query): Query<DoneQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("password") => Some(Notice::done(
            "Changed your password. Your other sessions have ended.",
        )),
        Some("app") => Some(Notice::done("Your authenticator app is on.")),
        Some("passkey") => Some(Notice::done("Added your passkey.")),
        Some("passkey_removed") => Some(Notice::done("Removed the passkey.")),
        Some("signed_out") => Some(Notice::done("Signed out everywhere else.")),
        Some("vacation") => Some(Notice::done("Saved your vacation.")),
        Some(_) | None => None,
    };
    account_view(&app, &who, notice).await
}

/// The Account page, with `notice` at its top.
async fn account_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::Account {
            session: who.session.clone(),
        })
        .await;
    let (admin, other_sessions, passkeys, passkeys_unavailable, locations_on) = match answer {
        Ok(Answer::AdminAccount {
            admin,
            other_sessions,
            passkeys,
            passkeys_unavailable,
            locations_on,
        }) => (
            admin,
            other_sessions,
            passkeys,
            passkeys_unavailable,
            locations_on,
        ),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered an account request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let (vacation_from, vacation_to) = match clock::now() {
        Ok(now) => vacation_range(now),
        Err(error) => return failure(&error),
    };
    html(&AccountPage {
        title: "Your account - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/account"),
        notice,
        locations_on,
        vacation: admin.vacation_until.map(vacation_last_day),
        vacation_from,
        vacation_to,
        location_icon: icons::MAP_PIN,
        role: role_name(admin.role),
        role_scope: role_scope(admin.role),
        added: stamp(admin.created),
        last_login: admin.last_login.map(stamp),
        authenticator_app: admin.authenticator_app,
        passkey_room: passkeys.len() < passkey::MAX_PASSKEYS,
        passkeys: passkeys
            .into_iter()
            .map(|view| PasskeyRow {
                name: view.name,
                added: stamp(view.created),
                last_used: view.last_used.map(stamp),
            })
            .collect(),
        passkeys_unavailable: passkeys_unavailable
            .map(|reason| sentence(&format!("passkeys cannot be used here: {reason}"))),
        max_passkeys: passkey::MAX_PASSKEYS,
        name_chars: passkey::MAX_NAME_CHARS,
        other_sessions,
        elsewhere: match other_sessions {
            0 => "This is your only session.".to_owned(),
            1 => "You have 1 other session, in another browser or on another device.".to_owned(),
            count => {
                format!("You have {count} other sessions, in other browsers or on other devices.")
            }
        },
        csrf: who.csrf.clone(),
        name: admin.name,
        id_icon: icons::ID_CARD,
        key_icon: icons::SHIELD_STAR,
        phone_icon: icons::PHONE,
        passkey_icon: icons::FINGERPRINT,
        laptop_icon: icons::LAPTOP,
        warning: icons::WARNING,
    })
}

/// What the page's script shows when the admin's session is gone.
const SESSION_ENDED: &str = "Your session has ended. Sign in again.";

#[derive(Deserialize)]
struct PasskeyNameForm {
    csrf: String,
    name: String,
}

/// Starts adding a passkey for the signed-in admin: the options for the
/// browser's passkey prompt, for the page's script.
async fn add_passkey_begin(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PasskeyNameForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, SESSION_ENDED, &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::PasskeyBegin {
            session: who.session,
            csrf: form.csrf,
            name: form.name,
        })
        .await;
    match answer {
        Ok(Answer::PasskeyOptions { options }) => json_body(StatusCode::OK, options, &[]),
        Ok(Answer::Invalid { message }) => {
            json_error(StatusCode::BAD_REQUEST, &sentence(&message), &[])
        }
        Ok(Answer::Denied) => json_error(StatusCode::UNAUTHORIZED, SESSION_ENDED, &[]),
        Ok(other) => failure(&format!(
            "the helper answered the start of a passkey with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct PasskeyAddForm {
    csrf: String,
    credential: String,
}

/// Adds the passkey the browser registered, and tells the page's script
/// where to go: the dashboard after a first second factor, else the Account
/// page.
async fn add_passkey_finish(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PasskeyAddForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, SESSION_ENDED, &[]),
        Err(error) => return failure(&error),
    };
    let next = match who.scope {
        Scope::Enrollment => "/",
        Scope::Full => "/account?done=passkey",
    };
    let answer = app
        .helper
        .call(Ask::PasskeyFinish {
            session: who.session,
            csrf: form.csrf,
            credential: form.credential,
        })
        .await;
    match answer {
        Ok(Answer::Done) => json_next(next, &[]),
        Ok(Answer::Invalid { message }) => {
            json_error(StatusCode::BAD_REQUEST, &sentence(&message), &[])
        }
        Ok(Answer::Denied) => json_error(StatusCode::UNAUTHORIZED, SESSION_ENDED, &[]),
        Ok(other) => failure(&format!("the helper answered a new passkey with {other:?}")),
        Err(error) => failure(&error),
    }
}

async fn remove_passkey(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PasskeyNameForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::RemovePasskey {
            session: who.session.clone(),
            csrf: form.csrf,
            name: form.name,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/account?done=passkey_removed", &[]),
        Ok(Answer::Invalid { message }) => {
            account_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(other) => failure(&format!(
            "the helper answered a passkey removal with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct SignOutForm {
    csrf: String,
}

async fn end_other_sessions(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<SignOutForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::EndOtherSessions {
            session: who.session.clone(),
            csrf: form.csrf,
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other("/account?done=signed_out", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(other) => failure(&format!(
            "the helper answered a sign-out elsewhere with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct DoneQuery {
    done: Option<String>,
}

async fn groups_page(
    State(app): State<App>,
    Query(query): Query<DoneQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    let notice = match query.done.as_deref() {
        Some("removed") => Some(Notice::done(
            "Removed the group's settings. Its members take the server's settings from their next connection.",
        )),
        Some(_) | None => None,
    };
    groups_view(&app, &who, notice).await
}

/// The Groups page: every group the password file names or that has a
/// settings file, with its members and the settings in effect for them.
async fn groups_view(app: &App, who: &Who, notice: Option<Notice>) -> Response {
    let answer = app
        .helper
        .call(Ask::ListGroups {
            session: who.session.clone(),
        })
        .await;
    let (groups, server, readable) = match answer {
        Ok(Answer::Groups {
            groups,
            server,
            readable,
        }) => (groups, server, readable),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a group list request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let cards = groups
        .into_iter()
        .map(|group| {
            let effective = match &group.settings {
                Some(settings) => settings.over(&server),
                None => server.clone(),
            };
            GroupCard {
                members: match group.members.as_slice() {
                    [] => "No members yet".to_owned(),
                    [one] => format!("1 member: {one}"),
                    many => format!("{} members: {}", many.len(), many.join(", ")),
                },
                own: group.settings.is_some(),
                tunnel: capitalized(&routes_text(&effective.routes)),
                dns: if effective.dns.is_empty() {
                    "None".to_owned()
                } else {
                    effective.dns.join(", ")
                },
                bandwidth: bandwidth_text(effective.download, effective.upload),
                restricted: match effective.restrict {
                    Some(true) => "Yes, to its routes",
                    Some(false) | None => "No",
                },
                name: group.name,
            }
        })
        .collect();
    html(&GroupsPage {
        title: "Groups - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, "/groups"),
        notice,
        cards,
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        readable,
        group_icon: icons::USERS_THREE,
    })
}

#[derive(Deserialize)]
struct NewGroupForm {
    csrf: String,
    name: String,
}

/// Creates a group's settings file with nothing set yet, and opens its
/// settings. A group that already has one is refused.
async fn create_group(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<NewGroupForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let name = form.name.trim().to_owned();
    let existing = app
        .helper
        .call(Ask::GetOverrides {
            session: who.session.clone(),
            owner: Owner::Group,
            name: name.clone(),
        })
        .await;
    match existing {
        Ok(Answer::Overrides { own: None, .. }) => {}
        Ok(Answer::Overrides { own: Some(_), .. }) => {
            return groups_view(
                &app,
                &who,
                Some(Notice::refused(format!(
                    "The group {name} already has settings. Open it below to change them."
                ))),
            )
            .await;
        }
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return groups_view(&app, &who, Some(Notice::refused(sentence(&message)))).await;
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered a settings request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    }
    let answer = app
        .helper
        .call(Ask::SetOverrides {
            session: who.session.clone(),
            csrf: form.csrf,
            owner: Owner::Group,
            name: name.clone(),
            form: Some(OverridesForm::default()),
        })
        .await;
    match answer {
        Ok(Answer::Done) => see_other_to(&format!("/groups/{name}?done=created")),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            groups_view(&app, &who, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(other) => failure(&format!("the helper answered a new group with {other:?}")),
        Err(error) => failure(&error),
    }
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    title: &'static str,
    page: PageLinks,
    shell: Shell,
    heading: String,
    /// Where the settings come from and when they apply.
    intro: String,
    notice: Option<Notice>,
    /// The form's address.
    action: String,
    /// Where the page's "back" link goes.
    back: &'static str,
    back_label: &'static str,
    is_user: bool,
    has_file: bool,
    readable: bool,
    can_operate: bool,
    csrf: String,
    values: OverridesForm,
    /// What each empty field takes instead, in words.
    inherits: Inherits,
    /// The further options this owner takes, and whether any is set, which
    /// opens their section.
    extras: Vec<ExtraField>,
    extras_open: bool,
}

/// One of the further options as the settings page asks for it.
struct ExtraField {
    /// The form field's name, `extra-<option>`.
    name: String,
    id: String,
    label: &'static str,
    value: String,
    /// "switch", "list" or "line".
    input: &'static str,
    /// What an empty field takes, in words.
    inherits: String,
    hint: &'static str,
    /// The unit symbol shown beside a measured number, as "s"; empty for
    /// other fields.
    unit: &'static str,
}

/// The further options `owner` takes, with their values in `values` and
/// what each takes when empty: the group's value, else the server's.
fn extra_fields_of(
    owner: Owner,
    values: &BTreeMap<String, String>,
    group: Option<&str>,
    group_settings: Option<&Overrides>,
    server: &Overrides,
) -> Vec<ExtraField> {
    let shown = |extra: &extras::Extra, found: &[String]| {
        if extra.kind == ExtraKind::Switch {
            match found {
                [value] if value == "true" => "on".to_owned(),
                [value] if value == "false" => "off".to_owned(),
                _ => found.join(", "),
            }
        } else {
            found.join(", ")
        }
    };
    extras::EXTRAS
        .iter()
        .filter(|extra| extra.only.is_none_or(|only| only == owner))
        .map(|extra| {
            let from_group = group_settings.and_then(|settings| settings.extra.get(extra.option));
            let inherits = match (from_group, group, server.extra.get(extra.option)) {
                (Some(found), Some(group), _) => {
                    format!("{} from the group {group}", shown(extra, found))
                }
                (_, _, Some(found)) => format!("{} from the server", shown(extra, found)),
                _ => "not set".to_owned(),
            };
            let (input, hint) = match extra.kind {
                ExtraKind::Switch => ("switch", ""),
                ExtraKind::Domains => ("list", "One domain per line."),
                ExtraKind::Networks => ("list", "One network per line, as 10.0.0.0/8."),
                ExtraKind::Seconds => ("line", ""),
                ExtraKind::Number { .. } => ("line", "A whole number."),
                ExtraKind::Address => ("line", "An IP address."),
                ExtraKind::Address6 => ("line", "An IPv6 address inside the VPN's IPv6 pool."),
                ExtraKind::Pool => (
                    "line",
                    "A private network of this group's own, as 10.20.0.0/24, overlapping no \
                     other pool. The firewall takes it at the next container start.",
                ),
                ExtraKind::Ports => (
                    "line",
                    "Rules like tcp(443), udp(53); put them inside !( ) to block those ports \
                     instead.",
                ),
                ExtraKind::Published => (
                    "list",
                    "One network per line, as 10.10.0.0/24, reached through this user's \
                     sessions. Site-to-site rules decide who reaches them.",
                ),
            };
            ExtraField {
                name: format!("extra-{}", extra.option),
                id: format!("extra-{}", extra.option),
                label: extra.label,
                value: match values.get(extra.option) {
                    Some(value) => value.clone(),
                    None => String::new(),
                },
                input,
                inherits,
                hint,
                unit: if matches!(extra.kind, ExtraKind::Seconds) {
                    "s"
                } else {
                    ""
                },
            }
        })
        .collect()
}

struct Inherits {
    routes: String,
    dns: String,
    download: String,
    upload: String,
    restrict: String,
}

#[derive(Deserialize)]
struct SettingsForm {
    csrf: String,
    /// "save" or "remove".
    action: String,
    #[serde(default)]
    fixed_ipv4: String,
    #[serde(default)]
    routes: String,
    #[serde(default)]
    dns: String,
    #[serde(default)]
    download: String,
    #[serde(default)]
    upload: String,
    #[serde(default)]
    restrict: String,
    /// Every other field: the further options, named `extra-<option>`.
    #[serde(flatten)]
    extra: BTreeMap<String, String>,
}

/// The further options of a settings form by ocserv option. A field not
/// named `extra-<option>` keeps its name, so the helper refuses it.
fn extra_fields(fields: BTreeMap<String, String>) -> BTreeMap<String, String> {
    fields
        .into_iter()
        .map(|(name, value)| match name.strip_prefix("extra-") {
            Some(option) => (option.to_owned(), value),
            None => (name, value),
        })
        .collect()
}

/// A user's or group's settings as the form shows them: an unset value is
/// an empty field.
fn form_values(settings: &Overrides) -> OverridesForm {
    let limit = |limit: Option<u64>| match limit {
        Some(bytes) => overrides::megabits(bytes),
        None => String::new(),
    };
    OverridesForm {
        fixed_ipv4: match &settings.fixed_ipv4 {
            Some(address) => address.clone(),
            None => String::new(),
        },
        routes: settings.routes.join("\n"),
        dns: settings.dns.join("\n"),
        download: limit(settings.download),
        upload: limit(settings.upload),
        restrict: match settings.restrict {
            Some(true) => "yes".to_owned(),
            Some(false) => "no".to_owned(),
            None => "inherit".to_owned(),
        },
        extra: extra_values(&settings.extra),
    }
}

/// The further options as their form fields show them: a switch as on or
/// off, a list one value per line.
fn extra_values(extra: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, String> {
    extra
        .iter()
        .map(|(option, values)| {
            let switch =
                extras::extra_of(option).is_some_and(|extra| extra.kind == ExtraKind::Switch);
            let text = match (switch, values.as_slice()) {
                (true, [value]) if value == "true" => "on".to_owned(),
                (true, [value]) if value == "false" => "off".to_owned(),
                _ => values.join("\n"),
            };
            (option.clone(), text)
        })
        .collect()
}

/// The settings page of a user or group. `typed` is a refused form's
/// values, shown again instead of the saved ones.
async fn settings_view(
    app: &App,
    who: &Who,
    owner: Owner,
    name: &str,
    notice: Option<Notice>,
    typed: Option<OverridesForm>,
) -> Response {
    let answer = app
        .helper
        .call(Ask::GetOverrides {
            session: who.session.clone(),
            owner,
            name: name.to_owned(),
        })
        .await;
    let (own, group, group_settings, server, readable) = match answer {
        Ok(Answer::Overrides {
            own,
            group,
            group_settings,
            server,
            readable,
        }) => (own, group, group_settings, server, readable),
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            return plain(StatusCode::NOT_FOUND, &sentence(&message));
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered a settings request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let (heading, intro, action, back, back_label) = match owner {
        Owner::User => (
            format!("Settings for {name}"),
            match &group {
                Some(group) => format!(
                    "These settings apply to {name} only and win over those of the group \
                     {group} and of the server. Each empty field takes the value shown under \
                     it. ocserv reads them when {name} next connects."
                ),
                None => format!(
                    "These settings apply to {name} only and win over the server's. Each \
                     empty field takes the value shown under it. ocserv reads them when {name} \
                     next connects."
                ),
            },
            format!("/users/{name}/settings"),
            "/users",
            "VPN users",
        ),
        Owner::Group => (
            format!("Settings for the group {name}"),
            format!(
                "These settings apply to every member of {name} and win over the server's; \
                 a member's own settings win over them. Each empty field takes the server's \
                 value, shown under it. ocserv reads them when a member next connects."
            ),
            format!("/groups/{name}"),
            "/groups",
            "Groups",
        ),
    };
    let inherits = inherits(group.as_deref(), group_settings.as_deref(), &server);
    let values = match (typed, &own) {
        (Some(typed), _) => typed,
        (None, Some(own)) => form_values(own),
        (None, None) => form_values(&Overrides::default()),
    };
    let extras = extra_fields_of(
        owner,
        &values.extra,
        group.as_deref(),
        group_settings.as_deref(),
        &server,
    );
    html(&SettingsPage {
        title: "Settings - OpenConnect admin",
        page: app.links(),
        shell: shell(app, who, back),
        heading,
        intro,
        notice,
        action,
        back,
        back_label,
        is_user: owner == Owner::User,
        has_file: own.is_some(),
        readable,
        can_operate: !matches!(who.role, Role::Viewer),
        csrf: who.csrf.clone(),
        values,
        inherits,
        extras_open: extras.iter().any(|field| !field.value.is_empty()),
        extras,
    })
}

/// What each empty field takes, with where it comes from: the group's own
/// value when `group` sets one, the server's otherwise.
fn inherits(
    group: Option<&str>,
    group_settings: Option<&Overrides>,
    server: &Overrides,
) -> Inherits {
    let unset = Overrides::default();
    let set = match group_settings {
        Some(settings) => settings,
        None => &unset,
    };
    let from = |group_sets: bool| match (group, group_sets) {
        (Some(group), true) => format!("from the group {group}"),
        (Some(_) | None, _) => "from the server".to_owned(),
    };
    let (routes, routes_from) = if set.routes.is_empty() {
        (&server.routes, from(false))
    } else {
        (&set.routes, from(true))
    };
    let (dns, dns_from) = if set.dns.is_empty() {
        (&server.dns, from(false))
    } else {
        (&set.dns, from(true))
    };
    let (download, download_from) = match set.download {
        Some(limit) => (Some(limit), from(true)),
        None => (server.download, from(false)),
    };
    let (upload, upload_from) = match set.upload {
        Some(limit) => (Some(limit), from(true)),
        None => (server.upload, from(false)),
    };
    let (restrict, restrict_from) = match set.restrict {
        Some(restrict) => (Some(restrict), from(true)),
        None => (server.restrict, from(false)),
    };
    Inherits {
        routes: format!("{}, {routes_from}", routes_text(routes)),
        dns: if dns.is_empty() {
            format!("none, {dns_from}")
        } else {
            format!("{}, {dns_from}", dns.join(", "))
        },
        download: format!("{}, {download_from}", limit_text(download)),
        upload: format!("{}, {upload_from}", limit_text(upload)),
        restrict: format!(
            "{}, {restrict_from}",
            match restrict {
                Some(true) => "held to its routes",
                Some(false) | None => "not held to its routes",
            }
        ),
    }
}

#[derive(Deserialize)]
struct SavedQuery {
    done: Option<String>,
}

fn saved_notice(done: Option<&str>) -> Option<Notice> {
    match done {
        Some("saved") => Some(Notice::done(
            "Saved. ocserv applies the settings from the next connection.",
        )),
        Some("created") => Some(Notice::done(
            "Created the group. Set what its members get below, and add members on the VPN users page.",
        )),
        Some("removed") => Some(Notice::done(
            "Removed the settings. The values now come from the group or the server.",
        )),
        Some(_) | None => None,
    }
}

async fn group_settings_page(
    State(app): State<App>,
    Path(name): Path<String>,
    Query(query): Query<SavedQuery>,
    headers: HeaderMap,
) -> Response {
    settings_page(&app, &headers, Owner::Group, &name, query.done.as_deref()).await
}

async fn user_settings_page(
    State(app): State<App>,
    Path(name): Path<String>,
    Query(query): Query<SavedQuery>,
    headers: HeaderMap,
) -> Response {
    settings_page(&app, &headers, Owner::User, &name, query.done.as_deref()).await
}

async fn settings_page(
    app: &App,
    headers: &HeaderMap,
    owner: Owner,
    name: &str,
    done: Option<&str>,
) -> Response {
    let who = match signed_in(app, headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if who.landing() != "/" {
        return see_other(who.landing(), &[]);
    }
    settings_view(app, &who, owner, name, saved_notice(done), None).await
}

async fn save_group_settings(
    State(app): State<App>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Response {
    save_settings(&app, &headers, Owner::Group, &name, form).await
}

async fn save_user_settings(
    State(app): State<App>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Response {
    save_settings(&app, &headers, Owner::User, &name, form).await
}

/// Saves or removes a user's or group's settings, and shows the page again
/// with what the helper refused.
async fn save_settings(
    app: &App,
    headers: &HeaderMap,
    owner: Owner,
    name: &str,
    form: SettingsForm,
) -> Response {
    let who = match signed_in(app, headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let SettingsForm {
        csrf,
        action,
        fixed_ipv4,
        routes,
        dns,
        download,
        upload,
        restrict,
        extra,
    } = form;
    let typed = OverridesForm {
        fixed_ipv4,
        routes,
        dns,
        download,
        upload,
        restrict,
        extra: extra_fields(extra),
    };
    let (sent, done) = match action.as_str() {
        "save" => (Some(typed.clone()), "saved"),
        "remove" => (None, "removed"),
        other => return bad_request(&format!("'{other}' is not an action on settings")),
    };
    let answer = app
        .helper
        .call(Ask::SetOverrides {
            session: who.session.clone(),
            csrf,
            owner,
            name: name.to_owned(),
            form: sent,
        })
        .await;
    match answer {
        Ok(Answer::Done) => match (owner, done) {
            (Owner::Group, "removed") => see_other("/groups?done=removed", &[]),
            (Owner::Group, _) => see_other_to(&format!("/groups/{name}?done={done}")),
            (Owner::User, _) => see_other_to(&format!("/users/{name}/settings?done={done}")),
        },
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => {
            settings_view(
                app,
                &who,
                owner,
                name,
                Some(Notice::refused(sentence(&message))),
                Some(typed),
            )
            .await
        }
        Ok(other) => failure(&format!(
            "the helper answered a change to settings with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    since: Option<u64>,
}

/// The dashboard's history as columns: sample times in Unix seconds, the
/// connected sessions, and the bytes per second sent to and received from
/// clients, null for a sample that only set the baseline.
#[derive(Serialize)]
struct HistoryColumns {
    interval: u64,
    time: Vec<u64>,
    sessions: Vec<u64>,
    to_clients: Vec<Option<u64>>,
    from_clients: Vec<Option<u64>>,
}

/// The history for the dashboard's charts, after `since` when given, for a
/// signed-in session with full access.
async fn history_json(
    State(app): State<App>,
    Query(query): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) if who.landing() == "/" => who,
        Ok(Some(_) | None) => {
            return plain(StatusCode::UNAUTHORIZED, "Sign in to see the history.");
        }
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::History {
            session: who.session.clone(),
            since: query.since,
        })
        .await;
    let (interval, samples) = match answer {
        Ok(Answer::History { interval, samples }) => (interval, samples),
        Ok(Answer::Denied) => {
            return plain(StatusCode::UNAUTHORIZED, "Sign in to see the history.");
        }
        Ok(other) => {
            return failure(&format!(
                "the helper answered a history request with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let columns = HistoryColumns {
        interval,
        time: samples.iter().map(|sample| sample.time).collect(),
        sessions: samples.iter().map(|sample| sample.sessions).collect(),
        to_clients: samples.iter().map(|sample| sample.to_clients).collect(),
        from_clients: samples.iter().map(|sample| sample.from_clients).collect(),
    };
    match serde_json::to_string(&columns) {
        Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Err(error) => failure(&format!(
            "the history could not be written as JSON: {error}"
        )),
    }
}

/// A length of time in words, to its two largest units: "3 days and 4
/// hours", "12 minutes", "less than a minute".
fn span(seconds: u64) -> String {
    let count = |number: u64, unit: &str| match number {
        1 => format!("1 {unit}"),
        number => format!("{number} {unit}s"),
    };
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
    );
    match (days, hours, minutes) {
        (0, 0, 0) => "less than a minute".to_owned(),
        (0, 0, minutes) => count(minutes, "minute"),
        (0, hours, 0) => count(hours, "hour"),
        (0, hours, minutes) => format!("{} and {}", count(hours, "hour"), count(minutes, "minute")),
        (days, 0, _) => count(days, "day"),
        (days, hours, _) => format!("{} and {}", count(days, "day"), count(hours, "hour")),
    }
}

async fn login_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match signed_in(&app, &headers).await {
        Ok(Some(who)) => see_other(who.landing(), &[]),
        Ok(None) => login_form(&app, String::new(), None),
        Err(error) => failure(&error),
    }
}

fn login_form(app: &App, name: String, error: Option<String>) -> Response {
    html(&LoginPage {
        title: "Sign in - OpenConnect admin",
        page: app.links(),
        host: app.host.clone(),
        error,
        name,
        warning: icons::WARNING,
    })
}

#[derive(Deserialize)]
struct LoginForm {
    name: String,
    password: String,
}

async fn login(
    State(app): State<App>,
    Extension(Peer(address)): Extension<Peer>,
    Form(form): Form<LoginForm>,
) -> Response {
    let LoginForm { name, password } = form;
    let answer = app
        .helper
        .call(Ask::Login {
            name: name.clone(),
            password,
            from: address.to_string(),
        })
        .await;
    let refused = |message: String| login_form(&app, name.clone(), Some(message));
    match answer {
        Ok(Answer::SignedIn {
            session,
            must_change_password,
            scope,
            ..
        }) => signed_in_now(&session, must_change_password, scope),
        Ok(Answer::SecondFactorRequired { pending }) => {
            match cookie_header(PENDING_COOKIE, &pending) {
                Ok(cookie) => see_other("/second-factor", &[cookie]),
                Err(error) => failure(&error),
            }
        }
        Ok(Answer::SecondFactorNotEnrolled) => refused(
            "Outside the local networks this panel trusts, a second factor is required, and \
             this account has none yet. Sign in from a trusted network to set one up, or ask an \
             owner for help."
                .to_owned(),
        ),
        Ok(Answer::LocationRefused) => refused(
            "This sign-in was refused because it does not fit where this account usually signs \
             in from. An admin has been alerted."
                .to_owned(),
        ),
        Ok(Answer::SecondFactorUnavailable { reason }) => refused(format!(
            "This account's only second factor is passkeys, and passkeys cannot be used here: \
             {reason}. Sign in from a trusted network to set up the authenticator app, or ask an \
             owner for help."
        )),
        Ok(Answer::Denied) => refused("The admin name or password is wrong.".to_owned()),
        Ok(Answer::Locked { retry_after }) => refused(locked(retry_after)),
        Ok(Answer::Invalid { message }) => refused(sentence(&message)),
        Ok(other) => failure(&format!("the helper answered a sign-in with {other:?}")),
        Err(error) => failure(&error),
    }
}

/// Sets the session cookie, ends any waiting sign-in, and sends the admin
/// to the first page they must see.
fn signed_in_now(session: &str, must_change_password: bool, scope: Scope) -> Response {
    let next = landing(must_change_password, scope);
    match cookie_header(SESSION_COOKIE, session) {
        Ok(cookie) => see_other(next, &[cookie, cleared(PENDING_COOKIE)]),
        Err(error) => failure(&error),
    }
}

/// A message from the helper as a sentence on a page: capitalized, and
/// ending with a period unless it already ends a sentence.
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    let mut text: String = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    };
    if !text.ends_with(['.', '!', '?']) {
        text.push('.');
    }
    text
}

/// An authenticator key in groups of four characters, for typing by hand.
fn grouped(key: &str) -> String {
    let characters: Vec<char> = key.chars().collect();
    characters
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn locked(retry_after: u64) -> String {
    let minutes = retry_after.div_ceil(60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!("Too many failed sign-ins. Try again in {minutes} {unit}.")
}

async fn second_factor_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match cookie(&headers, PENDING_COOKIE) {
        Ok(Some(pending)) => second_factor_form(&app, &pending).await,
        Ok(None) => see_other("/login", &[]),
        Err(error) => bad_request(&error),
    }
}

/// The second-factor page for the sign-in waiting as `pending`, offering
/// the factors its account has; the sign-in page once it has ended.
async fn second_factor_form(app: &App, pending: &str) -> Response {
    let answer = app
        .helper
        .call(Ask::SecondFactorOptions {
            pending: pending.to_owned(),
        })
        .await;
    let (code, passkey) = match answer {
        Ok(Answer::SecondFactorOptions { code, passkey }) => (code, passkey),
        Ok(Answer::Denied) => return see_other("/login", &[cleared(PENDING_COOKIE)]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered a second-factor check with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let intro = match (code, passkey) {
        (true, true) => {
            "Use one of your passkeys, or enter the six-digit code from your authenticator app."
        }
        (false, true) => {
            "Use one of your passkeys. Your device asks for its PIN, fingerprint or face."
        }
        (true, false) | (false, false) => "Enter the six-digit code from your authenticator app.",
    };
    html(&SecondFactorPage {
        title: "Second factor - OpenConnect admin",
        page: app.links(),
        intro,
        code,
        passkey,
        warning: icons::WARNING,
        passkey_icon: icons::FINGERPRINT,
    })
}

/// The sign-in page with `message`, clearing the waiting sign-in's cookie:
/// a refused second factor ends the sign-in it was for.
fn start_over(app: &App, message: String) -> Response {
    let mut response = login_form(app, String::new(), Some(message));
    response
        .headers_mut()
        .append(header::SET_COOKIE, cleared(PENDING_COOKIE));
    response
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn second_factor(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let pending = match cookie(&headers, PENDING_COOKIE) {
        Ok(Some(pending)) => pending,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    let answer = app
        .helper
        .call(Ask::SecondFactor {
            pending,
            code: form.code,
        })
        .await;
    match answer {
        Ok(Answer::SignedIn {
            session,
            must_change_password,
            scope,
            ..
        }) => signed_in_now(&session, must_change_password, scope),
        Ok(Answer::Denied) => start_over(
            &app,
            "That code is not right, so this sign-in has ended. Sign in again, check that your \
             phone's clock is correct, and enter the newest code."
                .to_owned(),
        ),
        Ok(Answer::Locked { retry_after }) => start_over(&app, locked(retry_after)),
        Ok(Answer::Invalid { message }) => start_over(&app, sentence(&message)),
        Ok(other) => failure(&format!(
            "the helper answered a second factor with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// What the page's script shows when the waiting sign-in is gone.
const SIGN_IN_AGAIN: &str = "This sign-in has ended. Sign in again.";

/// A JSON answer for a page's script, setting `cookies`.
fn json_body(status: StatusCode, body: String, cookies: &[HeaderValue]) -> Response {
    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    for cookie in cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    response
}

/// Tells a page's script what went wrong: `{"error": message}`.
fn json_error(status: StatusCode, message: &str, cookies: &[HeaderValue]) -> Response {
    json_body(
        status,
        serde_json::json!({ "error": message }).to_string(),
        cookies,
    )
}

/// Tells a page's script where to go now: `{"next": location}`.
fn json_next(location: &str, cookies: &[HeaderValue]) -> Response {
    json_body(
        StatusCode::OK,
        serde_json::json!({ "next": location }).to_string(),
        cookies,
    )
}

/// The options for the browser's passkey prompt that completes the waiting
/// sign-in, for the second-factor page's script.
async fn passkey_sign_in_begin(State(app): State<App>, headers: HeaderMap) -> Response {
    let pending = match cookie(&headers, PENDING_COOKIE) {
        Ok(Some(pending)) => pending,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, SIGN_IN_AGAIN, &[]),
        Err(error) => return bad_request(&error),
    };
    let answer = app.helper.call(Ask::PasskeySignInBegin { pending }).await;
    match answer {
        Ok(Answer::PasskeyOptions { options }) => json_body(StatusCode::OK, options, &[]),
        Ok(Answer::Denied) => json_error(
            StatusCode::UNAUTHORIZED,
            SIGN_IN_AGAIN,
            &[cleared(PENDING_COOKIE)],
        ),
        Ok(Answer::Invalid { message }) => {
            json_error(StatusCode::BAD_REQUEST, &sentence(&message), &[])
        }
        Ok(other) => failure(&format!(
            "the helper answered a passkey prompt for a sign-in with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct PasskeySignInForm {
    credential: String,
}

/// Completes the waiting sign-in with the browser's answer to the passkey
/// prompt, and tells the page's script where to go.
async fn passkey_sign_in(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PasskeySignInForm>,
) -> Response {
    let pending = match cookie(&headers, PENDING_COOKIE) {
        Ok(Some(pending)) => pending,
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, SIGN_IN_AGAIN, &[]),
        Err(error) => return bad_request(&error),
    };
    let answer = app
        .helper
        .call(Ask::PasskeySignIn {
            pending,
            credential: form.credential,
        })
        .await;
    match answer {
        Ok(Answer::SignedIn {
            session,
            must_change_password,
            scope,
            ..
        }) => match cookie_header(SESSION_COOKIE, &session) {
            Ok(cookie) => json_next(
                landing(must_change_password, scope),
                &[cookie, cleared(PENDING_COOKIE)],
            ),
            Err(error) => failure(&error),
        },
        Ok(Answer::Denied) => json_error(
            StatusCode::UNAUTHORIZED,
            "The passkey was not accepted, so this sign-in has ended. Sign in again.",
            &[cleared(PENDING_COOKIE)],
        ),
        Ok(Answer::Locked { retry_after }) => json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &locked(retry_after),
            &[cleared(PENDING_COOKIE)],
        ),
        Ok(other) => failure(&format!(
            "the helper answered a passkey sign-in with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn password_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match signed_in(&app, &headers).await {
        Ok(Some(who)) => password_form(&app, &who, None),
        Ok(None) => see_other("/login", &[]),
        Err(error) => failure(&error),
    }
}

fn password_form(app: &App, who: &Who, error: Option<String>) -> Response {
    let (heading, intro) = if who.must_change_password {
        (
            "Replace your one-time password",
            "The password you signed in with works only once. Choose your own to continue.",
        )
    } else {
        (
            "Change your password",
            "Enter your current password, then the new one twice.",
        )
    };
    html(&PasswordPage {
        title: "Password - OpenConnect admin",
        page: app.links(),
        heading,
        intro,
        error,
        warning: icons::WARNING,
        csrf: who.csrf.clone(),
        min_length: app.min_password_length,
        back: who.landing() == "/",
    })
}

#[derive(Deserialize)]
struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    repeat: String,
}

async fn change_password(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    if form.new != form.repeat {
        return password_form(
            &app,
            &who,
            Some("The two new passwords are different.".to_owned()),
        );
    }
    let answer = app
        .helper
        .call(Ask::ChangePassword {
            session: who.session.clone(),
            csrf: form.csrf,
            current: form.current,
            new: form.new,
        })
        .await;
    let done = if who.landing() == "/" {
        "/account?done=password"
    } else {
        "/"
    };
    match answer {
        Ok(Answer::Done) => see_other(done, &[]),
        Ok(Answer::Denied) => password_form(
            &app,
            &who,
            Some("The current password is wrong.".to_owned()),
        ),
        Ok(Answer::Locked { retry_after }) => password_form(&app, &who, Some(locked(retry_after))),
        Ok(Answer::Invalid { message }) => password_form(&app, &who, Some(sentence(&message))),
        Ok(other) => failure(&format!(
            "the helper answered a password change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn enroll_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match signed_in(&app, &headers).await {
        Ok(Some(who)) if who.must_change_password => see_other("/password", &[]),
        Ok(Some(who)) => enroll_form(&app, &who, None).await,
        Ok(None) => see_other("/login", &[]),
        Err(error) => failure(&error),
    }
}

/// The enrollment page: the key waiting for confirmation with the form for
/// its code, or the button that issues a key.
async fn enroll_form(app: &App, who: &Who, error: Option<String>) -> Response {
    let waiting = app
        .helper
        .call(Ask::TotpPending {
            session: who.session.clone(),
        })
        .await;
    let key = match waiting {
        Ok(Answer::TotpSecret { secret, uri }) => match qr::svg(&uri) {
            Ok(qr) => Some(EnrollKey {
                qr,
                grouped: grouped(&secret),
                uri,
            }),
            Err(error) => return failure(&error),
        },
        Ok(Answer::NoTotpPending) => None,
        Ok(Answer::Denied) => return see_other("/login", &[]),
        Ok(other) => {
            return failure(&format!(
                "the helper answered an enrollment check with {other:?}"
            ));
        }
        Err(error) => return failure(&error),
    };
    let setting_up = matches!(who.scope, Scope::Enrollment);
    let passkey = setting_up && who.passkeys;
    let (title, heading, intro) = if passkey {
        (
            "Second factor - OpenConnect admin",
            "Set up a second factor",
            "Outside the networks this panel trusts, signing in takes your password and then a \
             second factor. Set up an authenticator app or add a passkey to finish signing in.",
        )
    } else if setting_up {
        (
            "Authenticator app - OpenConnect admin",
            "Set up your authenticator app",
            "Outside the networks this panel trusts, signing in takes your password and a \
             six-digit code from an authenticator app. Set one up to finish signing in.",
        )
    } else {
        (
            "Authenticator app - OpenConnect admin",
            "Set up your authenticator app",
            "Signing in from outside the networks this panel trusts takes your password and a \
             six-digit code from an authenticator app.",
        )
    };
    html(&EnrollPage {
        title,
        page: app.links(),
        heading,
        intro,
        error,
        warning: icons::WARNING,
        csrf: who.csrf.clone(),
        key,
        back: who.landing() == "/",
        passkey,
        name_chars: passkey::MAX_NAME_CHARS,
        passkey_icon: icons::FINGERPRINT,
    })
}

#[derive(Deserialize)]
struct StartForm {
    csrf: String,
}

/// Issues a key and shows it from the enrollment page, so reloading that
/// page shows the same key again.
async fn start_enrollment(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<StartForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::TotpBegin {
            session: who.session.clone(),
            csrf: form.csrf,
        })
        .await;
    match answer {
        Ok(Answer::TotpSecret { .. }) => see_other("/enroll", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => enroll_form(&app, &who, Some(sentence(&message))).await,
        Ok(other) => failure(&format!(
            "the helper answered an enrollment start with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

#[derive(Deserialize)]
struct EnrollForm {
    csrf: String,
    code: String,
}

async fn confirm_enrollment(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<EnrollForm>,
) -> Response {
    let who = match signed_in(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = app
        .helper
        .call(Ask::TotpConfirm {
            session: who.session.clone(),
            csrf: form.csrf,
            code: form.code,
        })
        .await;
    match answer {
        Ok(Answer::Done) if who.landing() == "/" => see_other("/account?done=app", &[]),
        Ok(Answer::Done) => see_other("/", &[]),
        Ok(Answer::Denied) => see_other("/login", &[]),
        Ok(Answer::Invalid { message }) => enroll_form(&app, &who, Some(sentence(&message))).await,
        Ok(other) => failure(&format!(
            "the helper answered an enrollment confirmation with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    match cookie(&headers, SESSION_COOKIE) {
        Ok(Some(session)) => match app.helper.call(Ask::Logout { session }).await {
            Ok(Answer::Done | Answer::Denied) => {}
            Ok(other) => return failure(&format!("the helper answered a sign-out with {other:?}")),
            Err(error) => return failure(&error),
        },
        Ok(None) => {}
        Err(error) => return bad_request(&error),
    }
    see_other(
        "/login",
        &[cleared(SESSION_COOKIE), cleared(PENDING_COOKIE)],
    )
}

#[derive(Template)]
#[template(path = "portal_login.html")]
struct PortalLoginPage {
    title: &'static str,
    page: PageLinks,
    host: String,
    error: Option<String>,
    name: String,
    warning: &'static str,
    /// Whether the page asks for the code rather than the password.
    code_step: bool,
}

/// The header above every page of a signed-in portal session.
struct PortalBar {
    host: String,
    user: String,
    /// The page shown: "/" or "/account".
    current: &'static str,
    sun: &'static str,
    sign_out: &'static str,
}

fn portal_bar(app: &App, user: String, current: &'static str) -> PortalBar {
    PortalBar {
        host: app.host.clone(),
        user,
        current,
        sun: icons::SUN,
        sign_out: icons::SIGN_OUT,
    }
}

#[derive(Template)]
#[template(path = "portal_home.html")]
struct PortalHomePage {
    title: &'static str,
    page: PageLinks,
    bar: PortalBar,
    icons: KitIcons,
    notice: Option<Notice>,
    csrf: String,
    /// Whether the VPN asks for codes and the user has no key.
    needs_key: bool,
    address: String,
    pin: String,
    codes: bool,
    groups_label: &'static str,
    groups: String,
    setup: Setup,
}

#[derive(Template)]
#[template(path = "portal_key.html")]
struct PortalKeyPage {
    title: &'static str,
    page: PageLinks,
    intro: &'static str,
    error: Option<String>,
    warning: &'static str,
    csrf: String,
    key: Option<EnrollKey>,
    /// Whether the page offers to issue a key.
    start: bool,
    /// Whether the session has the full portal, so the page links back to
    /// it rather than offering only to sign out.
    back: bool,
}

#[derive(Template)]
#[template(path = "portal_account.html")]
struct PortalAccountPage {
    title: &'static str,
    page: PageLinks,
    bar: PortalBar,
    notice: Option<Notice>,
    csrf: String,
    /// Whether the sign-in is recent enough to change the password.
    recent: bool,
    min_length: usize,
    /// Whether the VPN asks for codes, and whether the user has a key.
    codes: bool,
    has_key: bool,
    rows: Vec<PortalSessionRow>,
    key_icon: &'static str,
    phone_icon: &'static str,
    plugs_icon: &'static str,
}

/// One of the user's own VPN sessions, as the account page shows it.
struct PortalSessionRow {
    id: u64,
    client: String,
    vpn: Vec<String>,
    remote: String,
    connected: String,
    /// Whether the browser reached the portal through this session.
    here: bool,
}

/// A VPN user's portal session, as the helper describes it.
struct PortalWho {
    session: String,
    scope: PortalScope,
}

/// Asks the helper a portal request. A failure inside the helper comes back
/// as an error.
async fn portal_call(app: &App, request: PortalRequest) -> Result<PortalResponse, String> {
    match app.helper.call(Ask::Portal { request }).await? {
        Answer::Portal {
            response: PortalResponse::Error { message },
        } => Err(message),
        Answer::Portal { response } => Ok(response),
        other => Err(format!(
            "the helper answered a portal request with {other:?}"
        )),
    }
}

/// The VPN user a request's portal cookie belongs to, or none when there is
/// no session or it has ended.
async fn portal_who(app: &App, headers: &HeaderMap) -> Result<Option<PortalWho>, String> {
    let Some(session) = cookie(headers, PORTAL_COOKIE)? else {
        return Ok(None);
    };
    match portal_call(
        app,
        PortalRequest::Whoami {
            session: session.clone(),
        },
    )
    .await?
    {
        PortalResponse::User { scope, .. } => Ok(Some(PortalWho { session, scope })),
        PortalResponse::Denied => Ok(None),
        other => Err(format!(
            "the helper answered a portal session check with {other:?}"
        )),
    }
}

fn portal_login_form(app: &App, name: String, error: Option<String>, code_step: bool) -> Response {
    html(&PortalLoginPage {
        title: "Sign in - OpenConnect VPN",
        page: app.links(),
        host: app.host.clone(),
        error,
        name,
        warning: icons::WARNING,
        code_step,
    })
}

async fn portal_login_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match portal_who(&app, &headers).await {
        Ok(Some(_signed_in)) => see_other("/", &[]),
        Ok(None) => portal_login_form(&app, String::new(), None, false),
        Err(error) => failure(&error),
    }
}

/// Sets the portal session cookie, ends any waiting sign-in, and sends the
/// user to the home page.
fn portal_signed_in(session: &str) -> Response {
    match cookie_header(PORTAL_COOKIE, session) {
        Ok(cookie) => see_other("/", &[cookie, cleared(PORTAL_PENDING_COOKIE)]),
        Err(error) => failure(&error),
    }
}

async fn portal_login(
    State(app): State<App>,
    Extension(Peer(address)): Extension<Peer>,
    Form(form): Form<LoginForm>,
) -> Response {
    let LoginForm { name, password } = form;
    let answer = portal_call(
        &app,
        PortalRequest::Login {
            name: name.clone(),
            password,
            code: None,
            from: address.to_string(),
        },
    )
    .await;
    let refused = |message: String| portal_login_form(&app, name.clone(), Some(message), false);
    match answer {
        Ok(PortalResponse::SignedIn { session, .. }) => portal_signed_in(&session),
        Ok(PortalResponse::CodeRequired { pending }) => {
            match cookie_header(PORTAL_PENDING_COOKIE, &pending) {
                Ok(cookie) => see_other("/code", &[cookie]),
                Err(error) => failure(&error),
            }
        }
        Ok(PortalResponse::Denied) => {
            refused("That user name and password did not sign in.".to_owned())
        }
        Ok(PortalResponse::Locked { retry_after }) => refused(locked(retry_after)),
        Ok(PortalResponse::Invalid { message }) => refused(sentence(&message)),
        Ok(other) => failure(&format!(
            "the helper answered a portal sign-in with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn portal_code_page(State(app): State<App>, headers: HeaderMap) -> Response {
    match cookie(&headers, PORTAL_PENDING_COOKIE) {
        Ok(Some(_pending)) => portal_login_form(&app, String::new(), None, true),
        Ok(None) => see_other("/login", &[]),
        Err(error) => bad_request(&error),
    }
}

/// Completes a sign-in with its code. Any refusal ends the waiting sign-in,
/// so the user starts again with the password.
async fn portal_code(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let pending = match cookie(&headers, PORTAL_PENDING_COOKIE) {
        Ok(Some(pending)) => pending,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    let answer = portal_call(
        &app,
        PortalRequest::Code {
            pending,
            code: form.code,
        },
    )
    .await;
    let restart = |message: String| {
        let mut response = portal_login_form(&app, String::new(), Some(message), false);
        response
            .headers_mut()
            .append(header::SET_COOKIE, cleared(PORTAL_PENDING_COOKIE));
        response
    };
    match answer {
        Ok(PortalResponse::SignedIn { session, .. }) => portal_signed_in(&session),
        Ok(PortalResponse::Denied) => {
            restart("That code did not sign in. Sign in again with your password.".to_owned())
        }
        Ok(PortalResponse::Locked { retry_after }) => restart(locked(retry_after)),
        Ok(PortalResponse::Invalid { message }) => restart(sentence(&message)),
        Ok(other) => failure(&format!("the helper answered a portal code with {other:?}")),
        Err(error) => failure(&error),
    }
}

/// The portal's home page: the connection details and client setup, or for
/// a session that may only set up a key, the page that sets one up.
async fn portal_home(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<DoneQuery>,
) -> Response {
    let session = match cookie(&headers, PORTAL_COOKIE) {
        Ok(Some(session)) => session,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    match portal_call(&app, PortalRequest::Home { session }).await {
        Ok(PortalResponse::Home {
            scope: PortalScope::EnrollKey,
            csrf,
            ..
        }) => portal_key_view(&app, csrf, PortalScope::EnrollKey, None, None, true),
        Ok(PortalResponse::Home {
            user,
            csrf,
            kit: Some(kit),
            needs_key,
            ..
        }) => {
            let notice = (query.done.as_deref() == Some("key")).then(|| {
                Notice::done(
                    "Your authenticator app is set up. The VPN asks for its code after your \
                     password.",
                )
            });
            let (groups_label, groups) = groups_of(&kit);
            html(&PortalHomePage {
                title: "Connect - OpenConnect VPN",
                page: app.links(),
                bar: portal_bar(&app, user, "/"),
                icons: kit_icons(),
                notice,
                csrf,
                needs_key,
                address: kit.address.clone(),
                pin: kit.pin.clone(),
                codes: kit.codes,
                groups_label,
                groups,
                setup: setup_of(&kit, "your"),
            })
        }
        Ok(PortalResponse::Denied) => see_other("/login", &[cleared(PORTAL_COOKIE)]),
        Ok(other) => failure(&format!(
            "the helper answered the portal's home page with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The page that sets up an authenticator key: the issued key with the form
/// for its code, or the button that issues one.
fn portal_key_view(
    app: &App,
    csrf: String,
    scope: PortalScope,
    key: Option<&Authenticator>,
    error: Option<String>,
    start: bool,
) -> Response {
    let key = match key.map(enroll_key).transpose() {
        Ok(key) => key,
        Err(error) => return failure(&error),
    };
    let intro = match scope {
        PortalScope::EnrollKey => {
            "The VPN asks for a six-digit code from an authenticator app after your password, \
             and you have no authenticator key yet. Set one up to connect."
        }
        PortalScope::Full => {
            "The VPN asks for a six-digit code from an authenticator app after your password. \
             Set one up before you connect."
        }
    };
    html(&PortalKeyPage {
        title: "Authenticator app - OpenConnect VPN",
        page: app.links(),
        intro,
        error,
        warning: icons::WARNING,
        csrf,
        key,
        start,
        back: matches!(scope, PortalScope::Full),
    })
}

#[derive(Deserialize)]
struct KeyForm {
    csrf: String,
    /// A code from the current key, when the form replaces it.
    old_code: Option<String>,
}

/// Issues a key and shows it with the form for its first code. A refused
/// replacement goes back to the account page with the reason.
async fn portal_key_begin(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<KeyForm>,
) -> Response {
    let who = match portal_who(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let replacing = form.old_code.is_some();
    let answer = portal_call(
        &app,
        PortalRequest::KeyBegin {
            session: who.session.clone(),
            csrf: form.csrf.clone(),
            old_code: form.old_code,
        },
    )
    .await;
    match answer {
        Ok(PortalResponse::Key { authenticator, .. }) => portal_key_view(
            &app,
            form.csrf,
            who.scope,
            Some(&authenticator),
            None,
            false,
        ),
        Ok(PortalResponse::Denied) => see_other("/login", &[]),
        Ok(PortalResponse::Locked { retry_after }) => portal_locked_out(&app, retry_after),
        Ok(PortalResponse::Invalid { message }) if replacing => {
            portal_account_page(&app, who.session, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(PortalResponse::Invalid { message }) => portal_key_view(
            &app,
            form.csrf,
            who.scope,
            None,
            Some(sentence(&message)),
            false,
        ),
        Ok(other) => failure(&format!(
            "the helper answered a portal key request with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn portal_key_confirm(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<EnrollForm>,
) -> Response {
    let who = match portal_who(&app, &headers).await {
        Ok(Some(who)) => who,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return failure(&error),
    };
    let answer = portal_call(
        &app,
        PortalRequest::KeyConfirm {
            session: who.session,
            csrf: form.csrf.clone(),
            code: form.code,
        },
    )
    .await;
    match answer {
        Ok(PortalResponse::Done) => match who.scope {
            PortalScope::EnrollKey => see_other("/?done=key", &[]),
            PortalScope::Full => see_other("/account?done=key", &[]),
        },
        Ok(PortalResponse::Key { authenticator, .. }) => portal_key_view(
            &app,
            form.csrf,
            who.scope,
            Some(&authenticator),
            Some(
                "That code does not match the new key. Check that your phone's clock is right \
                 and enter the newest code."
                    .to_owned(),
            ),
            false,
        ),
        Ok(PortalResponse::Denied) => see_other("/login", &[]),
        Ok(PortalResponse::Invalid { message }) => portal_key_view(
            &app,
            form.csrf,
            who.scope,
            None,
            Some(sentence(&message)),
            true,
        ),
        Ok(other) => failure(&format!(
            "the helper answered a portal key confirmation with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

/// The sign-in page after a wrong proof locked the user out, which ended
/// their portal sessions.
fn portal_locked_out(app: &App, retry_after: u64) -> Response {
    let mut response = portal_login_form(app, String::new(), Some(locked(retry_after)), false);
    response
        .headers_mut()
        .append(header::SET_COOKIE, cleared(PORTAL_COOKIE));
    response
}

/// The account page of the portal session `session`, with `notice` above
/// it. A session that may only set up a key goes to that page instead.
async fn portal_account_page(app: &App, session: String, notice: Option<Notice>) -> Response {
    let now = match clock::now() {
        Ok(now) => now,
        Err(error) => return failure(&error),
    };
    match portal_call(app, PortalRequest::Account { session }).await {
        Ok(PortalResponse::Account {
            user,
            csrf,
            codes,
            has_key,
            recent,
            sessions,
            this_session,
        }) => {
            let rows = sessions
                .iter()
                .map(|vpn| {
                    let row = session_row(vpn, now, &Places::none(), &app.assets);
                    PortalSessionRow {
                        id: row.id,
                        client: row.client,
                        vpn: row.vpn,
                        remote: row.remote,
                        connected: row.connected,
                        here: this_session == Some(vpn.id),
                    }
                })
                .collect();
            html(&PortalAccountPage {
                title: "Account - OpenConnect VPN",
                page: app.links(),
                bar: portal_bar(app, user, "/account"),
                notice,
                csrf,
                recent,
                min_length: app.min_password_length,
                codes,
                has_key,
                rows,
                key_icon: icons::SHIELD_STAR,
                phone_icon: icons::PHONE,
                plugs_icon: icons::PLUGS,
            })
        }
        Ok(PortalResponse::Invalid { .. }) => see_other("/", &[]),
        Ok(PortalResponse::Denied) => see_other("/login", &[cleared(PORTAL_COOKIE)]),
        Ok(other) => failure(&format!(
            "the helper answered the portal's account page with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn portal_account(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<DoneQuery>,
) -> Response {
    let session = match cookie(&headers, PORTAL_COOKIE) {
        Ok(Some(session)) => session,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    let notice = match query.done.as_deref() {
        Some("password") => Some(Notice::done(
            "Your password is changed. Your other VPN connections are disconnected; connect them \
             again with the new password.",
        )),
        Some("ended") => Some(Notice::done("That VPN connection is disconnected.")),
        Some("key") => Some(Notice::done(
            "Your new authenticator key is on. The VPN asks for its codes from now on.",
        )),
        Some(_) | None => None,
    };
    portal_account_page(&app, session, notice).await
}

#[derive(Deserialize)]
struct PortalPasswordForm {
    csrf: String,
    current: String,
    new: String,
    repeat: String,
}

async fn portal_change_password(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<PortalPasswordForm>,
) -> Response {
    let session = match cookie(&headers, PORTAL_COOKIE) {
        Ok(Some(session)) => session,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    if form.new != form.repeat {
        let different = Notice::refused("The two new passwords are different.".to_owned());
        return portal_account_page(&app, session, Some(different)).await;
    }
    let answer = portal_call(
        &app,
        PortalRequest::ChangePassword {
            session: session.clone(),
            csrf: form.csrf,
            current: form.current,
            new: form.new,
        },
    )
    .await;
    match answer {
        Ok(PortalResponse::Done) => see_other("/account?done=password", &[]),
        Ok(PortalResponse::Invalid { message }) => {
            portal_account_page(&app, session, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(PortalResponse::Locked { retry_after }) => portal_locked_out(&app, retry_after),
        Ok(PortalResponse::Denied) => see_other("/login", &[cleared(PORTAL_COOKIE)]),
        Ok(other) => failure(&format!(
            "the helper answered a portal password change with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn portal_end_session(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<EndForm>,
) -> Response {
    let session = match cookie(&headers, PORTAL_COOKIE) {
        Ok(Some(session)) => session,
        Ok(None) => return see_other("/login", &[]),
        Err(error) => return bad_request(&error),
    };
    let answer = portal_call(
        &app,
        PortalRequest::EndSession {
            session: session.clone(),
            csrf: form.csrf,
            id: form.id,
        },
    )
    .await;
    match answer {
        Ok(PortalResponse::Done) => see_other("/account?done=ended", &[]),
        Ok(PortalResponse::Invalid { message }) => {
            portal_account_page(&app, session, Some(Notice::refused(sentence(&message)))).await
        }
        Ok(PortalResponse::Denied) => see_other("/login", &[cleared(PORTAL_COOKIE)]),
        Ok(other) => failure(&format!(
            "the helper answered a portal disconnect with {other:?}"
        )),
        Err(error) => failure(&error),
    }
}

async fn portal_logout(State(app): State<App>, headers: HeaderMap) -> Response {
    match cookie(&headers, PORTAL_COOKIE) {
        Ok(Some(session)) => match portal_call(&app, PortalRequest::Logout { session }).await {
            Ok(PortalResponse::Done | PortalResponse::Denied) => {}
            Ok(other) => {
                return failure(&format!(
                    "the helper answered a portal sign-out with {other:?}"
                ));
            }
            Err(error) => return failure(&error),
        },
        Ok(None) => {}
        Err(error) => return bad_request(&error),
    }
    see_other(
        "/login",
        &[cleared(PORTAL_COOKIE), cleared(PORTAL_PENDING_COOKIE)],
    )
}

async fn asset(State(app): State<App>, Path(name): Path<String>) -> Response {
    let Some(asset) = app.assets.get(&name) else {
        return not_found().await;
    };
    let mut response = asset.bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}

async fn not_found() -> Response {
    plain(StatusCode::NOT_FOUND, "There is no page at this address.")
}

/// The admin a request's session cookie belongs to, or none when there is no
/// session or it has ended.
async fn signed_in(app: &App, headers: &HeaderMap) -> Result<Option<Who>, String> {
    let Some(session) = cookie(headers, SESSION_COOKIE)? else {
        return Ok(None);
    };
    match app
        .helper
        .call(Ask::Whoami {
            session: session.clone(),
        })
        .await?
    {
        Answer::Admin {
            name,
            role,
            scope,
            csrf,
            must_change_password,
            passkeys,
            ..
        } => Ok(Some(Who {
            session,
            name,
            role,
            scope,
            csrf,
            must_change_password,
            passkeys,
        })),
        Answer::Denied => Ok(None),
        other => Err(format!(
            "the helper answered a session check with {other:?}"
        )),
    }
}

/// Refuses requests for another host and forms from another origin, and adds
/// the security headers to every response.
async fn guard(State(app): State<App>, request: Request, next: Next) -> Response {
    let mut response = match refusal(&app, request.method(), request.headers()) {
        None => next.run(request).await,
        Some(refused) => refused,
    };
    secure(response.headers_mut(), app.scheme == "https");
    response
}

/// The answer to a request for another host or a form from another origin,
/// or none for a request the pages may answer.
fn refusal(app: &App, method: &Method, headers: &HeaderMap) -> Option<Response> {
    let host = match header_text(headers, &header::HOST) {
        Ok(Some(host)) => host,
        Ok(None) => return Some(bad_request("the request names no host")),
        Err(error) => return Some(bad_request(&error)),
    };
    let known = std::iter::once(&app.host)
        .chain(&app.other_hosts)
        .any(|expected| host_matches(host, expected));
    if !known {
        return Some(plain(
            StatusCode::MISDIRECTED_REQUEST,
            &format!("This {} answers only at {}.", app.site, app.host),
        ));
    }
    if method == Method::POST {
        let expected = format!("{}://{host}", app.scheme);
        let origin = match header_text(headers, &header::ORIGIN) {
            Ok(origin) => origin,
            Err(error) => return Some(bad_request(&error)),
        };
        let site = match header_text(headers, &HeaderName::from_static("sec-fetch-site")) {
            Ok(site) => site,
            Err(error) => return Some(bad_request(&error)),
        };
        let same_origin = origin.is_some_and(|origin| origin.eq_ignore_ascii_case(&expected));
        let same_site = site.is_none_or(|site| site == "same-origin" || site == "none");
        if !same_origin || !same_site {
            return Some(plain(
                StatusCode::FORBIDDEN,
                "Forms are accepted only from the panel's own pages.",
            ));
        }
    }
    None
}

/// Whether a Host header names `expected`, with or without a port.
fn host_matches(value: &str, expected: &str) -> bool {
    if value.eq_ignore_ascii_case(expected) {
        return true;
    }
    match (value.get(..expected.len()), value.get(expected.len()..)) {
        (Some(name), Some(rest)) => {
            name.eq_ignore_ascii_case(expected)
                && rest.len() > 1
                && rest.starts_with(':')
                && rest[1..].bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

fn secure(headers: &mut HeaderMap, https: bool) {
    let fixed: [(HeaderName, &'static str); 7] = [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        // Other sites get no referrer. Under no-referrer, browsers would also
        // send `Origin: null` with every form, which the origin check refuses.
        (header::REFERRER_POLICY, "same-origin"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    if https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

/// A header's value as text: none when it is absent, an error when it is
/// not plain text.
fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>, String> {
    match headers.get(name) {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .map(Some)
            .map_err(|error| format!("the {name} header is not plain text: {error}")),
    }
}

/// The value of the cookie `name`, from every Cookie header.
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let text = value
            .to_str()
            .map_err(|error| format!("a Cookie header is not plain text: {error}"))?;
        for pair in text.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=')
                && key == name
                && !value.is_empty()
            {
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}

fn cookie_header(name: &str, value: &str) -> Result<HeaderValue, String> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict"
    ))
    .map_err(|error| format!("the {name} cookie could not be set: {error}"))
}

fn cleared(name: &'static str) -> HeaderValue {
    match name {
        SESSION_COOKIE => HeaderValue::from_static(
            "__Host-ocpanel=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
        PORTAL_COOKIE => HeaderValue::from_static(
            "__Host-ocportal=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
        PORTAL_PENDING_COOKIE => HeaderValue::from_static(
            "__Host-ocportal-pending=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
        _ => HeaderValue::from_static(
            "__Host-ocpanel-pending=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    }
}

/// A redirect to a location built from a user or group name, which holds
/// only letters, digits and `._@+-`.
fn see_other_to(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(error) => failure(&format!(
            "the address {location} is not a header value: {error}"
        )),
    }
}

fn see_other(location: &'static str, cookies: &[HeaderValue]) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, HeaderValue::from_static(location));
    for cookie in cookies {
        headers.append(header::SET_COOKIE, cookie.clone());
    }
    response
}

fn html(template: &impl Template) -> Response {
    match template.render() {
        Ok(body) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response(),
        Err(error) => failure(&format!("a page could not be built: {error}")),
    }
}

fn plain(status: StatusCode, text: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text.to_owned(),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    plain(
        StatusCode::BAD_REQUEST,
        &format!("The request is not valid: {message}."),
    )
}

fn failure(message: &str) -> Response {
    eprintln!("ocpanel web: {message}");
    plain(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("The panel could not finish this request: {message}."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_match_with_or_without_a_port() {
        assert!(host_matches("vpn.example.com", "vpn.example.com"));
        assert!(host_matches("VPN.example.com:8443", "vpn.example.com"));
        assert!(host_matches("[fd3e::1]:8443", "[fd3e::1]"));
        assert!(!host_matches("vpn.example.com.evil", "vpn.example.com"));
        assert!(!host_matches("vpn.example.com:", "vpn.example.com"));
        assert!(!host_matches("vpn.example.com:84a3", "vpn.example.com"));
        assert!(!host_matches("evil.com", "vpn.example.com"));
    }

    #[test]
    fn cookies_are_read_from_every_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-ocpanel=tok"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("b=2"));
        assert_eq!(
            cookie(&headers, SESSION_COOKIE).unwrap(),
            Some("tok".to_owned())
        );
        assert_eq!(cookie(&headers, PENDING_COOKIE).unwrap(), None);
    }

    #[test]
    fn helper_messages_read_as_sentences() {
        assert_eq!(
            sentence("the password must be at least 12 characters long"),
            "The password must be at least 12 characters long."
        );
        assert_eq!(sentence("already a sentence."), "Already a sentence.");
        assert_eq!(sentence("é first"), "É first.");
        assert_eq!(sentence(""), ".");
    }

    #[test]
    fn audit_rows_show_the_time_in_utc_until_the_script_runs() {
        let row = audit_row(Record {
            time: "2026-11-26T12:30:05Z".to_owned(),
            actor: "alex".to_owned(),
            from: "192.168.1.20".to_owned(),
            action: "vpn.user.lock".to_owned(),
            result: Outcome::Denied,
            detail: "viewers cannot change the server".to_owned(),
        });
        assert_eq!(row.clock, "2026-11-26 12:30:05");
        assert_eq!(row.stamp, "2026-11-26T12:30:05Z");
        assert_eq!((row.result, row.result_class), ("Denied", "pill-bad"));
        assert_eq!(row.detail, "Viewers cannot change the server");
        assert_eq!(row.actor_note, None);
    }

    #[test]
    fn names_longer_than_any_account_are_shortened_on_the_audit_page() {
        let row = audit_row(Record {
            time: "2026-11-26T12:30:05Z".to_owned(),
            actor: "\u{e9}".repeat(3000),
            from: "203.0.113.9".to_owned(),
            action: "login".to_owned(),
            result: Outcome::Denied,
            detail: "not an admin name".to_owned(),
        });
        assert_eq!(row.actor.chars().count(), store::MAX_NAME_LEN + 1);
        assert!(row.actor.ends_with('\u{2026}'));
        assert_eq!(
            row.actor_note.as_deref(),
            Some("Shortened from 3000 characters")
        );
    }

    fn admin(name: &str, role: Role) -> AdminSummary {
        AdminSummary {
            name: name.to_owned(),
            role,
            second_factor: false,
            authenticator_app: false,
            passkeys: 0,
            must_change_password: false,
            locked_until: None,
            created: 0,
            last_login: None,
            vacation_until: None,
        }
    }

    #[test]
    fn the_admins_summary_counts_each_role_in_words() {
        assert_eq!(admins_summary(&[admin("a", Role::Owner)]), "1 owner");
        assert_eq!(
            admins_summary(&[
                admin("a", Role::Owner),
                admin("b", Role::Owner),
                admin("c", Role::Viewer)
            ]),
            "2 owners and 1 viewer"
        );
        assert_eq!(
            admins_summary(&[
                admin("a", Role::Viewer),
                admin("b", Role::Operator),
                admin("c", Role::Owner)
            ]),
            "1 owner, 1 operator and 1 viewer"
        );
    }

    #[test]
    fn admin_rows_show_lockouts_one_time_passwords_and_the_signed_in_admin() {
        let mut locked = admin("sam", Role::Operator);
        locked.locked_until = Some(1000 + 600);
        locked.must_change_password = true;
        let row = admin_row(locked, "alex", 1000);
        assert_eq!(
            (row.status, row.locked, row.is_self),
            ("Locked", true, false)
        );
        assert_eq!(row.status_note.as_deref(), Some("Lifts in 10 minutes"));
        let mut fresh = admin("alex", Role::Owner);
        fresh.must_change_password = true;
        let row = admin_row(fresh, "alex", 1000);
        assert_eq!((row.status, row.is_self), ("One-time password", true));
        assert_eq!(row.last_login.map(|last| last.text), None);
        assert_eq!(row.added.text, "1970-01-01 00:00:00");
        assert_eq!(role_of(row.role_value), Some(Role::Owner));
    }

    #[test]
    fn certificate_cards_warn_before_and_after_expiry() {
        let entry = |not_after| CertificateEntry {
            role: "VPN server".to_owned(),
            path: "/config/certs/server-cert.pem".to_owned(),
            facts: Some(crate::kit::Facts {
                subject: "vpn.example.com".to_owned(),
                issuer: "VPN CA".to_owned(),
                names: vec!["vpn.example.com".to_owned()],
                not_before: 0,
                not_after,
                pin: "pin-sha256:x".to_owned(),
            }),
            problem: None,
        };
        let now = 1_000_000_000;
        let card = certificate_card(entry(now + 400 * 86_400), now);
        assert_eq!(
            (card.left.as_deref(), card.left_class),
            (Some("Expires in 400 days"), "pill-ok")
        );
        assert_eq!(card.pin.as_deref(), Some("pin-sha256:x"));
        let card = certificate_card(entry(now + 86_400 + 5), now);
        assert_eq!(
            (card.left.as_deref(), card.left_class),
            (Some("Expires in 1 day"), "pill-warn")
        );
        let card = certificate_card(entry(now - 3 * 86_400), now);
        assert_eq!(
            (card.left.as_deref(), card.left_class),
            (Some("Expired 3 days ago"), "pill-bad")
        );
    }

    #[test]
    fn a_choice_keeps_a_current_value_it_does_not_list() {
        let listed = setting_choices(&[("all", "Every network")], "all");
        assert_eq!((listed.len(), listed[0].selected), (1, true));
        let unlisted = setting_choices(&[("0", "Default"), ("2", "Information")], "5");
        assert_eq!(unlisted.len(), 3);
        assert!(unlisted[2].selected && unlisted[2].value == "5");
        assert!(!unlisted[0].selected && !unlisted[1].selected);
    }

    #[test]
    fn keys_are_grouped_by_four() {
        assert_eq!(grouped("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP");
        assert_eq!(grouped("JBSWY3"), "JBSW Y3");
        assert_eq!(grouped(""), "");
    }

    #[test]
    fn lengths_of_time_read_in_words() {
        assert_eq!(span(0), "less than a minute");
        assert_eq!(span(59), "less than a minute");
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(12 * 60 + 30), "12 minutes");
        assert_eq!(span(3600), "1 hour");
        assert_eq!(span(2 * 3600 + 3 * 60), "2 hours and 3 minutes");
        assert_eq!(span(86_400 + 59 * 60), "1 day");
        assert_eq!(span(3 * 86_400 + 4 * 3600 + 5 * 60), "3 days and 4 hours");
    }

    #[test]
    fn the_ban_policy_reads_as_sentences() {
        let policy = BanPolicy {
            max_score: 80,
            ban_seconds: 300,
            reset_seconds: 1200,
            wrong_password_points: 10,
            connection_points: 1,
        };
        assert_eq!(
            ban_policy(&policy),
            "An address is banned for 5 minutes when its points reach 80. A wrong password adds \
             10 points and each connection 1 point; points start over after 20 minutes."
        );
        let off = BanPolicy {
            max_score: 0,
            ..policy
        };
        assert!(ban_policy(&off).starts_with("Bans are off"));
    }

    #[test]
    fn points_rows_leave_out_bans_and_cleared_addresses() {
        let policy = BanPolicy {
            max_score: 80,
            ban_seconds: 300,
            reset_seconds: 1200,
            wrong_password_points: 10,
            connection_points: 1,
        };
        let entry = |address: &str, score| BanPoints {
            address: address.to_owned(),
            score,
        };
        let points = [
            entry("192.0.2.1", 92),
            entry("192.0.2.2", 0),
            entry("192.0.2.3", 20),
            entry("192.0.2.4", 60),
        ];
        let banned = [Ban {
            address: "192.0.2.1".to_owned(),
            score: 92,
            lifts_in: Some(60),
        }];
        let rows = points_rows(&points, &banned, &policy);
        let shown: Vec<(&str, u64)> = rows
            .iter()
            .map(|row| (row.address.as_str(), row.share))
            .collect();
        assert_eq!(shown, [("192.0.2.4", 75), ("192.0.2.3", 25)]);
    }

    #[test]
    fn each_inherited_value_names_where_it_comes_from() {
        let server = Overrides {
            routes: vec!["default".to_owned()],
            dns: vec!["9.9.9.9".to_owned()],
            ..Overrides::default()
        };
        let staff = Overrides {
            routes: vec!["10.20.0.0/16".to_owned()],
            download: Some(6_250_000),
            ..Overrides::default()
        };
        let from_staff = inherits(Some("staff"), Some(&staff), &server);
        assert_eq!(from_staff.routes, "10.20.0.0/16, from the group staff");
        assert_eq!(from_staff.dns, "9.9.9.9, from the server");
        assert_eq!(from_staff.download, "50 Mbps, from the group staff");
        assert_eq!(from_staff.upload, "no limit, from the server");
        assert_eq!(
            from_staff.restrict,
            "not held to its routes, from the server"
        );
        assert_eq!(
            inherits(None, None, &server).routes,
            "every network, from the server"
        );
        assert_eq!(
            inherits(Some("staff"), None, &server).dns,
            "9.9.9.9, from the server"
        );
    }

    #[test]
    fn bandwidth_carries_its_unit_symbol() {
        assert_eq!(bandwidth_text(None, None), "No limit");
        assert_eq!(
            bandwidth_text(Some(6_250_000), Some(1_250_000)),
            "Down 50 Mbps, up 10 Mbps"
        );
        assert_eq!(
            bandwidth_text(None, Some(125_000)),
            "Up 1 Mbps; no download limit"
        );
        assert_eq!(
            bandwidth_text(Some(62_500), None),
            "Down 0.5 Mbps; no upload limit"
        );
    }

    #[test]
    fn a_rule_end_is_its_choice_or_the_network_typed_beside_it() {
        let network = |text: &str| Network::parse(text).map(End::Network);
        assert_eq!(chosen_end("clients", "", "From"), Ok(End::Clients));
        assert_eq!(
            chosen_end("group:staff", " ", "To"),
            Ok(End::Group("staff".to_owned()))
        );
        assert_eq!(
            chosen_end("network:10.10.0.0/24", "", "To"),
            network("10.10.0.0/24")
        );
        assert_eq!(
            chosen_end("other", " 10.30.0.0/24 ", "From"),
            network("10.30.0.0/24")
        );
        assert_eq!(
            chosen_end("other", "", "From"),
            Err("From is set to another network, but no network is typed".to_owned())
        );
        assert_eq!(
            chosen_end("clients", "10.30.0.0/24", "From"),
            Err("a network is typed for From, but From is not set to another network".to_owned())
        );
        assert!(chosen_end("other", "10.30.0.0/33", "To").is_err());
        assert_eq!(
            chosen_end("everyone", "", "To"),
            Err("'everyone' is not a choice for To".to_owned())
        );
    }

    #[test]
    fn the_rule_form_offers_groups_only_where_the_firewall_follows_them() {
        let view = SitesView {
            rules: Vec::new(),
            sites: vec![Site {
                owner: Owner::User,
                name: "branch".to_owned(),
                networks: vec!["10.10.0.0/24".to_owned()],
                egress: false,
                connected: true,
            }],
            groups: vec!["staff".to_owned()],
            checked: true,
            iptables: false,
            client_to_client: false,
            split: false,
        };
        assert_eq!(end_text(&End::Clients, &view.sites), "Every VPN client");
        assert_eq!(
            chosen_end("network:10.10.0.0/24", "", "To").map(|end| end_text(&end, &view.sites)),
            Ok("10.10.0.0/24 behind branch".to_owned())
        );
        let ends = end_pickers(&view, None);
        assert!(ends[0].clients && ends[0].clients_selected && !ends[1].clients);
        assert!(ends[1].networks[0].selected);
        assert_eq!(ends[1].networks[0].label, "10.10.0.0/24 behind branch");
        assert_eq!(ends[1].groups[0].value, "group:staff");
        let kept = SiteRuleForm {
            csrf: String::new(),
            from: "other".to_owned(),
            from_network: "10.30.0.0/24".to_owned(),
            to: "group:staff".to_owned(),
            to_network: String::new(),
        };
        let ends = end_pickers(&view, Some(&kept));
        assert!(ends[0].other && !ends[0].clients_selected);
        assert_eq!(ends[0].typed, "10.30.0.0/24");
        assert!(ends[1].groups[0].selected && !ends[1].networks[0].selected);
        assert!(site_notes(&view).is_empty());
        let iptables = SitesView {
            iptables: true,
            ..view
        };
        assert!(
            end_pickers(&iptables, None)
                .iter()
                .all(|end| end.groups.is_empty())
        );
        assert_eq!(site_notes(&iptables).len(), 1);
    }

    #[test]
    fn lockout_wording_rounds_up_to_whole_minutes() {
        assert_eq!(
            locked(1),
            "Too many failed sign-ins. Try again in 1 minute."
        );
        assert_eq!(
            locked(61),
            "Too many failed sign-ins. Try again in 2 minutes."
        );
    }
}
