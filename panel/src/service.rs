//! The helper's decisions: who may sign in and with what, and what a session
//! may do. Nothing here touches sockets or processes, so every rule is
//! tested directly.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Uuid};
use zeroize::{Zeroize, Zeroizing};

use crate::alerts::{self, Alerts, Counter, Topic, Tried};
use crate::audit::{Audit, Outcome};
use crate::blocklist::{self, Block, Blocklist};
use crate::clientcerts::{Authority, Cipher, Issued, Method, Records, Revocation, Subject};
use crate::config::VpnAddress;
use crate::countries;
use crate::events::{Event, EventLog, What};
use crate::extras;
use crate::firewall::{Backend, Firewall};
use crate::geoip;
use crate::history::History;
use crate::kit::{self, Authenticator};
use crate::location::{self, Kind as AccountKind, OpenSession, Sighting, Verdict};
use crate::net::{self, Network};
use crate::occtl::{Control, Session as VpnSession};
use crate::otpfile::CodeCheck;
use crate::overrides::{self, Directories, Form as OverridesForm, Overrides, Owner};
use crate::passkey::{self, RelyingParty, Unavailable};
use crate::passphrase;
use crate::password::Hasher;
use crate::portal::{PortalScope, PortalSession, PortalSessions, UserLockout};
use crate::protocol::{
    AdminChange, AdminSummary, AlertsView, CertificateEntry, ChannelEntry, ChannelView,
    ClientCertificate, CountryView, Group, IssueHow, IssuedCertificate, KeyFileDownload, Located,
    LocationVerdict, LocationView, MAX_MESSAGE, MailEntry, MailView, OneTimePassword, PasskeyView,
    Place, PortalRequest, PortalResponse, RefusedSignIn, Request, Response, Site, SitesView,
    UserChange, VpnSignIn,
};
use crate::secret;
use crate::server_settings::{
    self, Files as SettingsFiles, Renderer, Setting, Source, StateLine, spec_of,
};
use crate::serverconf::{BanPolicy, ServerConfig};
use crate::sessions::{Limiter, Pending, Scope, Session, Sessions};
use crate::sites::{self, End, Member, Plan, Sites};
use crate::store::{self, Admin, Role, Store, StoredPasskey};
use crate::totp;
use crate::vpnusers::{self, PasswordCheck, UserFile};

/// The longest password accepted, in characters.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The issuer authenticator apps show next to the account.
const TOTP_ISSUER: &str = "OpenConnect admin";

/// What the audit log names as the source of the helper's own actions.
const LOCAL: &str = "local";

/// The audit log lines on one page of the Audit log.
const AUDIT_PAGE: usize = 100;

/// The bytes of audit log lines on one page, which keeps the answer within
/// what the socket carries.
const AUDIT_PAGE_BYTES: usize = (MAX_MESSAGE >> 1) as usize;

/// The refusal for an admin who is not an owner on the Admins page.
const MANAGE_ADMINS: &str = "only owners can manage admins";

/// The refusal for an admin who is not an owner on the Settings page.
const CHANGE_SETTINGS: &str = "only owners can change the server's settings";

/// The refusal for an admin who is not an owner on the Bans page's country
/// rules.
const CHANGE_COUNTRIES: &str = "only owners can change the country rules";

/// The refusal for an admin who is not an owner on the Alerts page's mail
/// server.
const SET_MAIL: &str = "only owners can set the mail server for email alerts";

/// The image's own defaults of the settings checked together, for a
/// setting whose stored value an owner removes.
const IMAGE_DEFAULTS: &[(&str, &str)] = &[("TUNNEL_MODE", "all"), ("TUNNEL_ROUTES", "")];

/// What a change to the server settings did, in words, and whether ocserv
/// reloaded; or why nothing was stored.
type SettingsOutcome = Result<(String, bool), String>;

/// What an admin change did, in words, and the one-time password it set;
/// or why it was refused.
type AdminOutcome = Result<(String, Option<Zeroizing<String>>), String>;

/// The rules the service applies, taken from the panel's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Where a password alone signs in.
    pub lan_networks: Vec<Network>,
    /// Wrong passwords in a row that lock an account, and failed sign-ins in
    /// a row that block an address.
    pub max_failures: u32,
    /// How long a lockout or an address block lasts, in seconds.
    pub lockout: u64,
    /// The shortest admin password accepted, in characters.
    pub min_password_length: usize,
    /// How old a sign-in may be, in seconds, for replacing a second factor.
    pub reauth: u64,
}

/// A TOTP secret issued for confirmation.
struct Enrollment {
    secret: String,
    created: u64,
}

/// An authenticator key the portal issued to a VPN user, waiting for its
/// first code, with the same key in hex as liboath's users file holds it.
struct KeyEnrollment {
    authenticator: Authenticator,
    hex: Zeroizing<String>,
    created: u64,
    /// Whether it replaces the user's key, after a code from that key.
    replaces: bool,
}

/// A passkey registration started on the Account page or the setup page,
/// waiting for the browser's answer.
struct PasskeyEnrollment {
    name: String,
    /// The user handle the admin's passkeys carry, new for their first.
    user: Uuid,
    state: PasskeyRegistration,
    created: u64,
}

/// A passkey prompt for a sign-in whose password was accepted, waiting for
/// the browser's answer.
struct PasskeyChallenge {
    state: PasskeyAuthentication,
    created: u64,
}

/// A wrong secret given while signing in or changing a password; each
/// counts toward the account's lockout.
#[derive(Debug, Clone, Copy)]
enum Mistake {
    Password,
    CurrentPassword,
    TotpCode,
    Passkey,
}

impl Mistake {
    fn action(self) -> &'static str {
        match self {
            Mistake::Password => "login",
            Mistake::CurrentPassword => "password.change",
            Mistake::TotpCode => "login.totp",
            Mistake::Passkey => "login.passkey",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Mistake::Password | Mistake::CurrentPassword => "wrong password",
            Mistake::TotpCode => "wrong TOTP code",
            Mistake::Passkey => "passkey refused",
        }
    }
}

/// The VPN server the panel reads and acts on, its users' password file,
/// the dashboard's history of it, the configuration it runs with, its live
/// events, and the address clients reach it at.
pub struct Vpn {
    pub control: Box<dyn Control>,
    pub users: Box<dyn UserFile>,
    pub history: History,
    pub ocserv_config: PathBuf,
    pub events: EventLog,
    pub address: VpnAddress,
    /// The firewall's blocklist, the firewall it drives, and the Docker
    /// host's addresses, which the firewall always admits.
    pub blocklist: Blocklist,
    pub firewall: Box<dyn Firewall>,
    pub docker_hosts: Vec<IpAddr>,
    /// The server settings' record and stored values, and the builder that
    /// makes the configuration again when an owner changes them.
    pub settings: SettingsFiles,
    pub renderer: Box<dyn Renderer>,
    /// The certificates the Certificates page shows besides the VPN
    /// server's, each with what uses it.
    pub certificate_files: Vec<(String, PathBuf)>,
    /// The VPN users' client certificates the panel issued, the client CA
    /// that signs and revokes them, and the days a new one is valid.
    pub client_certificates: Records,
    pub authority: Box<dyn Authority>,
    pub client_cert_days: u64,
    /// The networks the container's own interfaces reach, which no network
    /// published for site-to-site may overlap.
    pub local_networks: Vec<Network>,
    /// The site-to-site rules and egress choices, and whether the firewall
    /// checks where tunnel traffic comes from, without which the rules open
    /// nothing.
    pub sites: Sites,
    pub source_check: bool,
    /// The country rules: the environment's, the panel's stored ones, and
    /// the country database.
    pub countries: countries::Setup,
    /// What each admin chose to be alerted to and where, the mail server,
    /// and the alerts waiting to go.
    pub alerts: Alerts,
    /// The relying party admin passkeys are registered with, or why the
    /// panel's address cannot have passkeys.
    pub passkeys: Result<RelyingParty, Unavailable>,
    /// The location checks: their setting, databases and learning.
    pub locations: Locations,
}

/// The location checks as the helper keeps them.
pub struct Locations {
    /// LOCATION_CHECKS and LOCATION_REFRESH_HOURS, each when set.
    pub environment: location::Environment,
    /// Where an owner's setting is stored.
    pub stored: PathBuf,
    /// The city and network databases, once downloaded; none before.
    pub atlas: Option<location::Atlas>,
    /// What each account showed before.
    pub learning: location::Learning,
    /// Wakes the thread that keeps the databases current; none where there
    /// is no such thread.
    pub wake: Option<std::sync::mpsc::Sender<()>>,
    /// When that thread last checked for newer databases, and what it
    /// installed, or why the check failed.
    pub last: Option<(u64, Result<Vec<String>, String>)>,
    /// The address of the VPN users page, where an admin allows the place of
    /// a refused sign-in, which the refusal's alert links to.
    pub users_page: String,
}

/// What became of the location check of a VPN sign-in.
#[derive(Debug)]
pub enum VpnCheck {
    /// Answered; `unsaved` says why what the sign-in showed could not be
    /// saved, which leaves the verdict as it is.
    Answered { unsaved: Option<String> },
    /// The answer could not be delivered, as when the session script gave
    /// up waiting and let the client in, so the check recorded and learned
    /// nothing: the script records that the check could not run.
    Undelivered { problem: String },
}

impl Service {
    /// What the thread that keeps the location databases current needs: none
    /// while the checks are off; else the MaxMind key in force and how long
    /// to wait before the next check.
    pub fn location_plan(&self) -> Result<Option<(Option<geoip::Key>, u64)>, String> {
        let setting =
            location::Stored::open(&self.locations.stored)?.in_force(&self.locations.environment);
        if !setting.on {
            return Ok(None);
        }
        Ok(Some((
            self.countries.maxmind.key()?,
            setting.refresh_hours * 3600,
        )))
    }

    /// Reads the location databases in `config_dir` again, after a download.
    pub fn reload_atlas(&mut self, config_dir: &Path) -> Result<(), String> {
        let key_set = self.countries.maxmind.key()?.is_some();
        self.locations.atlas = location::load_atlas(config_dir, key_set)?;
        Ok(())
    }

    /// Records how the check for newer location databases at `now` ended,
    /// for the Bans page.
    pub fn note_location_check(&mut self, now: u64, outcome: Result<Vec<String>, String>) {
        self.locations.last = Some((now, outcome));
    }

    /// The location checks as the Bans page shows them.
    fn location_view(&self) -> Result<LocationView, String> {
        let environment = &self.locations.environment;
        let setting = location::Stored::open(&self.locations.stored)?.in_force(environment);
        let (city, networks) = match &self.locations.atlas {
            Some(atlas) => {
                let (city, networks) = atlas.editions();
                (Some(city), networks)
            }
            None => (None, None),
        };
        Ok(LocationView {
            on: setting.on,
            refresh_hours: setting.refresh_hours,
            on_from_env: environment.on.is_some(),
            refresh_from_env: environment.refresh_hours.is_some(),
            city,
            networks,
            last: self.locations.last.clone(),
        })
    }
}

/// How a new client certificate gets its key.
enum Signing<'a> {
    /// A new key, handed out in a key file encrypted with the cipher.
    KeyFile(Cipher),
    /// The key of a PEM signing request.
    Request(&'a str),
    /// The key of the PEM certificate it renews.
    Again(&'a str),
}

/// The helper's state and the requests it answers.
pub struct Service {
    policy: Policy,
    store: Store,
    audit: Audit,
    hasher: Hasher,
    sessions: Sessions,
    pending: Pending,
    limiter: Limiter,
    /// TOTP secrets issued and not yet confirmed, by admin name.
    enrollments: HashMap<String, Enrollment>,
    /// Seconds a sign-in waits for its second factor, and an issued TOTP
    /// secret for its confirmation.
    second_factor_window: u64,
    /// The VPN server the panel reads and acts on.
    control: Box<dyn Control>,
    /// The VPN users' password file.
    users: Box<dyn UserFile>,
    /// The dashboard's samples of the VPN server.
    history: History,
    /// The configuration file the VPN server runs with.
    ocserv_config: PathBuf,
    /// The live events of the last PANEL_HISTORY_HOURS.
    events: EventLog,
    /// Where VPN clients connect, as the onboarding kit gives it.
    vpn_address: VpnAddress,
    /// The VPN user portal's sessions, failed sign-ins per user, and failed
    /// sign-ins per address, apart from the admin panel's.
    portal_sessions: PortalSessions,
    portal_lockout: UserLockout,
    portal_limiter: Limiter,
    /// Portal sign-ins whose password was right, waiting for their code.
    portal_pending: Pending,
    /// Authenticator keys the portal issued and not yet confirmed, by VPN
    /// user name; each waits as long as an admin's TOTP secret does.
    portal_keys: HashMap<String, KeyEnrollment>,
    blocklist: Blocklist,
    firewall: Box<dyn Firewall>,
    docker_hosts: Vec<IpAddr>,
    settings: SettingsFiles,
    renderer: Box<dyn Renderer>,
    certificate_files: Vec<(String, PathBuf)>,
    client_certificates: Records,
    authority: Box<dyn Authority>,
    client_cert_days: u64,
    local_networks: Vec<Network>,
    sites: Sites,
    source_check: bool,
    countries: countries::Setup,
    alerts: Alerts,
    passkeys: Result<RelyingParty, Unavailable>,
    /// Passkey registrations started and not yet finished, by admin name;
    /// each waits as long as an issued TOTP secret does.
    passkey_enrollments: HashMap<String, PasskeyEnrollment>,
    /// Passkey prompts for pending sign-ins, by the digest of the pending
    /// sign-in's token; each waits as long as the sign-in does.
    passkey_challenges: HashMap<[u8; 32], PasskeyChallenge>,
    locations: Locations,
}

impl Service {
    pub fn new(
        policy: Policy,
        store: Store,
        audit: Audit,
        hasher: Hasher,
        sessions: Sessions,
        second_factor_window: u64,
        vpn: Vpn,
    ) -> Service {
        let Vpn {
            control,
            users,
            history,
            ocserv_config,
            events,
            address: vpn_address,
            blocklist,
            firewall,
            docker_hosts,
            settings,
            renderer,
            certificate_files,
            client_certificates,
            authority,
            client_cert_days,
            local_networks,
            sites,
            source_check,
            countries,
            alerts,
            passkeys,
            locations,
        } = vpn;
        let (idle, max) = sessions.limits();
        let portal_sessions = PortalSessions::new(idle, max);
        let limiter = Limiter::new(policy.max_failures, policy.lockout);
        let portal_lockout = UserLockout::new(policy.max_failures, policy.lockout);
        let portal_limiter = Limiter::new(policy.max_failures, policy.lockout);
        Service {
            policy,
            store,
            audit,
            hasher,
            sessions,
            pending: Pending::new(second_factor_window),
            limiter,
            enrollments: HashMap::new(),
            second_factor_window,
            control,
            users,
            history,
            ocserv_config,
            events,
            vpn_address,
            portal_sessions,
            portal_lockout,
            portal_limiter,
            portal_pending: Pending::new(second_factor_window),
            portal_keys: HashMap::new(),
            blocklist,
            firewall,
            docker_hosts,
            settings,
            renderer,
            certificate_files,
            client_certificates,
            authority,
            client_cert_days,
            local_networks,
            sites,
            source_check,
            countries,
            alerts,
            passkeys,
            passkey_enrollments: HashMap::new(),
            passkey_challenges: HashMap::new(),
            locations,
        }
    }

    /// Adds `events` from the spool to the live events, noting why each
    /// failed sign-in failed when the user file tells, counts each ban toward
    /// an automatic block, and drops the events older than the log keeps.
    /// The events are kept even when the user file cannot be read or a block
    /// fails; the errors are returned after.
    pub fn record_events(&mut self, now: u64, events: Vec<Event>) -> Result<(), String> {
        let failures = events
            .iter()
            .any(|event| matches!(event.what, What::SignInFailed { .. }));
        let users = if failures {
            Some(self.users.list())
        } else {
            None
        };
        let mut errors = Vec::new();
        for event in &events {
            if let What::Banned { address, .. } = &event.what
                && let Err(error) = self.count_ban(address, now)
            {
                errors.push(error);
            }
        }
        for event in events {
            if matches!(
                event.what,
                What::LocationRefused { .. }
                    | What::LocationFlagged { .. }
                    | What::LocationUnchecked { .. }
            ) {
                self.note_location(event, now);
                continue;
            }
            let reason = match (&event.what, &users) {
                (What::SignInFailed { user, .. }, Some(Ok(users))) => {
                    Some(match users.iter().find(|known| known.name == *user) {
                        None => "there is no VPN user by that name".to_owned(),
                        Some(known) if known.locked => "the account is locked".to_owned(),
                        Some(known) if known.otp => {
                            "the password or the authenticator code was wrong".to_owned()
                        }
                        Some(_) => "the password was wrong".to_owned(),
                    })
                }
                (
                    What::SignInFailed { .. }
                    | What::Connected { .. }
                    | What::Disconnected { .. }
                    | What::Banned { .. }
                    | What::LocationRefused { .. }
                    | What::LocationFlagged { .. }
                    | What::LocationUnchecked { .. },
                    _,
                ) => None,
            };
            self.events.add(event, reason);
        }
        self.events.prune(now);
        if let Some(Err(error)) = users {
            errors.push(format!(
                "why the failed sign-ins failed is unknown, since {error}"
            ));
        }
        match errors.is_empty() {
            true => Ok(()),
            false => Err(errors.join("; ")),
        }
    }

    /// Samples the VPN server's sessions into the dashboard's history.
    #[cfg(unix)]
    pub fn sample(&mut self, now: u64) -> Result<(), String> {
        let sessions = self.control.sessions()?;
        self.history.record(now, &sessions)
    }

    /// Answers one request. A failure inside the helper is answered as
    /// `Error` with what failed.
    pub fn handle(&mut self, request: Request, now: u64) -> Response {
        let result = match request {
            Request::Ping => Ok(Response::Pong {
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }),
            Request::Login {
                name,
                mut password,
                from,
            } => {
                let result = self.login(&name, &password, &from, now);
                password.zeroize();
                result
            }
            Request::Logout { session } => self.logout(&session, now),
            Request::Whoami { session } => self.whoami(&session, now),
            Request::ChangePassword {
                session,
                csrf,
                mut current,
                mut new,
            } => {
                let result = self.change_password(&session, &csrf, &current, &new, now);
                current.zeroize();
                new.zeroize();
                result
            }
            Request::SecondFactor { pending, mut code } => {
                let result = self.second_factor(&pending, &code, now);
                code.zeroize();
                result
            }
            Request::TotpBegin { session, csrf } => self.totp_begin(&session, &csrf, now),
            Request::TotpConfirm {
                session,
                csrf,
                mut code,
            } => {
                let result = self.totp_confirm(&session, &csrf, &code, now);
                code.zeroize();
                result
            }
            Request::TotpPending { session } => Ok(self.totp_pending(&session, now)),
            Request::PasskeyBegin {
                session,
                csrf,
                name,
            } => self.passkey_begin(&session, &csrf, &name, now),
            Request::PasskeyFinish {
                session,
                csrf,
                credential,
            } => self.passkey_finish(&session, &csrf, &credential, now),
            Request::RemovePasskey {
                session,
                csrf,
                name,
            } => self.remove_passkey(&session, &csrf, &name, now),
            Request::SecondFactorOptions { pending } => self.second_factor_options(&pending, now),
            Request::SetLocationChecks {
                session,
                csrf,
                on,
                refresh_hours,
            } => self.set_location_checks(&session, &csrf, on, &refresh_hours, now),
            Request::PasskeySignInBegin { pending } => self.passkey_sign_in_begin(&pending, now),
            Request::PasskeySignIn {
                pending,
                credential,
            } => self.passkey_sign_in(&pending, &credential, now),
            Request::ServerStatus { session } => self.server_status(&session, now),
            Request::ListSessions { session } => self.list_sessions(&session, now),
            Request::EndSession { session, csrf, id } => {
                self.end_vpn_session(&session, &csrf, id, now)
            }
            Request::ListVpnUsers { session } => self.list_vpn_users(&session, now),
            Request::AllowPlace {
                session,
                csrf,
                user,
                from,
            } => self.allow_place(&session, &csrf, &user, &from, now),
            Request::SetVacation {
                session,
                csrf,
                kind,
                name,
                until,
            } => self.set_vacation(&session, &csrf, kind, &name, until.as_deref(), now),
            Request::History { session, since } => Ok(match self.full_session(&session, now) {
                Some(_) => Response::History {
                    interval: self.history.interval(),
                    samples: self
                        .history
                        .samples()
                        .into_iter()
                        .filter(|sample| since.is_none_or(|time| sample.time > time))
                        .collect(),
                },
                None => Response::Denied,
            }),
            Request::ChangeVpnUser {
                session,
                csrf,
                mut change,
            } => {
                let result = self.change_vpn_user(&session, &csrf, &change, now);
                change.wipe();
                result
            }
            Request::ListBans { session } => self.list_bans(&session, now),
            Request::ListAudit { session, before } => self.list_audit(&session, before, now),
            Request::Account { session } => self.account(&session, now),
            Request::EndOtherSessions { session, csrf } => {
                self.end_other_sessions(&session, &csrf, now)
            }
            Request::Certificates { session } => self.certificates(&session, now),
            Request::ClientCertificates { session } => self.client_certificates(&session, now),
            Request::IssueClientCertificate {
                session,
                csrf,
                user,
                how,
            } => self.issue_client_certificate(&session, &csrf, &user, &how, now),
            Request::RenewClientCertificate {
                session,
                csrf,
                serial,
            } => self.renew_client_certificate(&session, &csrf, &serial, now),
            Request::RevokeClientCertificate {
                session,
                csrf,
                serial,
            } => self.revoke_client_certificate(&session, &csrf, &serial, now),
            Request::ServerSettings { session } => self.list_server_settings(&session, now),
            Request::SetServerSettings {
                session,
                csrf,
                values,
            } => self.set_server_settings(&session, &csrf, &values, now),
            Request::ListAdmins { session } => self.list_admins(&session, now),
            Request::ChangeAdmin {
                session,
                csrf,
                change,
            } => self.change_admin(&session, &csrf, &change, now),
            Request::Unban {
                session,
                csrf,
                address,
            } => self.unban(&session, &csrf, &address, now),
            Request::Block {
                session,
                csrf,
                network,
                hours,
            } => self.block(&session, &csrf, &network, hours, now),
            Request::Unblock {
                session,
                csrf,
                network,
            } => self.unblock(&session, &csrf, &network, now),
            Request::KeepBlock {
                session,
                csrf,
                network,
            } => self.keep_block(&session, &csrf, &network, now),
            Request::SetCountries {
                session,
                csrf,
                rule,
                countries,
            } => self.set_countries(&session, &csrf, rule.as_deref(), countries.as_deref(), now),
            Request::SetMaxmindKey {
                session,
                csrf,
                account,
                mut license,
            } => {
                let result = self.set_maxmind_key(&session, &csrf, &account, &license, now);
                license.zeroize();
                result
            }
            Request::RemoveMaxmindKey { session, csrf } => {
                self.remove_maxmind_key(&session, &csrf, now)
            }
            Request::Alerts { session } => self.alerts_page(&session, now),
            Request::SetAlertTopics {
                session,
                csrf,
                topics,
            } => self.set_alert_topics(&session, &csrf, &topics, now),
            Request::AddAlertChannel {
                session,
                csrf,
                mut channel,
            } => {
                let result = self.add_alert_channel(&session, &csrf, &channel, now);
                channel.wipe();
                result
            }
            Request::RemoveAlertChannel { session, csrf, id } => {
                self.remove_alert_channel(&session, &csrf, id, now)
            }
            Request::TestAlertChannel { session, csrf, id } => {
                self.test_alert_channel(&session, &csrf, id, now)
            }
            Request::SetMailServer {
                session,
                csrf,
                mut server,
            } => {
                let result = self.set_mail_server(&session, &csrf, &server, now);
                server.wipe();
                result
            }
            Request::RemoveMailServer { session, csrf } => {
                self.remove_mail_server(&session, &csrf, now)
            }
            Request::ListGroups { session } => self.list_groups(&session, now),
            Request::GetOverrides {
                session,
                owner,
                name,
            } => self.get_overrides(&session, owner, &name, now),
            Request::SetOverrides {
                session,
                csrf,
                owner,
                name,
                form,
            } => self.set_overrides(&session, &csrf, owner, &name, form.as_ref(), now),
            Request::SiteRules { session } => self.site_rules(&session, now),
            Request::AddSiteRule {
                session,
                csrf,
                from,
                to,
            } => self.add_site_rule(&session, &csrf, from, to, now),
            Request::RemoveSiteRule { session, csrf, id } => {
                self.remove_site_rule(&session, &csrf, id, now)
            }
            Request::SetSiteEgress {
                session,
                csrf,
                user,
                on,
            } => self.set_site_egress(&session, &csrf, &user, on, now),
            Request::ListEvents { session, after } => self.list_events(&session, after, now),
            Request::Portal { request } => Ok(Response::Portal {
                response: self.portal(request, now),
            }),
        };
        match result {
            Ok(response) => response,
            Err(message) => Response::Error { message },
        }
    }

    fn login(
        &mut self,
        name: &str,
        password: &str,
        from: &str,
        now: u64,
    ) -> Result<Response, String> {
        let address = from
            .parse::<IpAddr>()
            .map_err(|error| format!("'{from}' is not an IP address: {error}"))?
            .to_canonical();
        let from = address.to_string();
        if let Some(retry_after) = self.limiter.blocked(address, now) {
            self.audit.record(
                now,
                name,
                &from,
                "login",
                Outcome::Denied,
                &format!("address blocked for {retry_after} more seconds after repeated failures"),
            )?;
            return Ok(Response::Locked { retry_after });
        }
        if let Some(problem) = store::name_problem(name) {
            let reason = format!("not an admin name: {problem}");
            return self.refuse_unknown(name, password, &from, address, &reason, now);
        }
        let found = self.store.get(&store::canonical_name(name)?).cloned();
        let Some(admin) = found else {
            return self.refuse_unknown(
                name,
                password,
                &from,
                address,
                "no admin of that name",
                now,
            );
        };
        if let Some(until) = admin.locked_until
            && now < until
        {
            let retry_after = until - now;
            self.audit.record(
                now,
                &admin.name,
                &from,
                "login",
                Outcome::Denied,
                &format!("account locked for {retry_after} more seconds"),
            )?;
            return Ok(Response::Locked { retry_after });
        }
        if !self.hasher.verify(password, &admin.password_hash)? {
            let locked = self.mistake(&admin.name, &from, address, Mistake::Password, now)?;
            return Ok(match locked {
                true => Response::Locked {
                    retry_after: self.policy.lockout,
                },
                false => Response::Denied,
            });
        }
        self.limiter.success(address);
        if let Some(refusal) = self.check_admin_place(&admin.name, address, now)? {
            return Ok(refusal);
        }
        let lan = net::any_contains(&self.policy.lan_networks, address);
        if !lan && admin.has_second_factor() {
            if admin.totp_secret.is_none()
                && let Err(unavailable) = &self.passkeys
            {
                let reason = unavailable.to_string();
                self.audit.record(
                    now,
                    &admin.name,
                    &from,
                    "login",
                    Outcome::Denied,
                    &format!(
                        "password accepted, but the account's only second factor is passkeys, \
                         which cannot be used here: {reason}"
                    ),
                )?;
                return Ok(Response::SecondFactorUnavailable { reason });
            }
            let pending = self.pending.create(&admin.name, address, now)?;
            self.audit.record(
                now,
                &admin.name,
                &from,
                "login.password",
                Outcome::Allowed,
                "password accepted; a second factor is due outside the LAN",
            )?;
            return Ok(Response::SecondFactorRequired { pending });
        }
        if !lan && !admin.enrollment_open {
            self.audit.record(
                now,
                &admin.name,
                &from,
                "login",
                Outcome::Denied,
                "password accepted, but outside the LAN a second factor is required and the account has none",
            )?;
            return Ok(Response::SecondFactorNotEnrolled);
        }
        let (scope, detail) = match lan {
            true => (Scope::Full, "password only, from a LAN network"),
            false => (
                Scope::Enrollment,
                "password accepted; enrollment-only session until a second factor is enrolled",
            ),
        };
        let entry = self.admin_mut(&admin.name)?;
        entry.failed_logins = 0;
        entry.locked_until = None;
        entry.last_login = Some(now);
        self.store.save()?;
        let issued = self
            .sessions
            .create(&admin.name, admin.role, scope, address, now)?;
        if matches!(scope, Scope::Full) {
            self.learn_admin_place(&admin.name, address, now)?;
        }
        self.audit
            .record(now, &admin.name, &from, "login", Outcome::Allowed, detail)?;
        if !lan {
            self.alert_sign_in(
                &admin.name,
                address,
                "with a password, to set up an authenticator app",
                now,
            );
        }
        Ok(Response::SignedIn {
            session: issued.token,
            csrf: issued.csrf,
            admin: admin.name,
            role: admin.role,
            scope,
            must_change_password: admin.must_change_password,
            expires: issued.expires,
        })
    }

    /// Spends the cost of a password check on the decoy hash, so that an
    /// unknown name is answered in the time a known one is, then refuses.
    fn refuse_unknown(
        &mut self,
        name: &str,
        password: &str,
        from: &str,
        address: IpAddr,
        reason: &str,
        now: u64,
    ) -> Result<Response, String> {
        if self.hasher.verify_decoy(password)? {
            return Err("the decoy password hash matched a password".to_owned());
        }
        self.limiter.failure(address, now);
        self.audit
            .record(now, name, from, "login", Outcome::Denied, reason)?;
        Ok(Response::Denied)
    }

    /// Counts a mistake against the admin and the address, locks the account
    /// when the count reaches the limit, and returns whether it did.
    fn mistake(
        &mut self,
        admin: &str,
        from: &str,
        address: IpAddr,
        mistake: Mistake,
        now: u64,
    ) -> Result<bool, String> {
        self.mistake_because(admin, from, address, mistake, mistake.description(), now)
    }

    /// Counts a mistake as `mistake` does, with `reason` in the audit log in
    /// place of the mistake's own description.
    fn mistake_because(
        &mut self,
        admin: &str,
        from: &str,
        address: IpAddr,
        mistake: Mistake,
        reason: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.limiter.failure(address, now);
        let max_failures = self.policy.max_failures;
        let lockout = self.policy.lockout;
        let entry = self.admin_mut(admin)?;
        entry.failed_logins += 1;
        let locked = entry.failed_logins >= max_failures;
        if locked {
            entry.locked_until = Some(now + lockout);
            entry.failed_logins = 0;
        }
        self.store.save()?;
        let detail = match locked {
            true => format!("{reason}; account locked for {lockout} seconds"),
            false => reason.to_owned(),
        };
        self.audit
            .record(now, admin, from, mistake.action(), Outcome::Denied, &detail)?;
        Ok(locked)
    }

    fn logout(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if let Some(session) = self.sessions.touch(token, now) {
            if !self.sessions.end(token) {
                return Err("a session ended while it was being closed".to_owned());
            }
            self.audit.record(
                now,
                &session.admin,
                &session.from.to_string(),
                "logout",
                Outcome::Allowed,
                "session ended",
            )?;
        }
        Ok(Response::Done)
    }

    fn whoami(&mut self, token: &str, now: u64) -> Result<Response, String> {
        let Some(session) = self.sessions.touch(token, now) else {
            return Ok(Response::Denied);
        };
        let admin = self.admin_of(&session)?;
        let expires = self.sessions.expires(&session);
        Ok(Response::Admin {
            name: admin.name,
            role: admin.role,
            scope: session.scope,
            csrf: session.csrf,
            must_change_password: admin.must_change_password,
            expires,
            passkeys: self.passkeys.is_ok(),
        })
    }

    fn change_password(
        &mut self,
        token: &str,
        csrf: &str,
        current: &str,
        new: &str,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.checked_session(token, csrf, "password.change", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let from = session.from.to_string();
        let admin = self.admin_of(&session)?;
        if !self.hasher.verify(current, &admin.password_hash)? {
            let locked = self.mistake(
                &admin.name,
                &from,
                session.from,
                Mistake::CurrentPassword,
                now,
            )?;
            if locked {
                self.sessions.end_admin(&admin.name, None);
            }
            return Ok(Response::Denied);
        }
        if let Err(message) = check_new_password(new, current, self.policy.min_password_length) {
            return Ok(Response::Invalid { message });
        }
        let hash = self.hasher.hash(new)?;
        let entry = self.admin_mut(&admin.name)?;
        entry.password_hash = hash;
        entry.must_change_password = false;
        self.store.save()?;
        let ended = self.sessions.end_admin(&admin.name, Some(token));
        if !self.sessions.reauthenticated(token, now) {
            return Err("the session ended while its password was being replaced".to_owned());
        }
        self.audit.record(
            now,
            &admin.name,
            &from,
            "password.change",
            Outcome::Allowed,
            &match ended {
                0 => "password replaced; no other session was open".to_owned(),
                1 => "password replaced; ended 1 other session".to_owned(),
                ended => format!("password replaced; ended {ended} other sessions"),
            },
        )?;
        Ok(Response::Done)
    }

    /// Completes a sign-in that is waiting for its second factor. A wrong
    /// code ends the pending sign-in and counts toward the lockout.
    fn second_factor(&mut self, token: &str, code: &str, now: u64) -> Result<Response, String> {
        let Some(pending) = self.pending.take(token, now) else {
            return Ok(Response::Denied);
        };
        let from = pending.from.to_string();
        let admin = self.store.get(&pending.admin).cloned().ok_or_else(|| {
            format!(
                "the admin '{}' of a pending sign-in does not exist",
                pending.admin
            )
        })?;
        let Some(secret) = admin.totp_secret.as_deref() else {
            let locked = self.mistake_because(
                &admin.name,
                &from,
                pending.from,
                Mistake::TotpCode,
                "a TOTP code, but the account has no authenticator app",
                now,
            )?;
            return Ok(match locked {
                true => Response::Locked {
                    retry_after: self.policy.lockout,
                },
                false => Response::Denied,
            });
        };
        let Some(step) = totp::verify(secret, code, now, admin.last_totp_step)? else {
            let locked = self.mistake(&admin.name, &from, pending.from, Mistake::TotpCode, now)?;
            return Ok(match locked {
                true => Response::Locked {
                    retry_after: self.policy.lockout,
                },
                false => Response::Denied,
            });
        };
        let entry = self.admin_mut(&admin.name)?;
        entry.last_totp_step = Some(step);
        entry.failed_logins = 0;
        entry.locked_until = None;
        entry.last_login = Some(now);
        self.store.save()?;
        let issued =
            self.sessions
                .create(&admin.name, admin.role, Scope::Full, pending.from, now)?;
        self.learn_admin_place(&admin.name, pending.from, now)?;
        self.audit.record(
            now,
            &admin.name,
            &from,
            "login",
            Outcome::Allowed,
            "password and TOTP code",
        )?;
        self.alert_sign_in(
            &admin.name,
            pending.from,
            "with a password and an authenticator code",
            now,
        );
        Ok(Response::SignedIn {
            session: issued.token,
            csrf: issued.csrf,
            admin: admin.name,
            role: admin.role,
            scope: Scope::Full,
            must_change_password: admin.must_change_password,
            expires: issued.expires,
        })
    }

    /// Issues a new TOTP secret to be confirmed with a code. The one-time
    /// password must be replaced first, and replacing an enrolled secret
    /// needs a recent sign-in.
    fn totp_begin(&mut self, token: &str, csrf: &str, now: u64) -> Result<Response, String> {
        let session = match self.checked_session(token, csrf, "totp.begin", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let admin = self.admin_of(&session)?;
        if admin.must_change_password {
            return Ok(Response::Invalid {
                message: "replace the one-time password first".to_owned(),
            });
        }
        if admin.totp_secret.is_some() && now >= session.authenticated + self.policy.reauth {
            return Ok(Response::Invalid {
                message: "sign in again before you replace your authenticator app".to_owned(),
            });
        }
        let secret = totp::new_secret()?;
        let uri = totp::uri(&secret, &admin.name, TOTP_ISSUER);
        self.enrollments.insert(
            admin.name.clone(),
            Enrollment {
                secret: secret.clone(),
                created: now,
            },
        );
        self.audit.record(
            now,
            &admin.name,
            &session.from.to_string(),
            "totp.begin",
            Outcome::Allowed,
            "a new TOTP secret was issued for confirmation",
        )?;
        Ok(Response::TotpSecret { secret, uri })
    }

    /// Enrolls the issued TOTP secret when `code` matches it, and gives an
    /// enrollment-only session full access.
    fn totp_confirm(
        &mut self,
        token: &str,
        csrf: &str,
        code: &str,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.checked_session(token, csrf, "totp.confirm", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let from = session.from.to_string();
        let Some(enrollment) = self.enrollments.remove(&session.admin) else {
            return Ok(Response::Invalid {
                message: "start setting up the authenticator app first".to_owned(),
            });
        };
        if now >= enrollment.created + self.second_factor_window {
            return Ok(Response::Invalid {
                message: "the setup took too long; start again for a new key".to_owned(),
            });
        }
        let Some(step) = totp::verify(&enrollment.secret, code, now, None)? else {
            self.audit.record(
                now,
                &session.admin,
                &from,
                "totp.confirm",
                Outcome::Denied,
                "the code did not match the new TOTP secret",
            )?;
            self.enrollments.insert(session.admin.clone(), enrollment);
            return Ok(Response::Invalid {
                message: "that code does not match; check that your phone's clock is right and \
                          enter the newest code"
                    .to_owned(),
            });
        };
        let entry = self.admin_mut(&session.admin)?;
        entry.totp_secret = Some(enrollment.secret);
        entry.last_totp_step = Some(step);
        entry.enrollment_open = false;
        self.store.save()?;
        if !self.sessions.set_scope(token, Scope::Full) {
            return Err("the session ended while TOTP was being enrolled".to_owned());
        }
        self.audit.record(
            now,
            &session.admin,
            &from,
            "totp.confirm",
            Outcome::Allowed,
            "TOTP enrolled; the session has full access",
        )?;
        Ok(Response::Done)
    }

    /// The secret `totp_begin` issued to the session's admin, while it waits
    /// for confirmation within the second-factor window.
    fn totp_pending(&mut self, token: &str, now: u64) -> Response {
        let Some(session) = self.sessions.touch(token, now) else {
            return Response::Denied;
        };
        match self.enrollments.get(&session.admin) {
            Some(enrollment) if now < enrollment.created + self.second_factor_window => {
                Response::TotpSecret {
                    uri: totp::uri(&enrollment.secret, &session.admin, TOTP_ISSUER),
                    secret: enrollment.secret.clone(),
                }
            }
            Some(_) | None => Response::NoTotpPending,
        }
    }

    /// Why the session's admin may not start adding a passkey named `name`,
    /// if they may not: passkeys must work at the panel's address, the
    /// one-time password must be replaced first, and an admin who already
    /// has a second factor needs a recent sign-in, as replacing the
    /// authenticator app does.
    fn passkey_refusal(
        &self,
        admin: &Admin,
        session: &Session,
        name: &str,
        now: u64,
    ) -> Option<String> {
        if let Err(unavailable) = &self.passkeys {
            return Some(format!("passkeys cannot be used here: {unavailable}"));
        }
        if admin.must_change_password {
            return Some("replace the one-time password first".to_owned());
        }
        if admin.has_second_factor() && now >= session.authenticated + self.policy.reauth {
            return Some("sign in again before you add a passkey".to_owned());
        }
        passkey_room(admin, name)
    }

    /// Starts registering a passkey named `name` for the session's admin:
    /// the options for the browser's passkey prompt.
    fn passkey_begin(
        &mut self,
        token: &str,
        csrf: &str,
        name: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "passkey.begin";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let admin = self.admin_of(&session)?;
        let name = name.trim();
        if let Some(message) = self.passkey_refusal(&admin, &session, name, now) {
            return Ok(Response::Invalid { message });
        }
        let user = match &admin.passkey_user {
            Some(handle) => Uuid::parse_str(handle).map_err(|error| {
                format!(
                    "the passkey user handle of '{}' is not a UUID: {error}",
                    admin.name
                )
            })?,
            None => Uuid::new_v4(),
        };
        let existing = admin
            .passkeys
            .iter()
            .map(passkey::credential_of)
            .collect::<Result<Vec<_>, _>>()?;
        let (options, state) = match &self.passkeys {
            Ok(party) => party.begin_registration(user, &admin.name, &existing)?,
            Err(unavailable) => {
                return Err(format!(
                    "passkeys became unavailable while one was being added: {unavailable}"
                ));
            }
        };
        let window = self.second_factor_window;
        self.passkey_enrollments
            .retain(|_admin, enrollment| now < enrollment.created + window);
        self.passkey_enrollments.insert(
            admin.name.clone(),
            PasskeyEnrollment {
                name: name.to_owned(),
                user,
                state,
                created: now,
            },
        );
        self.audit.record(
            now,
            &admin.name,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!("the browser was asked to register a passkey named '{name}'"),
        )?;
        Ok(Response::PasskeyOptions { options })
    }

    /// Adds the passkey the browser registered, from its answer as JSON, to
    /// the session's admin, and gives an enrollment-only session full access.
    fn passkey_finish(
        &mut self,
        token: &str,
        csrf: &str,
        credential: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "passkey.add";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let from = session.from.to_string();
        let Some(enrollment) = self.passkey_enrollments.remove(&session.admin) else {
            return Ok(Response::Invalid {
                message: "start adding the passkey first".to_owned(),
            });
        };
        if now >= enrollment.created + self.second_factor_window {
            return Ok(Response::Invalid {
                message: "adding the passkey took too long; start again".to_owned(),
            });
        }
        let checked = match &self.passkeys {
            Ok(party) => party.finish_registration(credential, &enrollment.state),
            Err(unavailable) => Err(passkey::Refused(format!(
                "passkeys cannot be used here: {unavailable}"
            ))),
        };
        let added = match checked {
            Ok(added) => added,
            Err(passkey::Refused(reason)) => {
                self.audit
                    .record(now, &session.admin, &from, action, Outcome::Denied, &reason)?;
                return Ok(Response::Invalid { message: reason });
            }
        };
        for other in self.store.list() {
            for stored in &other.passkeys {
                if passkey::credential_of(stored)?.cred_id() == added.cred_id() {
                    self.audit.record(
                        now,
                        &session.admin,
                        &from,
                        action,
                        Outcome::Denied,
                        &format!(
                            "the passkey for '{}' is already registered here",
                            enrollment.name
                        ),
                    )?;
                    return Ok(Response::Invalid {
                        message: "that passkey is already registered here; use another one"
                            .to_owned(),
                    });
                }
            }
        }
        let admin = self.admin_of(&session)?;
        if let Some(message) = passkey_room(&admin, &enrollment.name) {
            return Ok(Response::Invalid { message });
        }
        let stored = StoredPasskey {
            name: enrollment.name.clone(),
            created: now,
            last_used: None,
            credential: passkey::stored_form(&added)?,
        };
        let entry = self.admin_mut(&session.admin)?;
        entry.passkeys.push(stored);
        if entry.passkey_user.is_none() {
            entry.passkey_user = Some(enrollment.user.to_string());
        }
        entry.enrollment_open = false;
        self.store.save()?;
        let opened = matches!(session.scope, Scope::Enrollment);
        if opened && !self.sessions.set_scope(token, Scope::Full) {
            return Err("the session ended while a passkey was being added".to_owned());
        }
        let detail = match opened {
            true => format!(
                "added the passkey '{}'; the session has full access",
                enrollment.name
            ),
            false => format!("added the passkey '{}'", enrollment.name),
        };
        self.audit.record(
            now,
            &session.admin,
            &from,
            action,
            Outcome::Allowed,
            &detail,
        )?;
        Ok(Response::Done)
    }

    /// Removes the session admin's passkey named `name`. It needs a recent
    /// sign-in, and the admin's last second factor stays: a passkey goes only
    /// while an authenticator app or another passkey remains.
    fn remove_passkey(
        &mut self,
        token: &str,
        csrf: &str,
        name: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "passkey.remove";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let admin = self.admin_of(&session)?;
        let Some(index) = admin.passkeys.iter().position(|stored| stored.name == name) else {
            return Ok(Response::Invalid {
                message: format!("you have no passkey named '{name}'"),
            });
        };
        if now >= session.authenticated + self.policy.reauth {
            return Ok(Response::Invalid {
                message: "sign in again before you remove a passkey".to_owned(),
            });
        }
        if admin.totp_secret.is_none() && admin.passkeys.len() == 1 {
            return Ok(Response::Invalid {
                message: "set up the authenticator app or another passkey before you remove \
                          your last passkey"
                    .to_owned(),
            });
        }
        let entry = self.admin_mut(&session.admin)?;
        entry.passkeys.remove(index);
        self.store.save()?;
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!("removed the passkey '{name}'"),
        )?;
        Ok(Response::Done)
    }

    /// The second factors the pending sign-in `token` can be completed with.
    fn second_factor_options(&mut self, token: &str, now: u64) -> Result<Response, String> {
        let Some(pending) = self.pending.get(token, now) else {
            return Ok(Response::Denied);
        };
        let admin = self.store.get(&pending.admin).ok_or_else(|| {
            format!(
                "the admin '{}' of a pending sign-in does not exist",
                pending.admin
            )
        })?;
        Ok(Response::SecondFactorOptions {
            code: admin.totp_secret.is_some(),
            passkey: !admin.passkeys.is_empty() && self.passkeys.is_ok(),
        })
    }

    /// Offers the admin of the pending sign-in `token` a passkey prompt: the
    /// options for the browser, which name the admin's passkeys as the ones
    /// it may use.
    fn passkey_sign_in_begin(&mut self, token: &str, now: u64) -> Result<Response, String> {
        let Some(pending) = self.pending.get(token, now) else {
            return Ok(Response::Denied);
        };
        let admin = self.store.get(&pending.admin).cloned().ok_or_else(|| {
            format!(
                "the admin '{}' of a pending sign-in does not exist",
                pending.admin
            )
        })?;
        let party = match &self.passkeys {
            Ok(party) => party,
            Err(unavailable) => {
                return Ok(Response::Invalid {
                    message: format!("passkeys cannot be used here: {unavailable}"),
                });
            }
        };
        if admin.passkeys.is_empty() {
            return Ok(Response::Invalid {
                message: "this account has no passkey; use the authenticator app".to_owned(),
            });
        }
        let passkeys = admin
            .passkeys
            .iter()
            .map(passkey::credential_of)
            .collect::<Result<Vec<_>, _>>()?;
        let (options, state) = party.begin_sign_in(&passkeys)?;
        let window = self.second_factor_window;
        self.passkey_challenges
            .retain(|_digest, challenge| now < challenge.created + window);
        self.passkey_challenges.insert(
            secret::digest(token),
            PasskeyChallenge {
                state,
                created: now,
            },
        );
        Ok(Response::PasskeyOptions { options })
    }

    /// Completes the pending sign-in `token` with the browser's answer to its
    /// passkey prompt. A refused answer ends the pending sign-in and counts
    /// toward the lockout, as a wrong code does.
    fn passkey_sign_in(
        &mut self,
        token: &str,
        credential: &str,
        now: u64,
    ) -> Result<Response, String> {
        let Some(pending) = self.pending.take(token, now) else {
            return Ok(Response::Denied);
        };
        let challenge = self.passkey_challenges.remove(&secret::digest(token));
        let from = pending.from.to_string();
        let admin = self.store.get(&pending.admin).cloned().ok_or_else(|| {
            format!(
                "the admin '{}' of a pending sign-in does not exist",
                pending.admin
            )
        })?;
        let window = self.second_factor_window;
        let checked = match (&self.passkeys, challenge) {
            (Ok(party), Some(challenge)) if now < challenge.created + window => {
                party.finish_sign_in(credential, &challenge.state)
            }
            (Ok(_party), Some(_late)) => Err(passkey::Refused(
                "the passkey prompt was answered too late".to_owned(),
            )),
            (Ok(_party), None) => Err(passkey::Refused(
                "no passkey prompt was offered for this sign-in".to_owned(),
            )),
            (Err(unavailable), _challenge) => Err(passkey::Refused(format!(
                "passkeys cannot be used here: {unavailable}"
            ))),
        };
        let result = match checked {
            Ok(result) => result,
            Err(passkey::Refused(reason)) => {
                let locked = self.mistake_because(
                    &admin.name,
                    &from,
                    pending.from,
                    Mistake::Passkey,
                    &format!("passkey refused: {reason}"),
                    now,
                )?;
                return Ok(match locked {
                    true => Response::Locked {
                        retry_after: self.policy.lockout,
                    },
                    false => Response::Denied,
                });
            }
        };
        let used = {
            let entry = self.admin_mut(&admin.name)?;
            let mut used = None;
            for stored in &mut entry.passkeys {
                let mut credential = passkey::credential_of(stored)?;
                if credential.update_credential(&result).is_some() {
                    stored.credential = passkey::stored_form(&credential)?;
                    stored.last_used = Some(now);
                    used = Some(stored.name.clone());
                }
            }
            if used.is_some() {
                entry.failed_logins = 0;
                entry.locked_until = None;
                entry.last_login = Some(now);
            }
            used
        };
        let Some(used) = used else {
            self.audit.record(
                now,
                &admin.name,
                &from,
                Mistake::Passkey.action(),
                Outcome::Denied,
                "the passkey was removed while the sign-in waited for it",
            )?;
            return Ok(Response::Denied);
        };
        self.store.save()?;
        let issued =
            self.sessions
                .create(&admin.name, admin.role, Scope::Full, pending.from, now)?;
        self.learn_admin_place(&admin.name, pending.from, now)?;
        self.audit.record(
            now,
            &admin.name,
            &from,
            "login",
            Outcome::Allowed,
            &format!("password and passkey '{used}'"),
        )?;
        self.alert_sign_in(
            &admin.name,
            pending.from,
            "with a password and a passkey",
            now,
        );
        Ok(Response::SignedIn {
            session: issued.token,
            csrf: issued.csrf,
            admin: admin.name,
            role: admin.role,
            scope: Scope::Full,
            must_change_password: admin.must_change_password,
            expires: issued.expires,
        })
    }

    fn server_status(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        Ok(Response::Server {
            server: self.control.status()?,
        })
    }

    fn list_sessions(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let sessions = self.control.sessions()?;
        let places = self.places(sessions.iter().filter_map(|vpn| vpn.remote_ip.as_deref()))?;
        Ok(Response::Sessions { sessions, places })
    }

    /// The live events numbered after `after`, or all that are kept, with
    /// the countries of their addresses.
    fn list_events(
        &mut self,
        token: &str,
        after: Option<u64>,
        now: u64,
    ) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let events = self.events.after(after);
        let places = self.places(events.iter().filter_map(|logged| match &logged.event.what {
            What::Connected { from, .. }
            | What::Disconnected { from, .. }
            | What::SignInFailed { from, .. }
            | What::LocationUnchecked { from, .. } => from.as_deref(),
            What::Banned { address, .. } => Some(address.as_str()),
            What::LocationRefused { from, .. } | What::LocationFlagged { from, .. } => {
                Some(from.as_str())
            }
        }))?;
        Ok(Response::Events {
            events,
            hours: self.events.hours(),
            places,
        })
    }

    /// Where the country database places each of `addresses` that lies in
    /// a country, or why there is no database to find them in.
    fn places<'a>(
        &self,
        addresses: impl IntoIterator<Item = &'a str>,
    ) -> Result<Result<Located, String>, String> {
        let named = match &self.countries.database {
            Ok(named) => named,
            Err(problem) => return Ok(Err(problem.clone())),
        };
        let mut places: Vec<Place> = Vec::new();
        for address in addresses {
            if places.iter().any(|place| place.address == address) {
                continue;
            }
            if let Some(code) = named.countries.lookup(address_in(address)?)? {
                let name = match named.names.get(&code) {
                    Some(name) => name.clone(),
                    None => code.clone(),
                };
                places.push(Place {
                    address: address.to_owned(),
                    code,
                    name,
                });
            }
        }
        Ok(Ok(Located {
            database: named.countries.kind().to_owned(),
            places,
        }))
    }

    /// Ends the VPN session `id` and invalidates its cookie, and audits whose
    /// session it was.
    fn end_vpn_session(
        &mut self,
        token: &str,
        csrf: &str,
        id: u64,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.session.end", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let user = self
            .control
            .sessions()?
            .into_iter()
            .find(|vpn| vpn.id == id)
            .map(|vpn| vpn.user);
        let ended = match user {
            Some(user) if self.control.end_session(id)? => user,
            Some(_) | None => {
                return Ok(Response::Invalid {
                    message: "that session has already ended".to_owned(),
                });
            }
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.session.end",
            Outcome::Allowed,
            &format!("ended session {id} of {ended}"),
        )?;
        Ok(Response::Done)
    }

    fn list_vpn_users(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let refused = self.refused_sign_ins()?;
        let places = self.places(refused.iter().map(|sign_in| sign_in.from.as_str()))?;
        let users = self.users.list()?;
        let vacations = users
            .iter()
            .filter_map(|user| {
                self.vacation_of(AccountKind::Vpn, &user.name, now)
                    .map(|until| (user.name.clone(), until))
            })
            .collect();
        Ok(Response::VpnUsers {
            users,
            codes: ServerConfig::read(&self.ocserv_config)?
                .otp_file()
                .is_some(),
            refused,
            places,
            locations_on: self.location_checks_on()?,
            vacations,
        })
    }

    /// When `name`'s vacation ends, while they are on one.
    fn vacation_of(&self, kind: AccountKind, name: &str, now: u64) -> Option<u64> {
        self.locations
            .learning
            .history(kind, name)
            .and_then(|history| history.vacation_until)
            .filter(|until| now < *until)
    }

    /// Puts a VPN user or an admin on vacation through `until`, or ends
    /// their vacation with none. An admin sets their own; an owner or
    /// operator sets anyone's.
    fn set_vacation(
        &mut self,
        token: &str,
        csrf: &str,
        kind: AccountKind,
        name: &str,
        until: Option<&str>,
        now: u64,
    ) -> Result<Response, String> {
        let action = "locations.vacation";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let own = kind == AccountKind::Admin && name == session.admin;
        if !own && matches!(self.admin_of(&session)?.role, Role::Viewer) {
            self.audit.record(
                now,
                &session.admin,
                &session.from.to_string(),
                action,
                Outcome::Denied,
                "viewers set a vacation only for themselves",
            )?;
            return Ok(Response::Invalid {
                message: "your role lets you set a vacation only for yourself".to_owned(),
            });
        }
        let whose = match kind {
            AccountKind::Vpn => format!("VPN user {name}"),
            AccountKind::Admin => format!("admin {name}"),
        };
        let exists = match kind {
            AccountKind::Vpn => self.users.list()?.iter().any(|user| user.name == name),
            AccountKind::Admin => self.store.get(name).is_some(),
        };
        if !exists {
            return Ok(Response::Invalid {
                message: format!("there is no {whose}"),
            });
        }
        let vacation = if own {
            "their own vacation".to_owned()
        } else {
            format!("the vacation of {whose}")
        };
        let (ends, detail) = match until {
            Some(date) => match location::vacation_end(date, now) {
                Ok(end) => (Some(end), format!("set {vacation} through {date}")),
                Err(problem) => return Ok(Response::Invalid { message: problem }),
            },
            None => (None, format!("ended {vacation}")),
        };
        if ends.is_some() || self.locations.learning.history(kind, name).is_some() {
            self.locations
                .learning
                .history_mut(kind, name)
                .vacation_until = ends;
            self.locations.learning.save()?;
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &detail,
        )?;
        Ok(Response::Done)
    }

    /// The VPN sign-ins the location checks refused in the events kept,
    /// newest first, each known when its place is among the user's usual
    /// places now.
    fn refused_sign_ins(&self) -> Result<Vec<RefusedSignIn>, String> {
        let mut refused = Vec::new();
        for logged in self.events.kept() {
            let What::LocationRefused {
                user,
                from,
                score,
                reasons,
            } = &logged.event.what
            else {
                continue;
            };
            let history = self.locations.learning.history(AccountKind::Vpn, user);
            let known = match (&self.locations.atlas, history) {
                (Some(atlas), Some(history)) => match atlas.place(address_in(from)?)? {
                    Some(place) => history.knows(&place),
                    None => false,
                },
                (Some(_atlas), None) => false,
                (None, _history) => false,
            };
            refused.push(RefusedSignIn {
                user: user.clone(),
                from: from.clone(),
                time: logged.event.time,
                score: *score,
                reasons: reasons.clone(),
                known,
            });
        }
        refused.reverse();
        Ok(refused)
    }

    /// Makes the place of `from` usual for VPN user `user`, as where they
    /// are now, for an owner or operator: Allow this place, after the
    /// location checks refused a sign-in from it.
    fn allow_place(
        &mut self,
        token: &str,
        csrf: &str,
        user: &str,
        from: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "locations.allow";
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        if !self.users.list()?.iter().any(|known| known.name == user) {
            return Ok(Response::Invalid {
                message: format!("there is no VPN user named {user}"),
            });
        }
        let address = match address_in(from) {
            Ok(address) => address,
            Err(problem) => return Ok(Response::Invalid { message: problem }),
        };
        let Some(atlas) = &self.locations.atlas else {
            return Ok(Response::Invalid {
                message: "the location checks have no city data to place the address with"
                    .to_owned(),
            });
        };
        let Some(place) = atlas.place(address)? else {
            return Ok(Response::Invalid {
                message: format!("the city data places {address} nowhere"),
            });
        };
        self.locations
            .learning
            .history_mut(AccountKind::Vpn, user)
            .allow(&place, now);
        self.locations.learning.save()?;
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!(
                "allowed {address}{} for {user}'s VPN sign-ins",
                self.country_words(address)
            ),
        )?;
        Ok(Response::Done)
    }

    /// Answers a request of the VPN user portal. A failure inside the helper
    /// is answered as `Error` with what failed.
    fn portal(&mut self, request: PortalRequest, now: u64) -> PortalResponse {
        let result = match request {
            PortalRequest::Login {
                name,
                mut password,
                mut code,
                from,
            } => {
                let result = self.portal_login(&name, &password, code.as_deref(), &from, now);
                password.zeroize();
                if let Some(code) = code.as_mut() {
                    code.zeroize();
                }
                result
            }
            PortalRequest::Whoami { session } => {
                Ok(match self.portal_sessions.touch(&session, now) {
                    Some(found) => PortalResponse::User {
                        expires: self.portal_sessions.expires(&found),
                        user: found.user,
                        scope: found.scope,
                        csrf: found.csrf,
                    },
                    None => PortalResponse::Denied,
                })
            }
            PortalRequest::Code { pending, mut code } => {
                let result = self.portal_code(&pending, &code, now);
                code.zeroize();
                result
            }
            PortalRequest::KeyBegin {
                session,
                csrf,
                mut old_code,
            } => {
                let result = self.portal_key_begin(&session, &csrf, old_code.as_deref(), now);
                if let Some(code) = old_code.as_mut() {
                    code.zeroize();
                }
                result
            }
            PortalRequest::Account { session } => self.portal_account(&session, now),
            PortalRequest::ChangePassword {
                session,
                csrf,
                mut current,
                mut new,
            } => {
                let result = self.portal_change_password(&session, &csrf, &current, &new, now);
                current.zeroize();
                new.zeroize();
                result
            }
            PortalRequest::EndSession { session, csrf, id } => {
                self.portal_end_session(&session, &csrf, id, now)
            }
            PortalRequest::KeyConfirm {
                session,
                csrf,
                mut code,
            } => {
                let result = self.portal_key_confirm(&session, &csrf, &code, now);
                code.zeroize();
                result
            }
            PortalRequest::Home { session } => self.portal_home(&session, now),
            PortalRequest::Logout { session } => self.portal_logout(&session, now),
        };
        match result {
            Ok(response) => response,
            Err(message) => PortalResponse::Error { message },
        }
    }

    /// Signs a VPN user in to the portal: the password, then the code while
    /// the VPN asks for codes. While it does, a user without a key gets a
    /// session that can only enroll one. Failures count per address and per
    /// user, apart from the admin panel's, and every attempt is audited.
    fn portal_login(
        &mut self,
        name: &str,
        password: &str,
        code: Option<&str>,
        from: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        let address = from
            .parse::<IpAddr>()
            .map_err(|error| format!("'{from}' is not an IP address: {error}"))?
            .to_canonical();
        let from = address.to_string();
        let blocked = match self.portal_limiter.blocked(address, now) {
            Some(retry_after) => Some(retry_after),
            None => self.portal_lockout.locked(name, now),
        };
        if let Some(retry_after) = blocked {
            self.audit.record(
                now,
                name,
                &from,
                "portal.login",
                Outcome::Denied,
                &format!("refused for {retry_after} more seconds after repeated failures"),
            )?;
            return Ok(PortalResponse::Locked { retry_after });
        }
        let reason = match self.users.check_password(name, password)? {
            PasswordCheck::Accepted => None,
            PasswordCheck::Wrong => Some("wrong password".to_owned()),
            PasswordCheck::Unknown => Some("no VPN user of that name".to_owned()),
            PasswordCheck::Locked => Some("the VPN user is locked".to_owned()),
            PasswordCheck::Unsupported(reason) => Some(reason),
        };
        if let Some(reason) = reason {
            return self.portal_refused(name, &from, address, &reason, now);
        }
        let (codes, has_key) = self.codes_and_key(name)?;
        let (scope, detail) = match (codes, has_key, code) {
            (false, _, _) => (PortalScope::Full, "password; the VPN asks for no codes"),
            (true, false, _) => (
                PortalScope::EnrollKey,
                "password; the session may only set up a key, since the user has none",
            ),
            (true, true, None) => {
                let pending = self.portal_pending.create(name, address, now)?;
                return Ok(PortalResponse::CodeRequired { pending });
            }
            (true, true, Some(code)) => match self.users.check_code(name, code, now)? {
                CodeCheck::Accepted => (PortalScope::Full, "password and code"),
                CodeCheck::Wrong => {
                    return self.portal_refused(name, &from, address, "wrong code", now);
                }
                CodeCheck::Used => {
                    return self.portal_refused(name, &from, address, "a code used already", now);
                }
                CodeCheck::NoSecret => {
                    return self.portal_refused(
                        name,
                        &from,
                        address,
                        "the user's key went away during the sign-in",
                        now,
                    );
                }
            },
        };
        self.portal_session(name, address, scope, detail, now)
    }

    /// Completes a portal sign-in waiting for its code. A wrong code ends
    /// the pending sign-in and counts as a failure.
    fn portal_code(&mut self, token: &str, code: &str, now: u64) -> Result<PortalResponse, String> {
        let Some(pending) = self.portal_pending.take(token, now) else {
            return Ok(PortalResponse::Denied);
        };
        let (name, address) = (pending.admin, pending.from);
        let from = address.to_string();
        if let Some(retry_after) = self.portal_lockout.locked(&name, now) {
            return Ok(PortalResponse::Locked { retry_after });
        }
        match self.users.check_code(&name, code, now)? {
            CodeCheck::Accepted => {
                self.portal_session(&name, address, PortalScope::Full, "password and code", now)
            }
            CodeCheck::Wrong => self.portal_refused(&name, &from, address, "wrong code", now),
            CodeCheck::Used => {
                self.portal_refused(&name, &from, address, "a code used already", now)
            }
            CodeCheck::NoSecret => self.portal_refused(
                &name,
                &from,
                address,
                "the user's key went away during the sign-in",
                now,
            ),
        }
    }

    /// Opens a portal session after a sign-in succeeded, clearing the
    /// failure counts it was held to.
    fn portal_session(
        &mut self,
        name: &str,
        address: IpAddr,
        scope: PortalScope,
        detail: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        self.portal_limiter.success(address);
        self.portal_lockout.success(name);
        let issued = self.portal_sessions.create(name, scope, address, now)?;
        self.audit.record(
            now,
            name,
            &address.to_string(),
            "portal.login",
            Outcome::Allowed,
            detail,
        )?;
        Ok(PortalResponse::SignedIn {
            session: issued.token,
            csrf: issued.csrf,
            user: name.to_owned(),
            scope,
            expires: issued.expires,
        })
    }

    /// Refuses a portal sign-in: counts it against the address and the user,
    /// and audits why.
    fn portal_refused(
        &mut self,
        name: &str,
        from: &str,
        address: IpAddr,
        reason: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        self.portal_limiter.failure(address, now);
        let detail = if self.portal_lockout.failure(name, now) {
            format!(
                "{reason}; the user is refused for {} seconds",
                self.policy.lockout
            )
        } else {
            reason.to_owned()
        };
        self.audit
            .record(now, name, from, "portal.login", Outcome::Denied, &detail)?;
        Ok(PortalResponse::Denied)
    }

    /// Whether the VPN asks for codes, and whether `name` has a key for them.
    fn codes_and_key(&mut self, name: &str) -> Result<(bool, bool), String> {
        let codes = ServerConfig::read(&self.ocserv_config)?
            .otp_file()
            .is_some();
        let has_key = codes
            && self
                .users
                .list()?
                .iter()
                .any(|user| user.name == name && user.otp);
        Ok((codes, has_key))
    }

    /// The live portal session for `token`, when `csrf` is its token.
    fn portal_checked(&mut self, token: &str, csrf: &str, now: u64) -> Option<PortalSession> {
        self.portal_sessions
            .touch(token, now)
            .filter(|session| secret::equal(session.csrf.as_bytes(), csrf.as_bytes()))
    }

    /// Why the portal may not set up a key for `name`: the VPN asks for no
    /// codes, or the user has a key that this setup does not replace.
    fn key_refusal(
        &mut self,
        name: &str,
        replaces: bool,
    ) -> Result<Option<PortalResponse>, String> {
        let message = match self.codes_and_key(name)? {
            (false, _) => "the VPN asks for no codes, so there is no authenticator key to set up",
            (true, true) if !replaces => {
                "you have an authenticator key already; replace it with a code from it"
            }
            (true, _) => return Ok(None),
        };
        Ok(Some(PortalResponse::Invalid {
            message: message.to_owned(),
        }))
    }

    /// Refuses a change whose proof does not match, the current password or
    /// a code from the current key: counts it against the user and the
    /// address as a failed sign-in, and audits it. A failure that locks the
    /// user out also ends their portal sessions.
    fn portal_mistake(
        &mut self,
        session: &PortalSession,
        action: &str,
        reason: &str,
        message: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        self.portal_limiter.failure(session.from, now);
        let locked = self.portal_lockout.failure(&session.user, now);
        let detail = if locked {
            self.portal_sessions.end_user(&session.user, None);
            format!(
                "{reason}; the user is refused for {} seconds and their portal sessions ended",
                self.policy.lockout
            )
        } else {
            reason.to_owned()
        };
        self.audit.record(
            now,
            &session.user,
            &session.from.to_string(),
            action,
            Outcome::Denied,
            &detail,
        )?;
        Ok(if locked {
            PortalResponse::Locked {
                retry_after: self.policy.lockout,
            }
        } else {
            PortalResponse::Invalid {
                message: message.to_owned(),
            }
        })
    }

    /// Issues the session's user a new authenticator key to confirm with a
    /// code, replacing one issued before and not confirmed. A user who has a
    /// key gets a replacement only for `old_code`, a code from that key.
    fn portal_key_begin(
        &mut self,
        token: &str,
        csrf: &str,
        old_code: Option<&str>,
        now: u64,
    ) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_checked(token, csrf, now) else {
            return Ok(PortalResponse::Denied);
        };
        let replaces = match (self.codes_and_key(&session.user)?, old_code) {
            ((false, _), _) => {
                return Ok(PortalResponse::Invalid {
                    message: "the VPN asks for no codes, so there is no authenticator key to set \
                              up"
                    .to_owned(),
                });
            }
            ((true, false), _) => false,
            ((true, true), None) => {
                return Ok(PortalResponse::Invalid {
                    message: "enter a code from your current authenticator app to replace its key"
                        .to_owned(),
                });
            }
            ((true, true), Some(code)) => match self.users.check_code(&session.user, code, now)? {
                CodeCheck::Accepted => true,
                CodeCheck::Wrong | CodeCheck::Used | CodeCheck::NoSecret => {
                    return self.portal_mistake(
                        &session,
                        "portal.key.begin",
                        "a wrong code from the current authenticator key",
                        "that code from your current authenticator app did not match",
                        now,
                    );
                }
            },
        };
        let (authenticator, hex) =
            Authenticator::new(&session.user, &self.vpn_address.host.authority())?;
        self.portal_keys.insert(
            session.user.clone(),
            KeyEnrollment {
                authenticator: authenticator.clone(),
                hex,
                created: now,
                replaces,
            },
        );
        self.audit.record(
            now,
            &session.user,
            &session.from.to_string(),
            "portal.key.begin",
            Outcome::Allowed,
            if replaces {
                "a replacement authenticator key was issued for confirmation, after a code from \
                 the current one"
            } else {
                "a new authenticator key was issued for confirmation"
            },
        )?;
        Ok(PortalResponse::Key {
            authenticator,
            wrong: false,
        })
    }

    /// Saves the key `portal_key_begin` issued when `code` matches it, and
    /// gives an enrollment-only session the full portal. After a wrong code
    /// the same key waits for another.
    fn portal_key_confirm(
        &mut self,
        token: &str,
        csrf: &str,
        code: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_checked(token, csrf, now) else {
            return Ok(PortalResponse::Denied);
        };
        let from = session.from.to_string();
        let Some(enrollment) = self.portal_keys.remove(&session.user) else {
            return Ok(PortalResponse::Invalid {
                message: "start setting up the authenticator app first".to_owned(),
            });
        };
        if now >= enrollment.created + self.second_factor_window {
            return Ok(PortalResponse::Invalid {
                message: "the setup took too long; start again for a new key".to_owned(),
            });
        }
        if let Some(refusal) = self.key_refusal(&session.user, enrollment.replaces)? {
            return Ok(refusal);
        }
        if totp::verify(&enrollment.authenticator.key, code, now, None)?.is_none() {
            self.audit.record(
                now,
                &session.user,
                &from,
                "portal.key.confirm",
                Outcome::Denied,
                "the code did not match the new authenticator key",
            )?;
            let authenticator = enrollment.authenticator.clone();
            self.portal_keys.insert(session.user.clone(), enrollment);
            return Ok(PortalResponse::Key {
                authenticator,
                wrong: true,
            });
        }
        self.users.set_otp(&session.user, &enrollment.hex)?;
        let detail = match (session.scope, enrollment.replaces) {
            (PortalScope::EnrollKey, _) => {
                if !self.portal_sessions.widen(token) {
                    return Err("the session ended while its key was being set up".to_owned());
                }
                "authenticator key set up; the session has the full portal"
            }
            (PortalScope::Full, true) => "authenticator key replaced; the old key no longer works",
            (PortalScope::Full, false) => "authenticator key set up",
        };
        self.audit.record(
            now,
            &session.user,
            &from,
            "portal.key.confirm",
            Outcome::Allowed,
            detail,
        )?;
        Ok(PortalResponse::Done)
    }

    /// The session's user's account page: their VPN sessions, whether they
    /// have a key, and whether they signed in recently enough to change the
    /// password. A session that may only set up a key has no account page.
    fn portal_account(&mut self, token: &str, now: u64) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_sessions.touch(token, now) else {
            return Ok(PortalResponse::Denied);
        };
        if !matches!(session.scope, PortalScope::Full) {
            return Ok(PortalResponse::Invalid {
                message: "set up your authenticator app first".to_owned(),
            });
        }
        let (codes, has_key) = self.codes_and_key(&session.user)?;
        let sessions: Vec<VpnSession> = self
            .control
            .sessions()?
            .into_iter()
            .filter(|vpn| vpn.user == session.user)
            .collect();
        let this_session = vpn_session_at(&sessions, session.from)?;
        Ok(PortalResponse::Account {
            recent: now < session.authenticated + self.policy.reauth,
            user: session.user,
            csrf: session.csrf,
            codes,
            has_key,
            sessions,
            this_session,
        })
    }

    /// Replaces the session's user's password after checking the current
    /// one, within a recent sign-in, and ends their other sessions: every
    /// VPN session but the one the browser signed in through, and every
    /// other portal session.
    fn portal_change_password(
        &mut self,
        token: &str,
        csrf: &str,
        current: &str,
        new: &str,
        now: u64,
    ) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_checked(token, csrf, now) else {
            return Ok(PortalResponse::Denied);
        };
        if !matches!(session.scope, PortalScope::Full) {
            return Ok(PortalResponse::Denied);
        }
        if now >= session.authenticated + self.policy.reauth {
            return Ok(PortalResponse::Invalid {
                message: "sign in again before you change your password".to_owned(),
            });
        }
        if let Some(retry_after) = self.portal_lockout.locked(&session.user, now) {
            return Ok(PortalResponse::Locked { retry_after });
        }
        match self.users.check_password(&session.user, current)? {
            PasswordCheck::Accepted => {}
            PasswordCheck::Wrong => {
                return self.portal_mistake(
                    &session,
                    "portal.password",
                    "wrong current password",
                    "the current password is wrong",
                    now,
                );
            }
            PasswordCheck::Unknown | PasswordCheck::Locked => {
                self.portal_sessions.end_user(&session.user, None);
                return Ok(PortalResponse::Denied);
            }
            PasswordCheck::Unsupported(message) => return Ok(PortalResponse::Invalid { message }),
        }
        if let Err(message) = vpnusers::check_password(new, self.policy.min_password_length) {
            return Ok(PortalResponse::Invalid { message });
        }
        if secret::equal(new.as_bytes(), current.as_bytes()) {
            return Ok(PortalResponse::Invalid {
                message: "the new password must differ from the current one".to_owned(),
            });
        }
        let groups = self
            .users
            .list()?
            .into_iter()
            .find(|user| user.name == session.user)
            .map(|user| user.groups);
        let Some(groups) = groups else {
            self.portal_sessions.end_user(&session.user, None);
            return Ok(PortalResponse::Denied);
        };
        self.users.set_password(&session.user, &groups, new)?;
        let sessions: Vec<VpnSession> = self
            .control
            .sessions()?
            .into_iter()
            .filter(|vpn| vpn.user == session.user)
            .collect();
        let keep = vpn_session_at(&sessions, session.from)?;
        let mut ended = 0;
        for vpn in sessions.iter().filter(|vpn| Some(vpn.id) != keep) {
            if self.control.end_session(vpn.id)? {
                ended += 1;
            }
        }
        let portals = self.portal_sessions.end_user(&session.user, Some(token));
        self.audit.record(
            now,
            &session.user,
            &session.from.to_string(),
            "portal.password",
            Outcome::Allowed,
            &format!(
                "password changed; ended {ended} other VPN and {portals} other portal sessions"
            ),
        )?;
        Ok(PortalResponse::Done)
    }

    /// Ends one of the session's user's own VPN sessions.
    fn portal_end_session(
        &mut self,
        token: &str,
        csrf: &str,
        id: u64,
        now: u64,
    ) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_checked(token, csrf, now) else {
            return Ok(PortalResponse::Denied);
        };
        if !matches!(session.scope, PortalScope::Full) {
            return Ok(PortalResponse::Denied);
        }
        let theirs = self
            .control
            .sessions()?
            .iter()
            .any(|vpn| vpn.id == id && vpn.user == session.user);
        if !theirs || !self.control.end_session(id)? {
            return Ok(PortalResponse::Invalid {
                message: "that VPN session has ended already".to_owned(),
            });
        }
        self.audit.record(
            now,
            &session.user,
            &session.from.to_string(),
            "portal.session.end",
            Outcome::Allowed,
            &format!("ended VPN session {id}"),
        )?;
        Ok(PortalResponse::Done)
    }

    /// The portal's home page for the session's user: how to reach the
    /// server and set up a client, as the onboarding kit gives it without a
    /// password or a key, and whether they need a key. A session that may
    /// only set up a key gets no kit. A user removed since signing in loses
    /// every portal session.
    fn portal_home(&mut self, token: &str, now: u64) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_sessions.touch(token, now) else {
            return Ok(PortalResponse::Denied);
        };
        let groups = self
            .users
            .list()?
            .into_iter()
            .find(|user| user.name == session.user)
            .map(|user| user.groups);
        let Some(groups) = groups else {
            self.portal_sessions.end_user(&session.user, None);
            return Ok(PortalResponse::Denied);
        };
        let (codes, has_key) = self.codes_and_key(&session.user)?;
        let kit = match session.scope {
            PortalScope::Full => Some(Box::new(self.kit_server()?.kit(
                &session.user,
                &groups,
                None,
                None,
            ))),
            PortalScope::EnrollKey => None,
        };
        Ok(PortalResponse::Home {
            user: session.user,
            scope: session.scope,
            csrf: session.csrf,
            kit,
            needs_key: codes && !has_key,
        })
    }

    fn portal_logout(&mut self, token: &str, now: u64) -> Result<PortalResponse, String> {
        let Some(session) = self.portal_sessions.touch(token, now) else {
            return Ok(PortalResponse::Denied);
        };
        self.portal_sessions.end(token);
        self.audit.record(
            now,
            &session.user,
            &session.from.to_string(),
            "portal.logout",
            Outcome::Allowed,
            "session ended",
        )?;
        Ok(PortalResponse::Done)
    }

    /// What every onboarding kit tells about the server, from the
    /// configuration it runs with.
    fn kit_server(&self) -> Result<kit::Server, String> {
        let config = ServerConfig::read(&self.ocserv_config)?;
        kit::Server::of(&config, &self.vpn_address.text())
    }

    /// Makes `name` a new authenticator key and writes it to the one-time
    /// password file.
    fn new_authenticator(&mut self, name: &str) -> Result<Authenticator, String> {
        let (authenticator, hex) = Authenticator::new(name, &self.vpn_address.host.authority())?;
        self.users.set_otp(name, &hex)?;
        Ok(authenticator)
    }

    /// Adds, changes or removes a VPN user. Locking or removing one also
    /// ends their sessions, since ocserv checks the file only at sign-in. A
    /// change that sets a password or an authenticator key is answered with
    /// the user's onboarding kit; what the kit says about the server is read
    /// first, so that a failure there changes nothing.
    fn change_vpn_user(
        &mut self,
        token: &str,
        csrf: &str,
        change: &UserChange,
        now: u64,
    ) -> Result<Response, String> {
        let action = change.action();
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let name = change.name();
        let refused = |message: String| Ok(Response::Invalid { message });
        if let Err(message) = vpnusers::check_name(name, "user name") {
            return refused(message);
        }
        let existing = self
            .users
            .list()?
            .into_iter()
            .find(|user| user.name == name);
        let (detail, kit) = match (change, existing) {
            (UserChange::Add { .. }, Some(_)) => {
                return refused(format!("a user named {name} already exists"));
            }
            (
                UserChange::Add {
                    groups, password, ..
                },
                None,
            ) => {
                let groups = match vpnusers::parse_groups(groups) {
                    Ok(groups) => groups,
                    Err(message) => return refused(message),
                };
                let min = self.policy.min_password_length;
                let chosen = match chosen_password(password.as_deref(), min)? {
                    Chosen::Password(chosen) => chosen,
                    Chosen::Refused(message) => return refused(message),
                };
                let server = self.kit_server()?;
                let authenticator = match server.codes {
                    true => Some(self.new_authenticator(name)?),
                    false => None,
                };
                if let Err(error) = self.users.set_password(name, &groups, &chosen) {
                    if authenticator.is_some()
                        && let Err(undo) = self.users.remove_otp(name)
                    {
                        return Err(format!(
                            "{error}; the authenticator key written for {name} could not be \
                             removed either: {undo}"
                        ));
                    }
                    return Err(error);
                }
                let mut detail = match groups.as_slice() {
                    [] => format!("added {name}"),
                    groups => format!("added {name} in {}", groups.join(", ")),
                };
                detail.push_str(match (password.is_none(), authenticator.is_some()) {
                    (true, true) => " with a generated password and an authenticator key",
                    (true, false) => " with a generated password",
                    (false, true) => " with an authenticator key",
                    (false, false) => "",
                });
                let kit = server.kit(name, &groups, Some(chosen.to_string()), authenticator);
                (detail, Some(kit))
            }
            (_, None) => return refused(format!("there is no user named {name}")),
            (UserChange::SetPassword { password, .. }, Some(user)) => {
                let min = self.policy.min_password_length;
                let chosen = match chosen_password(password.as_deref(), min)? {
                    Chosen::Password(chosen) => chosen,
                    Chosen::Refused(message) => return refused(message),
                };
                let server = self.kit_server()?;
                self.users.set_password(name, &user.groups, &chosen)?;
                let detail = match password {
                    Some(_) => format!("replaced the password of {name}"),
                    None => format!("replaced the password of {name} with a generated one"),
                };
                let kit = server.kit(name, &user.groups, Some(chosen.to_string()), None);
                (detail, Some(kit))
            }
            (UserChange::SetGroups { groups, .. }, Some(user)) => {
                let groups = match vpnusers::parse_groups(groups) {
                    Ok(groups) => groups,
                    Err(message) => return refused(message),
                };
                if groups == user.groups {
                    return Ok(Response::Done);
                }
                self.users.set_groups(name, &groups)?;
                let detail = match groups.as_slice() {
                    [] => format!("took {name} out of every group"),
                    groups => format!("set the groups of {name} to {}", groups.join(", ")),
                };
                (detail, None)
            }
            (UserChange::ResetOtp { .. }, Some(user)) => {
                let server = self.kit_server()?;
                if !server.codes {
                    return refused(
                        "the VPN does not ask for codes: ocserv found no one-time password \
                         file when it started"
                            .to_owned(),
                    );
                }
                let authenticator = self.new_authenticator(name)?;
                let kit = server.kit(name, &user.groups, None, Some(authenticator));
                (format!("gave {name} a new authenticator key"), Some(kit))
            }
            (UserChange::Lock { .. }, Some(_)) => {
                self.users.lock(name)?;
                let detail = ended(
                    format!("locked {name}"),
                    self.control.end_user_sessions(name)?,
                );
                (detail, None)
            }
            (UserChange::Unlock { .. }, Some(_)) => {
                self.users.unlock(name)?;
                (format!("unlocked {name}"), None)
            }
            (UserChange::Remove { .. }, Some(_)) => {
                self.users.remove(name)?;
                let mut removed = match self.users.remove_otp(name)? {
                    true => format!("removed {name} and their authenticator key"),
                    false => format!("removed {name}"),
                };
                if self
                    .locations
                    .learning
                    .forget_account(AccountKind::Vpn, name)
                {
                    self.locations.learning.save()?;
                }
                let certificates = self.client_certificates.active_of(name, now);
                self.revoke_certificates(&session.admin, &certificates, now)?;
                match certificates.len() {
                    0 => {}
                    1 => removed.push_str(" and revoked their certificate"),
                    count => removed.push_str(&format!(" and revoked their {count} certificates")),
                }
                if self.sites.set_egress(name, false)? {
                    removed.push_str(" and kept their site's networks inside the VPN");
                    self.sync_sites()?;
                }
                (ended(removed, self.control.end_user_sessions(name)?), None)
            }
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &detail,
        )?;
        Ok(match kit {
            Some(kit) => Response::Kit { kit: Box::new(kit) },
            None => Response::Done,
        })
    }

    fn list_bans(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        Ok(Response::Bans {
            banned: self.control.bans()?,
            points: self.control.ban_points()?,
            policy: BanPolicy::of(&ServerConfig::read(&self.ocserv_config)?)?,
            blocks: self.blocklist.active(now).cloned().collect(),
            auto: self.blocklist.auto(),
            countries: Box::new(self.country_view()?),
            locations: Box::new(self.location_view()?),
        })
    }

    /// The country rules in force and where they come from, the database's
    /// countries, and the countries of the failed sign-ins and connects
    /// kept.
    fn country_view(&self) -> Result<CountryView, String> {
        let setup = &self.countries;
        let stored = countries::read_stored(&setup.stored)?;
        let effective = countries::effective(&setup.environment, &stored);
        let (database, names, seen, built) = match &setup.database {
            Ok(named) => (
                Ok(named.countries.kind().to_owned()),
                named
                    .names
                    .iter()
                    .map(|(code, name)| (code.clone(), name.clone()))
                    .collect(),
                self.event_countries(&named.countries)?,
                named.countries.built(),
            ),
            Err(problem) => (
                Err(problem.clone()),
                Vec::new(),
                EventCountries {
                    failed: Vec::new(),
                    connected: Vec::new(),
                },
                0,
            ),
        };
        let maxmind = &setup.maxmind;
        Ok(CountryView {
            rule: effective.rule,
            listed: countries::codes(&effective.countries),
            rule_from_env: setup.environment.rule.is_some(),
            list_from_env: setup.environment.countries.is_some(),
            enforceable: self.firewall.backend() == Backend::Nftables,
            database,
            names,
            failed: seen.failed,
            connected: seen.connected,
            hours: self.events.hours(),
            built,
            maxmind_account: maxmind.key()?.map(|key| key.account),
            maxmind_from_env: maxmind.environment.is_some(),
            maxmind_busy: maxmind.busy,
            maxmind_last: maxmind.last.clone(),
        })
    }

    /// Hands a MaxMind key an owner typed to the download thread, which
    /// keeps it once a download with it works.
    fn set_maxmind_key(
        &mut self,
        token: &str,
        csrf: &str,
        account: &str,
        license: &str,
        now: u64,
    ) -> Result<Response, String> {
        let key = geoip::Key {
            account: account.trim().to_owned(),
            license: license.trim().to_owned(),
        };
        self.change_maxmind("geoip.key", token, csrf, now, |maxmind| {
            geoip::check_key(&key)?;
            let detail = format!(
                "asked for a GeoLite2 download with MaxMind account {}",
                key.account
            );
            maxmind.candidate = Some(key);
            Ok(detail)
        })
    }

    /// Removes the MaxMind key the panel keeps and its GeoLite2 copy, and has
    /// the download thread read DB-IP Lite again.
    fn remove_maxmind_key(
        &mut self,
        token: &str,
        csrf: &str,
        now: u64,
    ) -> Result<Response, String> {
        self.change_maxmind("geoip.key.remove", token, csrf, now, |maxmind| {
            if maxmind.key()?.is_none() {
                return Err("there is no MaxMind key to remove".to_owned());
            }
            geoip::remove(&maxmind.key_file)?;
            geoip::remove(&maxmind.database_file)?;
            maxmind.reread = true;
            Ok("removed the MaxMind key and its GeoLite2 copy".to_owned())
        })
    }

    /// Makes `change` to MaxMind's key for an owner with full access, while
    /// the environment sets no key and no download is under way, then wakes
    /// the download thread. A refusal or a failed change is answered and
    /// audited as refused.
    fn change_maxmind(
        &mut self,
        action: &str,
        token: &str,
        csrf: &str,
        now: u64,
        change: impl FnOnce(&mut geoip::Maxmind) -> Result<String, String>,
    ) -> Result<Response, String> {
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let owner = matches!(self.admin_of(&session)?.role, Role::Owner);
        let maxmind = &mut self.countries.maxmind;
        let outcome = if !owner {
            Err(CHANGE_COUNTRIES.to_owned())
        } else if maxmind.environment.is_some() {
            Err("the MaxMind key is set in the container's environment, which wins".to_owned())
        } else if maxmind.busy {
            Err("a GeoLite2 download is under way; try again once it ends".to_owned())
        } else {
            change(maxmind).and_then(|detail| {
                maxmind.busy = true;
                maxmind.wake().map(|()| detail)
            })
        };
        let (result, detail, response) = match outcome {
            Ok(detail) => (Outcome::Allowed, detail, Response::Done),
            Err(message) => (
                Outcome::Denied,
                message.clone(),
                Response::Invalid { message },
            ),
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            result,
            &detail,
        )?;
        Ok(response)
    }

    /// The next thing the download thread is to do.
    pub fn take_geoip_job(&mut self) -> Result<geoip::Job, String> {
        self.countries.maxmind.take_job()
    }

    /// Records what the download thread did at `now`: `outcome`, and when
    /// it has one, the database it read again, with which the country rules
    /// in force load anew, since their networks come from it.
    pub fn finish_geoip(
        &mut self,
        now: u64,
        outcome: Result<String, String>,
        database: Option<Result<countries::Named, String>>,
    ) -> Result<(), String> {
        let (result, detail) = match &outcome {
            Ok(done) => (Outcome::Allowed, done.clone()),
            Err(why) => (
                Outcome::Denied,
                format!("the GeoLite2 download failed: {why}"),
            ),
        };
        self.audit.record(
            now,
            blocklist::AUTOMATIC,
            LOCAL,
            "geoip.download",
            result,
            &detail,
        )?;
        let maxmind = &mut self.countries.maxmind;
        maxmind.busy = false;
        maxmind.last = Some((now, outcome));
        let Some(database) = database else {
            return Ok(());
        };
        self.countries.database = database;
        let stored = countries::read_stored(&self.countries.stored)?;
        let effective = countries::effective(&self.countries.environment, &stored);
        let input = countries::input_for(&effective, &self.countries.environment)?;
        if input.is_some() && self.firewall.backend() == Backend::Nftables {
            self.firewall.load_countries(input.as_ref())?;
        }
        Ok(())
    }

    /// What the Alerts page shows the session's admin.
    fn alerts_page(&mut self, token: &str, now: u64) -> Result<Response, String> {
        let Some(session) = self.full_session(token, now) else {
            return Ok(Response::Denied);
        };
        let admin = self.admin_of(&session)?;
        let owner = matches!(admin.role, Role::Owner);
        let (topics, channels) = match self.alerts.choice(&admin.name) {
            Some(choice) => (
                choice.topics.iter().copied().collect(),
                choice
                    .channels
                    .iter()
                    .map(|channel| ChannelView {
                        id: channel.id,
                        kind: channel.target.kind().to_owned(),
                        label: channel.target.label(),
                        unencrypted: channel.target.unencrypted(),
                        added: channel.added,
                        status: self.alerts.status(channel.id),
                    })
                    .collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        let mail = self.alerts.mail();
        let stored = countries::read_stored(&self.countries.stored)?;
        let effective = countries::effective(&self.countries.environment, &stored);
        let view = AlertsView {
            topics,
            owner,
            channels,
            max_channels: alerts::MAX_CHANNELS,
            mail_set: mail.is_some(),
            mail_from_env: self.alerts.mail_from_environment(),
            mail: match mail {
                Some(server) if owner => Some(MailView {
                    label: server.label(),
                    host: server.host.clone(),
                    port: server.port,
                    security: server.security,
                    user: server.user.clone(),
                    password_set: server.password.is_some(),
                    from: server.from.clone(),
                }),
                Some(_not_an_owner) => None,
                None => None,
            },
            country_rules_on: effective.rule != "off"
                && self.firewall.backend() == Backend::Nftables,
        };
        Ok(Response::Alerts {
            view: Box::new(view),
        })
    }

    /// The live session for `token` when `csrf` is its CSRF token and it has
    /// full access, for a change to its admin's own alerts, which every role
    /// may make; otherwise the refusal to answer with.
    fn alert_session(
        &mut self,
        token: &str,
        csrf: &str,
        action: &str,
        now: u64,
    ) -> Result<Result<Session, Response>, String> {
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Err(Response::Denied));
        }
        Ok(Ok(session))
    }

    /// Audits what a change to alerts did, or why it was refused, as
    /// `action` by the session's admin, and answers with `Done` or the
    /// refusal.
    fn audited(
        &mut self,
        session: &Session,
        action: &str,
        outcome: Result<String, String>,
        now: u64,
    ) -> Result<Response, String> {
        let (result, detail, response) = match outcome {
            Ok(detail) => (Outcome::Allowed, detail, Response::Done),
            Err(message) => (
                Outcome::Denied,
                message.clone(),
                Response::Invalid { message },
            ),
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            result,
            &detail,
        )?;
        Ok(response)
    }

    /// Replaces the topics that alert the session's admin.
    fn set_alert_topics(
        &mut self,
        token: &str,
        csrf: &str,
        topics: &[Topic],
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.topics";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let chosen: BTreeSet<Topic> = topics.iter().copied().collect();
        let detail = match chosen.is_empty() {
            true => "chose no alerts".to_owned(),
            false => {
                let words: Vec<&str> = chosen.iter().map(|topic| topic.words()).collect();
                format!("chose alerts for {}", words.join(", "))
            }
        };
        self.alerts.set_topics(&session.admin, chosen)?;
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &detail,
        )?;
        Ok(Response::Done)
    }

    /// Adds a channel for the session's admin, once it checks out.
    fn add_alert_channel(
        &mut self,
        token: &str,
        csrf: &str,
        entry: &ChannelEntry,
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.channel.add";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let target = match entry {
            ChannelEntry::Ntfy {
                server,
                topic,
                token: access,
            } => alerts::ntfy(server, topic, access),
            ChannelEntry::Telegram { token: bot, chat } => alerts::telegram(bot, chat),
            ChannelEntry::Webhook { url } => alerts::webhook(url),
            ChannelEntry::Email { address } => alerts::email(address),
        };
        let outcome = match target {
            Ok(target) => {
                let added = format!(
                    "added {} channel: {}",
                    target.kind_with_article(),
                    target.label()
                );
                self.alerts
                    .add(&session.admin, target, now)?
                    .map(|_id| added)
            }
            Err(message) => Err(message),
        };
        self.audited(&session, action, outcome, now)
    }

    /// Removes the session's admin's channel `id`.
    fn remove_alert_channel(
        &mut self,
        token: &str,
        csrf: &str,
        id: u32,
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.channel.remove";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let outcome = match self.alerts.remove(&session.admin, id)? {
            Some(channel) => Ok(format!(
                "removed the {} channel {}",
                channel.target.kind(),
                channel.target.label()
            )),
            None => Err("you have no such channel".to_owned()),
        };
        self.audited(&session, action, outcome, now)
    }

    /// Queues a test message for the session's admin's channel `id`.
    fn test_alert_channel(
        &mut self,
        token: &str,
        csrf: &str,
        id: u32,
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.test";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let asked = self.alerts.channel(&session.admin, id).map(|channel| {
            format!(
                "asked for a test message on the {} channel {}",
                channel.target.kind(),
                channel.target.label()
            )
        });
        let outcome = match asked {
            Some(asked) => match self.alerts.test(&session.admin, id, now) {
                true => Ok(asked),
                false => Err("you have no such channel".to_owned()),
            },
            None => Err("you have no such channel".to_owned()),
        };
        self.audited(&session, action, outcome, now)
    }

    /// Saves the mail server an owner entered, while the environment sets
    /// none.
    fn set_mail_server(
        &mut self,
        token: &str,
        csrf: &str,
        entry: &MailEntry,
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.mail";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let owner = matches!(self.admin_of(&session)?.role, Role::Owner);
        let outcome = if !owner {
            Err(SET_MAIL.to_owned())
        } else if self.alerts.mail_from_environment() {
            Err("the mail server is set in the container's environment, which wins".to_owned())
        } else {
            match mail_from_entry(entry, self.alerts.saved_mail()) {
                Ok(server) => {
                    let detail =
                        format!("set the mail server for email alerts: {}", server.label());
                    self.alerts.set_mail(Some(server))?;
                    Ok(detail)
                }
                Err(message) => Err(message),
            }
        };
        self.audited(&session, action, outcome, now)
    }

    /// Removes the mail server the panel saved.
    fn remove_mail_server(
        &mut self,
        token: &str,
        csrf: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "alert.mail.remove";
        let session = match self.alert_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let owner = matches!(self.admin_of(&session)?.role, Role::Owner);
        let outcome = if !owner {
            Err(SET_MAIL.to_owned())
        } else if self.alerts.saved_mail().is_none() {
            Err("the panel has no mail server saved to remove".to_owned())
        } else {
            self.alerts.set_mail(None)?;
            Ok("removed the mail server for email alerts".to_owned())
        };
        self.audited(&session, action, outcome, now)
    }

    /// The country the country database places `address` in, as words that
    /// follow the address in an alert: " (China)", nothing for an address in
    /// no country, or why its country is unknown.
    fn country_words(&self, address: IpAddr) -> String {
        let named = match &self.countries.database {
            Ok(named) => named,
            Err(problem) => return format!(" (its country is unknown: {problem})"),
        };
        match named.countries.lookup(address) {
            Ok(Some(code)) => match named.names.get(&code) {
                Some(name) => format!(" ({name})"),
                None => format!(" ({code})"),
            },
            Ok(None) => String::new(),
            Err(error) => format!(" (its country is unknown: {error})"),
        }
    }

    /// Alerts the owners, and `admin` themselves, to `admin`'s sign-in from
    /// `from`, outside the trusted networks: an admin who is not an owner
    /// hears only of their own, as only owners read the audit log.
    fn alert_sign_in(&mut self, admin: &str, from: IpAddr, how: &str, now: u64) {
        let text = format!(
            "{admin} signed in to the panel from {from}{}, outside the trusted networks, {how}",
            self.country_words(from)
        );
        let store = &self.store;
        let reaches = |name: &str| {
            name == admin
                || store
                    .get(name)
                    .is_some_and(|other| matches!(other.role, Role::Owner))
        };
        self.alerts.raise(now, Topic::SignIns, &text, &reaches);
    }

    /// Whether the location checks are on: LOCATION_CHECKS when the
    /// environment sets it, else an owner's setting.
    fn location_checks_on(&self) -> Result<bool, String> {
        Ok(location::Stored::open(&self.locations.stored)?
            .in_force(&self.locations.environment)
            .on)
    }

    /// What an admin's sign-in from `address` shows, and where the admin's
    /// open panel sessions come from; none while the location checks are off
    /// or have no databases yet.
    fn admin_sighting(
        &self,
        admin: &str,
        address: IpAddr,
        now: u64,
    ) -> Result<Option<(Sighting, Vec<OpenSession>)>, String> {
        if !self.location_checks_on()? {
            return Ok(None);
        }
        let Some(atlas) = &self.locations.atlas else {
            return Ok(None);
        };
        let mut open = Vec::new();
        for from in self.sessions.addresses_of(admin, now) {
            if let Some(place) = atlas.place(from)? {
                open.push(OpenSession {
                    lat: place.lat,
                    lon: place.lon,
                });
            }
        }
        let sighting = Sighting {
            time: now,
            place: atlas.place(address)?,
            devices: Vec::new(),
        };
        Ok(Some((sighting, open)))
    }

    /// Scores an admin's sign-in from `address`: alerts on an unusual one,
    /// and refuses an implausible one once the account is learned and not
    /// on vacation. A check that cannot run is audited and lets the sign-in
    /// on. What the sign-in shows is learned only once the whole sign-in
    /// succeeds.
    fn check_admin_place(
        &mut self,
        admin: &str,
        address: IpAddr,
        now: u64,
    ) -> Result<Option<Response>, String> {
        let from = address.to_string();
        let (sighting, open) = match self.admin_sighting(admin, address, now) {
            Ok(Some(seen)) => seen,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.audit.record(
                    now,
                    admin,
                    &from,
                    "login.location",
                    Outcome::Allowed,
                    &format!("the location check could not run: {error}"),
                )?;
                return Ok(None);
            }
        };
        let history = match self.locations.learning.history(AccountKind::Admin, admin) {
            Some(history) => history.clone(),
            None => location::History::default(),
        };
        let score = history.score(&sighting, &open);
        let verdict = history.verdict(&score, now);
        if matches!(verdict, Verdict::Allow) {
            return Ok(None);
        }
        let reasons: Vec<String> = score.reasons.iter().map(location::Reason::words).collect();
        let reasons = reasons.join("; ");
        let place = self.country_words(address);
        let (outcome, text) = match verdict {
            Verdict::Refuse => (
                Outcome::Denied,
                format!(
                    "Refused {admin}'s sign-in to the panel from {from}{place}, scored {} of 100: \
                     {reasons}",
                    score.points
                ),
            ),
            Verdict::Flag | Verdict::Allow => (
                Outcome::Allowed,
                format!(
                    "{admin} signed in to the panel from {from}{place}, which is unusual, scored \
                     {} of 100: {reasons}",
                    score.points
                ),
            ),
        };
        self.audit
            .record(now, admin, &from, "login.location", outcome, &text)?;
        let store = &self.store;
        let reaches = |name: &str| {
            name == admin
                || store
                    .get(name)
                    .is_some_and(|other| matches!(other.role, Role::Owner))
        };
        self.alerts.raise(now, Topic::Locations, &text, &reaches);
        Ok(match verdict {
            Verdict::Refuse => Some(Response::LocationRefused),
            Verdict::Flag | Verdict::Allow => None,
        })
    }

    /// Learns an admin's whole sign-in from `address`, when the location
    /// checks are on; a failure is audited and changes nothing else, since
    /// the sign-in has already succeeded.
    fn learn_admin_place(&mut self, admin: &str, address: IpAddr, now: u64) -> Result<(), String> {
        let learned = match self.admin_sighting(admin, address, now) {
            Ok(Some((sighting, _open))) => {
                self.locations
                    .learning
                    .history_mut(AccountKind::Admin, admin)
                    .learn(&sighting);
                self.locations.learning.save()
            }
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        match learned {
            Ok(()) => Ok(()),
            Err(error) => self.audit.record(
                now,
                admin,
                &address.to_string(),
                "login.location",
                Outcome::Allowed,
                &format!("the sign-in could not be learned: {error}"),
            ),
        }
    }

    /// What a VPN sign-in shows, with its address, and where the user's other
    /// open VPN sessions come from; none while the location checks are off
    /// or have no databases yet.
    fn vpn_sighting(
        &mut self,
        sign_in: &VpnSignIn,
        now: u64,
    ) -> Result<Option<(IpAddr, Sighting, Vec<OpenSession>)>, String> {
        if !self.location_checks_on()? || self.locations.atlas.is_none() {
            return Ok(None);
        }
        let address = address_in(&sign_in.from)?;
        let sessions = self.control.sessions()?;
        let Some(atlas) = &self.locations.atlas else {
            return Ok(None);
        };
        let mut open = Vec::new();
        for session in &sessions {
            if session.user != sign_in.user || Some(session.id) == sign_in.session {
                continue;
            }
            let Some(remote) = &session.remote_ip else {
                continue;
            };
            if let Some(place) = atlas.place(address_in(remote)?)? {
                open.push(OpenSession {
                    lat: place.lat,
                    lon: place.lon,
                });
            }
        }
        let sighting = Sighting {
            time: now,
            place: atlas.place(address)?,
            devices: sign_in.devices.clone(),
        };
        Ok(Some((address, sighting, open)))
    }

    /// Checks a VPN sign-in that ocserv's session script reports, and hands
    /// the verdict to `deliver`: alerts on an unusual sign-in, refuses an
    /// implausible one once the account is learned and not on vacation, and
    /// learns one that is let in. A check that cannot run lets the client
    /// in, and the Live events page and the alerts say so. Nothing is
    /// recorded or learned unless the verdict is delivered, since the script
    /// lets the client in when no answer comes.
    pub fn check_vpn_sign_in(
        &mut self,
        sign_in: &VpnSignIn,
        now: u64,
        deliver: &mut dyn FnMut(&LocationVerdict) -> Result<(), String>,
    ) -> VpnCheck {
        let (verdict, what, learned) = match self.vpn_sighting(sign_in, now) {
            Ok(None) => (LocationVerdict::Allow, None, None),
            Ok(Some((address, sighting, open))) => {
                let history = match self
                    .locations
                    .learning
                    .history(AccountKind::Vpn, &sign_in.user)
                {
                    Some(history) => history.clone(),
                    None => location::History::default(),
                };
                let score = history.score(&sighting, &open);
                let reasons: Vec<String> =
                    score.reasons.iter().map(location::Reason::words).collect();
                let (user, from) = (sign_in.user.clone(), address.to_string());
                match history.verdict(&score, now) {
                    Verdict::Allow => (LocationVerdict::Allow, None, Some(sighting)),
                    Verdict::Flag => (
                        LocationVerdict::Flag {
                            score: score.points,
                            reasons: reasons.clone(),
                        },
                        Some(What::LocationFlagged {
                            user,
                            from,
                            score: score.points,
                            reasons,
                        }),
                        Some(sighting),
                    ),
                    Verdict::Refuse => (
                        LocationVerdict::Refuse {
                            score: score.points,
                            reasons: reasons.clone(),
                        },
                        Some(What::LocationRefused {
                            user,
                            from,
                            score: score.points,
                            reasons,
                        }),
                        None,
                    ),
                }
            }
            Err(problem) => (
                LocationVerdict::Unchecked {
                    problem: problem.clone(),
                },
                Some(What::LocationUnchecked {
                    user: sign_in.user.clone(),
                    from: Some(sign_in.from.clone()),
                    problem,
                }),
                None,
            ),
        };
        if let Err(problem) = deliver(&verdict) {
            return VpnCheck::Undelivered { problem };
        }
        if let Some(what) = what {
            self.note_location(Event { time: now, what }, now);
        }
        let unsaved = match learned {
            Some(sighting) => {
                self.locations
                    .learning
                    .history_mut(AccountKind::Vpn, &sign_in.user)
                    .learn(&sighting);
                self.locations.learning.save().err()
            }
            None => None,
        };
        VpnCheck::Answered { unsaved }
    }

    /// Puts what the location check of a VPN sign-in found on the Live
    /// events page, and alerts the admins who chose location alerts to it.
    fn note_location(&mut self, event: Event, now: u64) {
        let text = match &event.what {
            What::LocationRefused {
                user,
                from,
                score,
                reasons,
            } => format!(
                "Refused {user}'s VPN sign-in from {from}{}, scored {score} of 100: {}. To allow \
                 the place: {}",
                self.address_words(from),
                reasons.join("; "),
                self.locations.users_page
            ),
            What::LocationFlagged {
                user,
                from,
                score,
                reasons,
            } => format!(
                "{user} signed in to the VPN from {from}{}, which is unusual, scored {score} of \
                 100: {}",
                self.address_words(from),
                reasons.join("; ")
            ),
            What::LocationUnchecked {
                user,
                from: Some(from),
                problem,
            } => format!(
                "The location check of {user}'s VPN sign-in from {from}{} could not run, so the \
                 client was let in: {problem}",
                self.address_words(from)
            ),
            What::LocationUnchecked {
                user,
                from: None,
                problem,
            } => format!(
                "The location check of {user}'s VPN sign-in could not run, so the client was let \
                 in: {problem}"
            ),
            What::Connected { .. }
            | What::Disconnected { .. }
            | What::SignInFailed { .. }
            | What::Banned { .. } => return,
        };
        self.events.add(event, None);
        self.alerts
            .raise(now, Topic::Locations, &text, &|_admin| true);
    }

    /// The country `address` lies in, as words that follow it in an alert.
    fn address_words(&self, address: &str) -> String {
        match address_in(address) {
            Ok(address) => self.country_words(address),
            Err(problem) => format!(" ({problem})"),
        }
    }

    /// Whether the location databases are to be read again: the checks are
    /// on and none are loaded.
    pub fn needs_atlas(&self) -> bool {
        self.locations.atlas.is_none()
    }

    /// Turns the location checks on or off and sets how often their
    /// databases are checked, for an owner. A value the environment sets
    /// cannot be changed here. Turning the checks on wakes the thread that
    /// downloads and reads the databases; turning them off frees the
    /// databases' memory.
    fn set_location_checks(
        &mut self,
        token: &str,
        csrf: &str,
        on: bool,
        refresh: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "locations.change";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        if !matches!(self.admin_of(&session)?.role, Role::Owner) {
            return Ok(Response::Invalid {
                message: "only owners can change the location checks".to_owned(),
            });
        }
        let refresh_hours = match location::refresh_hours(refresh) {
            Ok(hours) => hours,
            Err(problem) => return Ok(Response::Invalid { message: problem }),
        };
        let environment = &self.locations.environment;
        if environment.on.is_some_and(|set| set != on) {
            return Ok(Response::Invalid {
                message: "LOCATION_CHECKS sets this in the container's environment, which wins"
                    .to_owned(),
            });
        }
        if environment
            .refresh_hours
            .is_some_and(|set| set != refresh_hours)
        {
            return Ok(Response::Invalid {
                message: "LOCATION_REFRESH_HOURS sets this in the container's environment, which \
                          wins"
                    .to_owned(),
            });
        }
        location::Stored { on, refresh_hours }.save(&self.locations.stored)?;
        match on {
            true => {
                if let Some(wake) = &self.locations.wake {
                    wake.send(()).map_err(|error| {
                        format!("the location database thread has stopped: {error}")
                    })?;
                }
            }
            false => self.locations.atlas = None,
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!(
                "turned the location checks {}; the databases are checked every {refresh_hours} \
                 hours",
                if on { "on" } else { "off" }
            ),
        )?;
        Ok(Response::Done)
    }

    /// The alert messages due at `now`, which the sender now has.
    pub fn take_alerts(&mut self, now: u64) -> Vec<alerts::Delivery> {
        self.alerts.take_due(now)
    }

    /// Records how a try of channel `channel`'s message went, and audits a
    /// message that is done: sent, or given up after its last try.
    pub fn finish_alert(&mut self, now: u64, channel: u32, tried: Tried) -> Result<(), String> {
        let Some(report) = self.alerts.finish(now, channel, tried) else {
            return Ok(());
        };
        let alerts = match report.alerts {
            1 => "1 alert".to_owned(),
            count => format!("{count} alerts"),
        };
        let (result, detail) = match &report.error {
            None => (
                Outcome::Allowed,
                format!(
                    "sent {alerts} to {}'s {} channel {}",
                    report.admin, report.kind, report.label
                ),
            ),
            Some(error) => (
                Outcome::Denied,
                format!(
                    "gave up sending {alerts} to {}'s {} channel {} after {} tries: {error}",
                    report.admin, report.kind, report.label, report.tries
                ),
            ),
        };
        self.audit.record(
            now,
            blocklist::AUTOMATIC,
            LOCAL,
            "alert.send",
            result,
            &detail,
        )
    }

    /// When the alert sender next has work: a message due, or the country
    /// rules' counter to read on the hour.
    pub fn next_alert_wake(&self) -> u64 {
        match self.alerts.next_due() {
            Some(due) => due.min(self.alerts.next_fold()),
            None => self.alerts.next_fold(),
        }
    }

    /// Whether the country rules' counter is due to be read at `now`.
    pub fn drops_due(&self, now: u64) -> bool {
        now >= self.alerts.next_fold()
    }

    /// Adds what the country rules' counter counted to the day's drops, and
    /// after midnight UTC alerts the admins who chose it to the day before's.
    pub fn fold_drops(&mut self, now: u64, counter: Counter) -> Result<(), String> {
        self.alerts.fold(now, counter, &|_admin| true)
    }

    /// The countries `database` places the addresses of the events kept in.
    fn event_countries(&self, database: &countries::Countries) -> Result<EventCountries, String> {
        let mut failed: BTreeMap<Option<String>, u64> = BTreeMap::new();
        let mut connected: Vec<String> = Vec::new();
        for logged in self.events.kept() {
            let (from, failure) = match &logged.event.what {
                What::SignInFailed { from, .. } => (from, true),
                What::Connected { from, .. } => (from, false),
                What::Disconnected { .. }
                | What::Banned { .. }
                | What::LocationRefused { .. }
                | What::LocationFlagged { .. }
                | What::LocationUnchecked { .. } => continue,
            };
            let Some(from) = from else {
                continue;
            };
            let country = database.lookup(address_in(from)?)?;
            if failure {
                *failed.entry(country).or_insert(0) += 1;
            } else if let Some(country) = country
                && !connected.contains(&country)
            {
                connected.push(country);
            }
        }
        let mut failed: Vec<(Option<String>, u64)> = failed.into_iter().collect();
        failed.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        connected.sort();
        Ok(EventCountries { failed, connected })
    }

    /// Stores the country rules from the Bans page and loads them into the
    /// firewall, for an owner with full access.
    fn set_countries(
        &mut self,
        token: &str,
        csrf: &str,
        rule: Option<&str>,
        codes: Option<&[String]>,
        now: u64,
    ) -> Result<Response, String> {
        let action = "countries.change";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let outcome = if matches!(self.admin_of(&session)?.role, Role::Owner) {
            self.change_countries(rule, codes, session.from)?
        } else {
            Err(CHANGE_COUNTRIES.to_owned())
        };
        let (result, detail, response) = match outcome {
            Ok(detail) => (Outcome::Allowed, detail, Response::Done),
            Err(message) => (
                Outcome::Denied,
                message.clone(),
                Response::Invalid { message },
            ),
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            result,
            &detail,
        )?;
        Ok(response)
    }

    /// Checks the rule and the countries asked for against the environment,
    /// which wins, and against the admin's own address `from`, which the
    /// rules must not drop; then loads them into the firewall and stores
    /// them. What changed, in words, or why nothing did.
    fn change_countries(
        &mut self,
        rule: Option<&str>,
        codes: Option<&[String]>,
        from: IpAddr,
    ) -> Result<Result<String, String>, String> {
        let environment = &self.countries.environment;
        let before = countries::read_stored(&self.countries.stored)?;
        let mut next = before.clone();
        if let Some(rule) = rule {
            if environment.rule.is_some() {
                return Ok(Err(
                    "COUNTRY_RULE is set in the container's environment, so the panel cannot \
                     change the rule"
                        .to_owned(),
                ));
            }
            let rule = rule.trim().to_ascii_lowercase();
            if !matches!(rule.as_str(), "off" | "block" | "allow") {
                return Ok(Err(format!(
                    "the country rule {rule} is not off, block or allow"
                )));
            }
            next.rule = rule;
        }
        if let Some(codes) = codes {
            if environment.countries.is_some() {
                return Ok(Err(
                    "COUNTRIES is set in the container's environment, so the panel cannot \
                     change the list"
                        .to_owned(),
                ));
            }
            let mut listed: Vec<String> = Vec::new();
            for code in codes {
                let code = code.trim().to_ascii_uppercase();
                if !countries::valid_code(&code) {
                    return Ok(Err(format!("{code} is not a two-letter country code")));
                }
                if !listed.contains(&code) {
                    listed.push(code);
                }
            }
            next.countries = listed;
        }
        if next == before {
            return Ok(Ok("nothing changed".to_owned()));
        }
        let effective = countries::effective(environment, &next);
        let input = match countries::input_for(&effective, environment) {
            Ok(input) => input,
            Err(message) => return Ok(Err(message)),
        };
        if let Some(input) = &input {
            if self.firewall.backend() != Backend::Nftables {
                return Ok(Err(countries::NEEDS_NFTABLES.to_owned()));
            }
            let country = match &self.countries.database {
                Ok(named) => named.countries.lookup(from)?,
                Err(problem) => {
                    return Ok(Err(format!(
                        "the country rules cannot be loaded: {problem}"
                    )));
                }
            };
            if !input.admits(from, country.as_deref())? {
                let place = match &country {
                    Some(code) => format!("{from} ({code})"),
                    None => format!("{from}, which no country holds"),
                };
                return Ok(Err(format!(
                    "these rules would drop new connections from your own address, {place}, \
                     and lock you out"
                )));
            }
        }
        if let Err(error) = self.firewall.load_countries(input.as_ref()) {
            return Ok(Err(format!(
                "the firewall refused the country rules: {error}"
            )));
        }
        countries::write_stored(&self.countries.stored, &next)?;
        Ok(Ok(country_detail(&effective)))
    }

    /// A page of the audit log, for an owner with full access.
    fn list_audit(
        &mut self,
        token: &str,
        before: Option<usize>,
        now: u64,
    ) -> Result<Response, String> {
        let refusal = "only owners can read the audit log";
        if let Err(refused) = self.owner_session(token, "audit.read", refusal, now)? {
            return Ok(refused);
        }
        let (records, older) = self.audit.page(before, AUDIT_PAGE, AUDIT_PAGE_BYTES)?;
        Ok(Response::Audit { records, older })
    }

    /// The admin accounts, for an owner with full access.
    fn list_admins(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if let Err(refused) = self.owner_session(token, "admin.list", MANAGE_ADMINS, now)? {
            return Ok(refused);
        }
        let admins = self
            .store
            .list()
            .iter()
            .map(|admin| {
                summary(
                    admin,
                    now,
                    self.vacation_of(AccountKind::Admin, &admin.name, now),
                )
            })
            .collect();
        Ok(Response::Admins {
            admins,
            locations_on: self.location_checks_on()?,
        })
    }

    /// The certificates the VPN server and the panel use, for a session with
    /// full access: the server's from its running configuration, then the
    /// panel's own. A file that cannot be read is listed with the reason.
    fn certificates(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let mut files = Vec::new();
        if let Some(server) = ServerConfig::read(&self.ocserv_config)?.server_cert() {
            files.push(("VPN server".to_owned(), server.to_owned()));
        }
        files.extend(self.certificate_files.iter().cloned());
        let certificates = files
            .into_iter()
            .map(|(role, path)| {
                let read = fs::read_to_string(&path)
                    .map_err(|error| format!("it cannot be read: {error}"))
                    .and_then(|pem| kit::certificate_facts(&pem));
                let (facts, problem) = match read {
                    Ok(facts) => (Some(facts), None),
                    Err(problem) => (None, Some(problem)),
                };
                CertificateEntry {
                    role,
                    path: path.display().to_string(),
                    facts,
                    problem,
                }
            })
            .collect();
        Ok(Response::Certificates { certificates })
    }

    /// The client certificates the panel issued, newest first, for a session
    /// with full access.
    fn client_certificates(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        Ok(Response::ClientCertificates {
            certificates: self
                .client_certificates
                .newest_first()
                .map(certificate_summary)
                .collect(),
            days: self.client_cert_days,
        })
    }

    /// Issues a client certificate for the VPN user `user`, for an owner or
    /// operator.
    fn issue_client_certificate(
        &mut self,
        token: &str,
        csrf: &str,
        user: &str,
        how: &IssueHow,
        now: u64,
    ) -> Result<Response, String> {
        let action = "certificate.issue";
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let Some(found) = self
            .users
            .list()?
            .into_iter()
            .find(|known| known.name == user)
        else {
            return Ok(Response::Invalid {
                message: format!("there is no VPN user named {user}"),
            });
        };
        let signing = match how {
            IssueHow::KeyFile { cipher } => Signing::KeyFile(*cipher),
            IssueHow::Request { pem } => Signing::Request(pem),
        };
        self.issue(
            &session,
            action,
            "issued",
            user,
            &found.groups,
            signing,
            now,
        )
    }

    /// Issues a new certificate for the user of the certificate `serial`, the
    /// way that one was issued, naming the user's groups now, for an owner or
    /// operator. The old certificate stays valid until it expires.
    fn renew_client_certificate(
        &mut self,
        token: &str,
        csrf: &str,
        serial: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "certificate.renew";
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let refused = |message: String| Ok(Response::Invalid { message });
        let Some(old) = self.client_certificates.find(serial).cloned() else {
            return refused(format!("no certificate has the serial number {serial}"));
        };
        if old.revoked.is_some() {
            return refused(format!(
                "the certificate {serial} is revoked; issue a new one instead"
            ));
        }
        let Some(found) = self
            .users
            .list()?
            .into_iter()
            .find(|known| known.name == old.user)
        else {
            return refused(format!("{} is no longer a VPN user", old.user));
        };
        let signing = match (old.method, old.cipher) {
            (Method::KeyFile, Some(cipher)) => Signing::KeyFile(cipher),
            (Method::KeyFile, None) => {
                return Err(format!(
                    "the record of the key file {serial} does not say how it was encrypted"
                ));
            }
            (Method::Request, _) => Signing::Again(&old.pem),
        };
        self.issue(
            &session,
            action,
            "renewed",
            &old.user,
            &found.groups,
            signing,
            now,
        )
    }

    /// Signs a certificate for `user` in `groups` the way `signing` says,
    /// records it, and audits it as `action`, with `verb` saying what was
    /// done. A refused signing request is answered as invalid.
    #[allow(clippy::too_many_arguments)]
    fn issue(
        &mut self,
        session: &Session,
        action: &str,
        verb: &str,
        user: &str,
        groups: &[String],
        signing: Signing<'_>,
        now: u64,
    ) -> Result<Response, String> {
        let subject = Subject { user, groups };
        let days = self.client_cert_days;
        let server = self.kit_server()?.kit(user, groups, None, None);
        let (signed, method, key_file, source) = match signing {
            Signing::KeyFile(cipher) => {
                let passphrase = Zeroizing::new(passphrase::generate()?);
                let made = self
                    .authority
                    .key_file(&subject, days, cipher, &passphrase)?;
                let download = KeyFileDownload {
                    cipher,
                    p12_base64: data_encoding::BASE64.encode(made.p12.as_slice()),
                    passphrase: passphrase.to_string(),
                };
                let source = match cipher {
                    Cipher::Aes256 => "in a key file encrypted with AES-256",
                    Cipher::TripleDes => "in a key file encrypted with 3DES",
                };
                (made.signed, Method::KeyFile, Some(download), source)
            }
            Signing::Request(pem) => match self.authority.sign_request(&subject, days, pem)? {
                Ok(signed) => (
                    signed,
                    Method::Request,
                    None,
                    "for the key of a signing request",
                ),
                Err(message) => return Ok(Response::Invalid { message }),
            },
            Signing::Again(pem) => (
                self.authority.sign_again(&subject, days, pem)?,
                Method::Request,
                None,
                "for the key it had",
            ),
        };
        self.client_certificates.add(Issued {
            serial: signed.serial.clone(),
            user: user.to_owned(),
            groups: groups.to_vec(),
            method,
            cipher: key_file.as_ref().map(|download| download.cipher),
            by: session.admin.clone(),
            issued: now,
            not_after: signed.not_after,
            revoked: None,
            pem: signed.pem.clone(),
        })?;
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!(
                "{verb} a certificate for {user} {source}, serial {}, valid for {days} days",
                signed.serial
            ),
        )?;
        Ok(Response::ClientCertificateIssued {
            issued: Box::new(IssuedCertificate {
                user: user.to_owned(),
                serial: signed.serial,
                not_after: signed.not_after,
                url: server.url(),
                pin: server.pin,
                certificate: signed.pem,
                key_file,
            }),
        })
    }

    /// Revokes the certificate `serial` and ends its user's VPN sessions, for
    /// an owner or operator.
    fn revoke_client_certificate(
        &mut self,
        token: &str,
        csrf: &str,
        serial: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "certificate.revoke";
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let Some(found) = self.client_certificates.find(serial).cloned() else {
            return Ok(Response::Invalid {
                message: format!("no certificate has the serial number {serial}"),
            });
        };
        if found.revoked.is_some() {
            return Ok(Response::Invalid {
                message: format!("the certificate {serial} is already revoked"),
            });
        }
        self.revoke_certificates(&session.admin, std::slice::from_ref(&found), now)?;
        let detail = ended(
            format!("revoked the certificate {serial} of {}", found.user),
            self.control.end_user_sessions(&found.user)?,
        );
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &detail,
        )?;
        Ok(Response::Done)
    }

    /// Revokes `certificates` on behalf of `admin`, then has ocserv load the
    /// new revocation list.
    fn revoke_certificates(
        &mut self,
        admin: &str,
        certificates: &[Issued],
        now: u64,
    ) -> Result<(), String> {
        for certificate in certificates {
            self.authority
                .revoke(&certificate.serial, &certificate.pem)?;
            self.client_certificates.revoke(
                &certificate.serial,
                Revocation {
                    at: now,
                    by: admin.to_owned(),
                },
            )?;
        }
        if !certificates.is_empty() {
            self.control.reload()?;
        }
        Ok(())
    }

    /// The server settings the Settings page offers, for an owner with full
    /// access.
    fn list_server_settings(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if let Err(refused) = self.owner_session(token, "settings.read", CHANGE_SETTINGS, now)? {
            return Ok(refused);
        }
        let Some(state) = server_settings::read_state(&self.settings.state)? else {
            return Ok(Response::ServerSettings { settings: None });
        };
        let stored = server_settings::read_stored(&self.settings.stored)?;
        let mut settings = Vec::new();
        for (name, apply, source, running) in state {
            if spec_of(&name).is_none() {
                return Err(format!(
                    "{} names {name}, which this panel does not know",
                    self.settings.state.display()
                ));
            }
            settings.push(Setting {
                stored: stored.get(&name).cloned(),
                name,
                apply,
                source,
                running,
            });
        }
        Ok(Response::ServerSettings {
            settings: Some(settings),
        })
    }

    /// Stores the values typed on the Settings page for an owner with full
    /// access, applies what a reload can, and audits the change or the
    /// refusal.
    fn set_server_settings(
        &mut self,
        token: &str,
        csrf: &str,
        values: &[(String, String)],
        now: u64,
    ) -> Result<Response, String> {
        let action = "settings.change";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let outcome = if matches!(self.admin_of(&session)?.role, Role::Owner) {
            self.change_settings(values)?
        } else {
            Err(CHANGE_SETTINGS.to_owned())
        };
        let from = session.from.to_string();
        match outcome {
            Ok((detail, reloaded)) => {
                self.audit.record(
                    now,
                    &session.admin,
                    &from,
                    action,
                    Outcome::Allowed,
                    &detail,
                )?;
                Ok(Response::ServerSettingsSaved { reloaded })
            }
            Err(message) => {
                self.audit.record(
                    now,
                    &session.admin,
                    &from,
                    action,
                    Outcome::Denied,
                    &message,
                )?;
                Ok(Response::Invalid { message })
            }
        }
    }

    /// Checks and stores `values`, then builds the configuration again and
    /// reloads ocserv when a reload applies the change. A value the builder
    /// or ocserv refuses leaves the stored values as they were.
    fn change_settings(&mut self, values: &[(String, String)]) -> Result<SettingsOutcome, String> {
        let Some(state) = server_settings::read_state(&self.settings.state)? else {
            return Ok(Err(
                "the server runs its own configuration file, so its settings are changed there"
                    .to_owned(),
            ));
        };
        let before = server_settings::read_stored(&self.settings.stored)?;
        let mut stored = before.clone();
        let mut changes = Vec::new();
        for (name, value) in values {
            let Some(spec) = spec_of(name) else {
                return Ok(Err(format!("{name} is not a setting this page changes")));
            };
            let Some((_, _, source, running)) = state.iter().find(|line| line.0 == *name) else {
                return Err(format!(
                    "{} has no line for {name}",
                    self.settings.state.display()
                ));
            };
            if !source.is_open() {
                return Ok(Err(format!(
                    "{name} is set by {}, so the panel cannot change it",
                    source_text(source)
                )));
            }
            let next = match server_settings::check(spec, value) {
                Ok(Some(value)) if !(*source == Source::Default && value == *running) => {
                    Some(value)
                }
                Ok(Some(_) | None) => None,
                Err(message) => return Ok(Err(message)),
            };
            if stored.get(name) == next.as_ref() {
                continue;
            }
            match next {
                Some(value) => {
                    changes.push(format!("set {name} to {value}"));
                    stored.insert(name.clone(), value);
                }
                None => {
                    changes.push(format!("returned {name} to its default"));
                    stored.remove(name);
                }
            }
        }
        if changes.is_empty() {
            return Ok(Ok(("nothing changed".to_owned(), false)));
        }
        if effective("TUNNEL_MODE", &stored, &state)? == "split-include"
            && effective("TUNNEL_ROUTES", &stored, &state)?.is_empty()
        {
            return Ok(Err(
                "split-include needs at least one network in TUNNEL_ROUTES".to_owned(),
            ));
        }
        server_settings::write_stored(&self.settings.stored, &stored)?;
        match self.apply_settings() {
            Ok(true) => Ok(Ok((
                format!("{}; applied with a reload", changes.join("; ")),
                true,
            ))),
            Ok(false) => Ok(Ok((
                format!("{}; applies at the next start", changes.join("; ")),
                false,
            ))),
            Err(error) => {
                server_settings::write_stored(&self.settings.stored, &before)?;
                Ok(Err(format!("nothing was saved: {error}")))
            }
        }
    }

    /// Builds the configuration again and installs it with a reload when
    /// every option that changed is one a reload applies; returns whether
    /// ocserv reloaded.
    fn apply_settings(&mut self) -> Result<bool, String> {
        let next_config = self.ocserv_config.with_extension("conf.next");
        let next_state = self.settings.state.with_extension("next");
        self.renderer.render(&next_config, &next_state)?;
        let running = ServerConfig::read(&self.ocserv_config)?;
        let next = ServerConfig::read(&next_config)?;
        let (changed, reloadable) = server_settings::difference(&running, &next);
        if !reloadable {
            for path in [&next_config, &next_state] {
                fs::remove_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
            }
            return Ok(false);
        }
        fs::rename(&next_config, &self.ocserv_config)
            .map_err(|error| format!("{}: {error}", self.ocserv_config.display()))?;
        fs::rename(&next_state, &self.settings.state)
            .map_err(|error| format!("{}: {error}", self.settings.state.display()))?;
        if changed.is_empty() {
            return Ok(false);
        }
        self.control.reload()?;
        Ok(true)
    }

    /// The session admin's own account and how many other sessions they
    /// have.
    fn account(&mut self, token: &str, now: u64) -> Result<Response, String> {
        let Some(session) = self.full_session(token, now) else {
            return Ok(Response::Denied);
        };
        let admin = self.admin_of(&session)?;
        Ok(Response::AdminAccount {
            admin: summary(
                &admin,
                now,
                self.vacation_of(AccountKind::Admin, &admin.name, now),
            ),
            locations_on: self.location_checks_on()?,
            other_sessions: self.sessions.others_of(&admin.name, token, now),
            passkeys: admin
                .passkeys
                .iter()
                .map(|stored| PasskeyView {
                    name: stored.name.clone(),
                    created: stored.created,
                    last_used: stored.last_used,
                })
                .collect(),
            passkeys_unavailable: match &self.passkeys {
                Ok(_party) => None,
                Err(unavailable) => Some(unavailable.to_string()),
            },
        })
    }

    /// Ends every session of the session's admin but this one, and audits
    /// how many ended.
    fn end_other_sessions(
        &mut self,
        token: &str,
        csrf: &str,
        now: u64,
    ) -> Result<Response, String> {
        let action = "session.end_others";
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let ended = self.sessions.end_admin(&session.admin, Some(token));
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &format!("signed out everywhere else; {}", sessions_ended(ended)),
        )?;
        Ok(Response::Done)
    }

    /// Changes an admin account for an owner with full access, and audits
    /// the change or the refusal.
    fn change_admin(
        &mut self,
        token: &str,
        csrf: &str,
        change: &AdminChange,
        now: u64,
    ) -> Result<Response, String> {
        let action = change.action();
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refused) => return Ok(refused),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Response::Denied);
        }
        let outcome = if matches!(self.admin_of(&session)?.role, Role::Owner) {
            self.admin_change(&session.admin, change, now)?
        } else {
            Err(MANAGE_ADMINS.to_owned())
        };
        let from = session.from.to_string();
        match outcome {
            Ok((detail, password)) => {
                self.audit.record(
                    now,
                    &session.admin,
                    &from,
                    action,
                    Outcome::Allowed,
                    &detail,
                )?;
                Ok(Response::AdminChanged {
                    one_time_password: password
                        .map(|password| OneTimePassword(password.as_str().to_owned())),
                })
            }
            Err(message) => {
                self.audit.record(
                    now,
                    &session.admin,
                    &from,
                    action,
                    Outcome::Denied,
                    &message,
                )?;
                Ok(Response::Invalid { message })
            }
        }
    }

    /// Makes `change` for the owner `actor`: what was done, in words, and
    /// the one-time password it set; or why it was refused. An owner's own
    /// account is changed only by another owner.
    fn admin_change(
        &mut self,
        actor: &str,
        change: &AdminChange,
        now: u64,
    ) -> Result<AdminOutcome, String> {
        if let AdminChange::Add { name, role } = change {
            return self.add_admin(name, *role, now);
        }
        let Some(target) = self.store.get(change.name()).cloned() else {
            return Ok(Err("there is no admin of that name".to_owned()));
        };
        let name = target.name;
        if name == actor {
            return Ok(Err(
                "you cannot change your own account here; another owner can".to_owned(),
            ));
        }
        let detail = match change {
            AdminChange::Add { .. } => {
                return Err("an added admin reached the change of an existing one".to_owned());
            }
            AdminChange::SetRole { role, .. } => {
                if target.role == *role {
                    return Ok(Err(format!(
                        "nothing changed: {name} is already {}",
                        role_with_article(*role)
                    )));
                }
                self.admin_mut(&name)?.role = *role;
                self.store.save()?;
                format!(
                    "changed {name}'s role from {} to {}",
                    role_word(target.role),
                    role_word(*role)
                )
            }
            AdminChange::ResetPassword { .. } => {
                let password = Zeroizing::new(secret::one_time_password()?);
                let hash = self.hasher.hash(&password)?;
                let entry = self.admin_mut(&name)?;
                entry.password_hash = hash;
                entry.must_change_password = true;
                entry.failed_logins = 0;
                entry.locked_until = None;
                self.store.save()?;
                let ended = self.sessions.end_admin(&name, None);
                return Ok(Ok((
                    format!("gave {name} a one-time password; {}", sessions_ended(ended)),
                    Some(password),
                )));
            }
            AdminChange::ResetSecondFactor { .. } => {
                if target.totp_secret.is_none() && target.passkeys.is_empty() {
                    return Ok(Err(format!(
                        "nothing changed: {name} has no authenticator app or passkey"
                    )));
                }
                let removed = factors_text(target.totp_secret.is_some(), target.passkeys.len());
                let entry = self.admin_mut(&name)?;
                entry.totp_secret = None;
                entry.last_totp_step = None;
                entry.passkeys.clear();
                entry.passkey_user = None;
                entry.enrollment_open = true;
                self.store.save()?;
                self.enrollments.remove(&name);
                self.passkey_enrollments.remove(&name);
                let ended = self.sessions.end_admin(&name, None);
                format!(
                    "removed {name}'s {removed} and opened its setup; {}",
                    sessions_ended(ended)
                )
            }
            AdminChange::Unlock { .. } => {
                let locked = target.locked_until.is_some_and(|until| now < until);
                if !locked && target.failed_logins == 0 {
                    return Ok(Err(format!("nothing changed: {name} is not locked")));
                }
                let entry = self.admin_mut(&name)?;
                entry.locked_until = None;
                entry.failed_logins = 0;
                self.store.save()?;
                format!("unlocked {name}")
            }
            AdminChange::Remove { .. } => {
                if !self.store.remove(&name) {
                    return Err(format!("the admin '{name}' vanished while being removed"));
                }
                self.store.save()?;
                self.alerts.forget(&name)?;
                if self
                    .locations
                    .learning
                    .forget_account(AccountKind::Admin, &name)
                {
                    self.locations.learning.save()?;
                }
                self.enrollments.remove(&name);
                self.passkey_enrollments.remove(&name);
                let ended = self.sessions.end_admin(&name, None);
                format!(
                    "removed {name}, who was {}; {}",
                    role_with_article(target.role),
                    sessions_ended(ended)
                )
            }
        };
        Ok(Ok((detail, None)))
    }

    /// Adds an admin with a one-time password, open to set up a second
    /// factor from anywhere once, like the first admin.
    fn add_admin(&mut self, name: &str, role: Role, now: u64) -> Result<AdminOutcome, String> {
        let name = match store::canonical_name(name) {
            Ok(name) => name,
            Err(message) => return Ok(Err(message)),
        };
        if self.store.get(&name).is_some() {
            return Ok(Err(format!("an admin named {name} already exists")));
        }
        let password = Zeroizing::new(secret::one_time_password()?);
        let password_hash = self.hasher.hash(&password)?;
        self.store.add(Admin {
            name: name.clone(),
            role,
            password_hash,
            must_change_password: true,
            totp_secret: None,
            last_totp_step: None,
            enrollment_open: true,
            failed_logins: 0,
            locked_until: None,
            created: now,
            last_login: None,
            passkeys: Vec::new(),
            passkey_user: None,
        })?;
        self.store.save()?;
        Ok(Ok((
            format!(
                "added {name} as {} with a one-time password",
                role_with_article(role)
            ),
            Some(password),
        )))
    }

    /// Blocks `network` at the firewall on every port, for `hours` or until
    /// lifted, and disconnects the VPN sessions from it. Neither the admin's
    /// own address, loopback nor the Docker host may be blocked.
    fn block(
        &mut self,
        token: &str,
        csrf: &str,
        network: &str,
        hours: Option<u64>,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.block", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let refused = |message: String| Ok(Response::Invalid { message });
        let parsed = match Network::parse(network.trim()) {
            Ok(parsed) => parsed,
            Err(message) => return refused(message),
        };
        let loopback = [
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]),
        ];
        if parsed.contains(session.from) {
            return refused(format!(
                "{parsed} holds your own address, {}, and blocking it would lock you out",
                session.from
            ));
        }
        if let Some(kept) = loopback
            .iter()
            .chain(&self.docker_hosts)
            .find(|kept| parsed.contains(**kept))
        {
            return refused(format!(
                "{parsed} holds {kept}, which the firewall always admits"
            ));
        }
        let until = match hours {
            Some(0) => return refused("a block lasts at least an hour".to_owned()),
            Some(hours) => Some(now + hours.saturating_mul(3600)),
            None => None,
        };
        if let Some(existing) = self.blocklist.overlapping(&parsed)? {
            return refused(format!(
                "{parsed} overlaps the block of {}; lift that block first",
                existing.network
            ));
        }
        let block = Block {
            network: parsed.to_string(),
            since: now,
            until,
            by: session.admin.clone(),
            reason: match hours {
                Some(hours) => format!(
                    "blocked by {} for {}",
                    session.admin,
                    blocklist::hours_text(hours)
                ),
                None => format!("blocked by {} until lifted", session.admin),
            },
        };
        let ended = self.apply_block(block)?;
        let span = match hours {
            Some(hours) => format!("for {}", blocklist::hours_text(hours)),
            None => "until lifted".to_owned(),
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.block",
            Outcome::Allowed,
            &format!("blocked {parsed} {span}; {}", disconnected(ended)),
        )?;
        Ok(Response::Done)
    }

    /// Adds `block` to the blocklist and the firewall, and disconnects the
    /// VPN sessions from its network; how many it disconnected. A block the
    /// firewall refuses is taken off the list again.
    fn apply_block(&mut self, block: Block) -> Result<usize, String> {
        let network = Network::parse(&block.network)?;
        let text = block.network.clone();
        self.blocklist.add(block)?;
        if let Err(error) = self.firewall.block(&network) {
            return Err(match self.blocklist.remove(&text) {
                Ok(_removed) => error,
                Err(undo) => {
                    format!("{error}; the block could not be taken off the list either: {undo}")
                }
            });
        }
        let mut ended = 0;
        for vpn in self.control.sessions()? {
            let Some(remote) = vpn.remote_ip.as_deref() else {
                continue;
            };
            let address = remote
                .parse::<IpAddr>()
                .map_err(|error| format!("occtl gave '{remote}' as a client address: {error}"))?;
            if network.contains(address) && self.control.end_session(vpn.id)? {
                ended += 1;
            }
        }
        Ok(ended)
    }

    /// Lifts the block of `network`.
    fn unblock(
        &mut self,
        token: &str,
        csrf: &str,
        network: &str,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.unblock", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let Some(lifted) = self.blocklist.remove(network)? else {
            return Ok(Response::Invalid {
                message: format!("{network} is not blocked"),
            });
        };
        self.firewall.unblock(&Network::parse(&lifted.network)?)?;
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.unblock",
            Outcome::Allowed,
            &format!("lifted the block of {}", lifted.network),
        )?;
        Ok(Response::Done)
    }

    /// Makes the block of `network` stay until it is lifted.
    fn keep_block(
        &mut self,
        token: &str,
        csrf: &str,
        network: &str,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.block.keep", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let note = format!("kept until lifted by {}", session.admin);
        if !self.blocklist.keep(network, &note)? {
            return Ok(Response::Invalid {
                message: format!("{network} is not blocked"),
            });
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.block.keep",
            Outcome::Allowed,
            &format!("the block of {network} stays until it is lifted"),
        )?;
        Ok(Response::Done)
    }

    /// Lifts the blocks whose time ran out by `now`.
    pub fn expire_blocks(&mut self, now: u64) -> Result<(), String> {
        for lifted in self.blocklist.expire(now)? {
            self.firewall.unblock(&Network::parse(&lifted.network)?)?;
            self.audit.record(
                now,
                blocklist::AUTOMATIC,
                LOCAL,
                "vpn.unblock",
                Outcome::Allowed,
                &format!("the block of {} ran out", lifted.network),
            )?;
        }
        Ok(())
    }

    /// Counts ocserv's ban of `address`, and blocks it when the bans within
    /// the window reach the count.
    fn count_ban(&mut self, address: &str, now: u64) -> Result<(), String> {
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| format!("ocserv banned '{address}', not an IP address: {error}"))?;
        let Some(block) = self.blocklist.count_ban(address, now, &self.docker_hosts)? else {
            return Ok(());
        };
        let network = block.network.clone();
        let reason = block.reason.clone();
        let ended = self.apply_block(block)?;
        self.audit.record(
            now,
            blocklist::AUTOMATIC,
            LOCAL,
            "vpn.block",
            Outcome::Allowed,
            &format!("blocked {network}: {reason}; {}", disconnected(ended)),
        )?;
        let text = format!(
            "Blocked {network}{} at the firewall for {}: {reason}",
            self.country_words(address),
            blocklist::hours_text(self.blocklist.auto().duration / 3600)
        );
        self.alerts.raise(now, Topic::Blocks, &text, &|_admin| true);
        Ok(())
    }

    /// Lifts the ban on `address` and clears its points. An IPv6 address
    /// stands for its whole /64, as ocserv bans it.
    fn unban(
        &mut self,
        token: &str,
        csrf: &str,
        address: &str,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.unban", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let address = match address.trim().parse::<IpAddr>() {
            Ok(address) => address.to_string(),
            Err(error) => {
                return Ok(Response::Invalid {
                    message: format!("'{address}' is not an IP address: {error}"),
                });
            }
        };
        if !self.control.unban(&address)? {
            return Ok(Response::Invalid {
                message: format!("{address} has no ban and no points to clear"),
            });
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.unban",
            Outcome::Allowed,
            &format!("lifted the ban on {address} and cleared its points"),
        )?;
        Ok(Response::Done)
    }

    /// The configuration the VPN server runs with, the settings directories
    /// it names, and the settings a group's empty fields inherit.
    fn server_settings(&self) -> Result<(ServerConfig, Directories, Overrides), String> {
        let config = ServerConfig::read(&self.ocserv_config)?;
        let directories = Directories::of(&config);
        let server = Overrides::from_config(&config)
            .map_err(|error| format!("the VPN server's configuration: {error}"))?;
        Ok((config, directories, server))
    }

    /// Brings the firewall's site-to-site part up to date with the rules,
    /// the published networks, the pools and the sessions.
    fn sync_sites(&mut self) -> Result<(), String> {
        let (config, directories, _server) = self.server_settings()?;
        let clients = sites::clients(&config, &directories)?;
        let published = directories.publishers()?;
        let checked = self.source_check;
        let rules = &self.sites;
        let control = &mut self.control;
        self.firewall.sync_sites(&mut || {
            let sessions = Member::of_sessions(&control.sessions()?)?;
            Ok(Plan::new(
                rules,
                clients.clone(),
                &published,
                &sessions,
                None,
                checked,
            ))
        })
    }

    fn list_groups(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let (_, directories, server) = self.server_settings()?;
        let users = self.users.list()?;
        let names = group_names(&users, &directories)?;
        let mut groups = Vec::new();
        for name in names {
            groups.push(Group {
                members: users
                    .iter()
                    .filter(|user| user.groups.contains(&name))
                    .map(|user| user.name.clone())
                    .collect(),
                settings: directories.read(Owner::Group, &name)?,
                name,
            });
        }
        Ok(Response::Groups {
            groups,
            server,
            readable: directories.groups.is_some(),
        })
    }

    fn get_overrides(
        &mut self,
        token: &str,
        owner: Owner,
        name: &str,
        now: u64,
    ) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        if let Err(message) = overrides::check_owner_name(name, owner) {
            return Ok(Response::Invalid { message });
        }
        let (_, directories, server) = self.server_settings()?;
        let group = match owner {
            Owner::Group => None,
            Owner::User => {
                let Some(user) = self
                    .users
                    .list()?
                    .into_iter()
                    .find(|user| user.name == name)
                else {
                    return Ok(Response::Invalid {
                        message: format!("there is no user named {name}"),
                    });
                };
                user.groups.into_iter().next()
            }
        };
        let group_settings = match &group {
            Some(group) => directories.read(Owner::Group, group)?,
            None => None,
        };
        Ok(Response::Overrides {
            own: directories.read(owner, name)?.map(Box::new),
            group,
            group_settings: group_settings.map(Box::new),
            server: Box::new(server),
            readable: directories.of_owner(owner).is_some(),
        })
    }

    /// Replaces a user's or group's settings, or removes its settings file
    /// when `form` is none. ocserv reads the file at the user's next
    /// connection.
    fn set_overrides(
        &mut self,
        token: &str,
        csrf: &str,
        owner: Owner,
        name: &str,
        form: Option<&OverridesForm>,
        now: u64,
    ) -> Result<Response, String> {
        let action = match (owner, form) {
            (Owner::User, Some(_)) => "vpn.user.settings",
            (Owner::User, None) => "vpn.user.settings.remove",
            (Owner::Group, Some(_)) => "vpn.group.settings",
            (Owner::Group, None) => "vpn.group.settings.remove",
        };
        let session = match self.operating_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let refused = |message: String| Ok(Response::Invalid { message });
        if let Err(message) = overrides::check_owner_name(name, owner) {
            return refused(message);
        }
        if owner == Owner::User && !self.users.list()?.iter().any(|user| user.name == name) {
            return refused(format!("there is no user named {name}"));
        }
        let (config, directories, _) = self.server_settings()?;
        if directories.of_owner(owner).is_none() {
            return refused(format!(
                "the VPN server reads no per-{0} settings: its configuration sets no \
                 config-per-{0}",
                owner.noun()
            ));
        }
        let detail = match form {
            None => {
                if !directories.remove(owner, name)? {
                    return refused(format!("the {} {name} has no settings", owner.noun()));
                }
                format!("removed the settings of {} {name}", owner.noun())
            }
            Some(form) => {
                let pool = overrides::pool(&config)?;
                let pool6 = match config.last(&["ipv6-network"]) {
                    Some(text) => Some(
                        Network::parse(text)
                            .map_err(|error| format!("the VPN's ipv6-network: {error}"))?,
                    ),
                    None => None,
                };
                let group_pools =
                    directories.group_pools((owner == Owner::Group).then_some(name))?;
                let published = directories.published((owner, name))?;
                let context = extras::Context {
                    pool: pool.as_ref(),
                    pool6: pool6.as_ref(),
                    group_pools: &group_pools,
                    published: &published,
                    local: &self.local_networks,
                };
                let taken = directories.fixed_addresses(name)?;
                let settings = match overrides::check(form, owner, &context, &taken) {
                    Ok(settings) => settings,
                    Err(message) => return refused(message),
                };
                directories.write(owner, name, &settings)?;
                format!(
                    "set the settings of {} {name}: {}",
                    owner.noun(),
                    overrides::describe(&settings)
                )
            }
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Allowed,
            &detail,
        )?;
        self.sync_sites().map_err(|error| {
            format!("the settings are saved, but the firewall could not take them in: {error}")
        })?;
        Ok(Response::Done)
    }

    /// The Sites page's contents: the rules, each user or group that
    /// publishes networks, the groups a rule can name, and what the page
    /// notes about the firewall and the container's settings.
    fn site_rules(&mut self, token: &str, now: u64) -> Result<Response, String> {
        if self.full_session(token, now).is_none() {
            return Ok(Response::Denied);
        }
        let (_config, directories, _server) = self.server_settings()?;
        let sessions = self.control.sessions()?;
        let mut sites: Vec<Site> = Vec::new();
        for (owner, name, network) in directories.publishers()? {
            if let Some(site) = sites
                .iter_mut()
                .find(|site| site.owner == owner && site.name == name)
            {
                site.networks.push(network.to_string());
                continue;
            }
            let connected = sessions.iter().any(|session| match owner {
                Owner::User => session.user == name,
                Owner::Group => session.group.as_deref() == Some(name.as_str()),
            });
            sites.push(Site {
                egress: owner == Owner::User && self.sites.egress(&name),
                connected,
                owner,
                name,
                networks: vec![network.to_string()],
            });
        }
        let groups = group_names(&self.users.list()?, &directories)?;
        Ok(Response::SiteRules {
            view: Box::new(SitesView {
                rules: self.sites.rules().to_vec(),
                sites,
                groups,
                checked: self.source_check,
                iptables: self.firewall.backend() == Backend::Iptables,
                client_to_client: self.running("CLIENT_TO_CLIENT")?.as_deref() == Some("true"),
                split: self.running("TUNNEL_MODE")?.as_deref() == Some("split-include"),
            }),
        })
    }

    /// The value the container started with for `name`, as the entrypoint
    /// recorded it; none when it was unset.
    fn running(&self, name: &str) -> Result<Option<String>, String> {
        Ok(server_settings::read_state(&self.settings.state)?
            .into_iter()
            .flatten()
            .find(|line| line.0 == name)
            .map(|line| line.3)
            .filter(|value| !value.is_empty()))
    }

    /// Adds a site-to-site rule from `from` to `to` and loads it into the
    /// firewall; a rule the firewall refuses is taken off again.
    fn add_site_rule(
        &mut self,
        token: &str,
        csrf: &str,
        from: End,
        to: End,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.site.rule.add", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let refused = |message: String| Ok(Response::Invalid { message });
        let names_group = |end: &End| matches!(end, End::Group(_name));
        if self.firewall.backend() == Backend::Iptables && (names_group(&from) || names_group(&to))
        {
            return refused(
                "this container's firewall is legacy iptables, whose rules can name networks only"
                    .to_owned(),
            );
        }
        let (_config, directories, _server) = self.server_settings()?;
        let groups = group_names(&self.users.list()?, &directories)?;
        for end in [&from, &to] {
            if let End::Group(name) = end
                && !groups.contains(name)
            {
                return refused(format!("there is no group named {name}"));
            }
        }
        let described = format!("{} reach {}", from.describe(), to.describe());
        let id = match self.sites.add(from, to, &session.admin, now) {
            Ok(id) => id,
            Err(message) => return refused(message),
        };
        if let Err(error) = self.sync_sites() {
            return Err(match self.sites.remove(id) {
                Ok(_rule) => error,
                Err(undo) => {
                    format!("{error}; the rule could not be taken off again either: {undo}")
                }
            });
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.site.rule.add",
            Outcome::Allowed,
            &format!("let {described}"),
        )?;
        Ok(Response::Done)
    }

    /// Removes the site-to-site rule `id` and takes it out of the firewall;
    /// a removal the firewall refuses puts the rule back.
    fn remove_site_rule(
        &mut self,
        token: &str,
        csrf: &str,
        id: u64,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.site.rule.remove", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        let Some(rule) = self.sites.remove(id)? else {
            return Ok(Response::Invalid {
                message: format!("there is no rule numbered {id}"),
            });
        };
        let described = format!("{} reach {}", rule.from.describe(), rule.to.describe());
        if let Err(error) = self.sync_sites() {
            return Err(match self.sites.restore(rule) {
                Ok(()) => error,
                Err(undo) => format!("{error}; the rule could not be put back either: {undo}"),
            });
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.site.rule.remove",
            Outcome::Allowed,
            &format!("stopped letting {described}"),
        )?;
        Ok(Response::Done)
    }

    /// Lets the networks `user` publishes reach beyond the VPN, or keeps
    /// them inside it, and has the firewall follow; a change the firewall
    /// refuses is undone.
    fn set_site_egress(
        &mut self,
        token: &str,
        csrf: &str,
        user: &str,
        on: bool,
        now: u64,
    ) -> Result<Response, String> {
        let session = match self.operating_session(token, csrf, "vpn.site.egress", now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(refusal),
        };
        if !self.users.list()?.iter().any(|known| known.name == user) {
            return Ok(Response::Invalid {
                message: format!("there is no user named {user}"),
            });
        }
        if !self.sites.set_egress(user, on)? {
            return Ok(Response::Done);
        }
        if let Err(error) = self.sync_sites() {
            return Err(match self.sites.set_egress(user, !on) {
                Ok(_changed) => error,
                Err(undo) => format!("{error}; the change could not be undone either: {undo}"),
            });
        }
        let detail = if on {
            format!("let the networks {user} publishes reach beyond the VPN")
        } else {
            format!("kept the networks {user} publishes inside the VPN")
        };
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            "vpn.site.egress",
            Outcome::Allowed,
            &detail,
        )?;
        Ok(Response::Done)
    }

    /// The live session for `token` when it has full access, not only the
    /// access to enroll a second factor.
    fn full_session(&mut self, token: &str, now: u64) -> Option<Session> {
        self.sessions
            .touch(token, now)
            .filter(|session| matches!(session.scope, Scope::Full))
    }

    /// The live session for `token` when `csrf` is its CSRF token, it has
    /// full access, and its admin may change the server: an owner or an
    /// operator. Otherwise the refusal to answer with.
    fn operating_session(
        &mut self,
        token: &str,
        csrf: &str,
        action: &str,
        now: u64,
    ) -> Result<Result<Session, Response>, String> {
        let session = match self.checked_session(token, csrf, action, now)? {
            Ok(session) => session,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !matches!(session.scope, Scope::Full) {
            return Ok(Err(Response::Denied));
        }
        if matches!(self.admin_of(&session)?.role, Role::Viewer) {
            self.audit.record(
                now,
                &session.admin,
                &session.from.to_string(),
                action,
                Outcome::Denied,
                "viewers cannot change the server",
            )?;
            return Ok(Err(Response::Invalid {
                message: "your role lets you look but not change anything".to_owned(),
            }));
        }
        Ok(Ok(session))
    }

    /// The live session for `token` when it has full access and its admin
    /// is an owner; otherwise the refusal to answer with, which is audited
    /// as `action` when the admin is not an owner.
    fn owner_session(
        &mut self,
        token: &str,
        action: &str,
        refusal: &str,
        now: u64,
    ) -> Result<Result<Session, Response>, String> {
        let Some(session) = self.full_session(token, now) else {
            return Ok(Err(Response::Denied));
        };
        if matches!(self.admin_of(&session)?.role, Role::Owner) {
            return Ok(Ok(session));
        }
        self.audit.record(
            now,
            &session.admin,
            &session.from.to_string(),
            action,
            Outcome::Denied,
            refusal,
        )?;
        Ok(Err(Response::Invalid {
            message: refusal.to_owned(),
        }))
    }

    /// The live session for `token` when `csrf` is its CSRF token; otherwise
    /// the refusal to answer with.
    fn checked_session(
        &mut self,
        token: &str,
        csrf: &str,
        action: &str,
        now: u64,
    ) -> Result<Result<Session, Response>, String> {
        let Some(session) = self.sessions.touch(token, now) else {
            return Ok(Err(Response::Denied));
        };
        if !secret::equal(csrf.as_bytes(), session.csrf.as_bytes()) {
            self.audit.record(
                now,
                &session.admin,
                &session.from.to_string(),
                action,
                Outcome::Denied,
                "the request did not carry the session's CSRF token",
            )?;
            return Ok(Err(Response::Denied));
        }
        Ok(Ok(session))
    }

    fn admin_of(&self, session: &Session) -> Result<Admin, String> {
        self.store.get(&session.admin).cloned().ok_or_else(|| {
            format!(
                "the admin '{}' of a live session does not exist",
                session.admin
            )
        })
    }

    fn admin_mut(&mut self, name: &str) -> Result<&mut Admin, String> {
        self.store
            .get_mut(name)
            .ok_or_else(|| format!("the admin '{name}' does not exist"))
    }
}

/// An audit detail, with "and ended their sessions" added when `ended`.
fn ended(detail: String, ended: bool) -> String {
    if ended {
        format!("{detail} and ended their sessions")
    } else {
        detail
    }
}

/// The address in `text` as events and occtl write one, without the
/// interface an IPv6 link-local address may name.
fn address_in(text: &str) -> Result<IpAddr, String> {
    let host = text.split_once('%').map_or(text, |(host, _scope)| host);
    host.parse()
        .map_err(|error| format!("{text} is not an IP address: {error}"))
}

/// The countries of the events kept: failed sign-ins by country, most
/// first, under none for an address in no country; and the countries VPN
/// users connected from.
struct EventCountries {
    failed: Vec<(Option<String>, u64)>,
    connected: Vec<String>,
}

/// The mail server an owner entered, checked. An empty password keeps the
/// one saved while the host and user name stay the same, so that a saved
/// password never goes to a server it was not given for.
fn mail_from_entry(
    entry: &MailEntry,
    saved: Option<&alerts::MailServer>,
) -> Result<alerts::MailServer, String> {
    let security = alerts::Security::parse(entry.security.trim()).ok_or_else(|| {
        format!(
            "'{}' is not a way to reach a mail server: give TLS, STARTTLS or none",
            entry.security.trim()
        )
    })?;
    let port = match entry.port.trim() {
        "" => security.default_port(),
        port => alerts::port_number(port).map_err(|error| format!("the port: {error}"))?,
    };
    let host = entry.host.trim().to_ascii_lowercase();
    let user = match entry.user.trim() {
        "" => None,
        user => Some(user.to_owned()),
    };
    let password = match entry.password.as_str() {
        "" => saved
            .filter(|saved| saved.host == host && saved.user == user)
            .and_then(|saved| saved.password.clone()),
        typed => Some(alerts::Secret::new(typed.to_owned())),
    };
    let server = alerts::MailServer {
        host,
        port,
        security,
        user,
        password,
        from: entry.from.trim().to_owned(),
    };
    alerts::check_mail(&server)?;
    Ok(server)
}

/// The country rules in force, in words, for the audit log.
fn country_detail(effective: &countries::Effective) -> String {
    let listed = countries::codes(&effective.countries).join(", ");
    match effective.rule.as_str() {
        "block" => format!("blocked {listed} at the firewall"),
        "allow" => format!("allowed only {listed} at the firewall"),
        _ if listed.is_empty() => "turned the country rules off".to_owned(),
        _ => format!("turned the country rules off, keeping {listed} listed"),
    }
}

/// Where a setting the panel may not change gets its value, in words.
fn source_text(source: &Source) -> String {
    match source {
        Source::Environment => "the container's environment".to_owned(),
        Source::Override(by) => by.clone(),
        Source::Panel | Source::Default => "the panel".to_owned(),
    }
}

/// The groups the password file's `users` name or that have a settings file
/// in `directories`, in order.
fn group_names(
    users: &[vpnusers::VpnUser],
    directories: &Directories,
) -> Result<Vec<String>, String> {
    let mut names = directories.names(Owner::Group)?;
    for group in users.iter().flat_map(|user| &user.groups) {
        if !names.contains(group) {
            names.push(group.clone());
        }
    }
    names.sort();
    Ok(names)
}

/// The value `name` will have at the next start: the stored one, else the
/// one the server uses, else, for a stored value being removed, the image's
/// default from IMAGE_DEFAULTS.
fn effective(
    name: &str,
    stored: &BTreeMap<String, String>,
    state: &[StateLine],
) -> Result<String, String> {
    if let Some(value) = stored.get(name) {
        return Ok(value.clone());
    }
    match state.iter().find(|line| line.0 == name) {
        Some((_, _, Source::Panel, _)) | None => {
            match IMAGE_DEFAULTS.iter().find(|(known, _)| *known == name) {
                Some((_, value)) => Ok((*value).to_owned()),
                None => Err(format!("the image's default of {name} is not known")),
            }
        }
        Some((_, _, _, running)) => Ok(running.clone()),
    }
}

/// A client certificate as the Certificates page lists it, without the
/// certificate itself.
fn certificate_summary(issued: &Issued) -> ClientCertificate {
    ClientCertificate {
        serial: issued.serial.clone(),
        user: issued.user.clone(),
        groups: issued.groups.clone(),
        method: issued.method,
        by: issued.by.clone(),
        issued: issued.issued,
        not_after: issued.not_after,
        revoked: issued.revoked.clone(),
    }
}

/// An admin account as the panel's pages show it, without its secrets, with
/// when their vacation ends while it lasts.
fn summary(admin: &Admin, now: u64, vacation_until: Option<u64>) -> AdminSummary {
    AdminSummary {
        vacation_until,
        name: admin.name.clone(),
        role: admin.role,
        second_factor: admin.has_second_factor(),
        authenticator_app: admin.totp_secret.is_some(),
        passkeys: admin.passkeys.len(),
        must_change_password: admin.must_change_password,
        locked_until: admin.locked_until.filter(|until| now < *until),
        created: admin.created,
        last_login: admin.last_login,
    }
}

/// Why `admin` has no room for a passkey named `name`, if they have none: the
/// name must be valid and not one of their other passkeys', and they must
/// have fewer than the most an admin may have.
fn passkey_room(admin: &Admin, name: &str) -> Option<String> {
    if let Some(problem) = passkey::name_problem(name) {
        return Some(problem);
    }
    if admin.passkeys.len() >= passkey::MAX_PASSKEYS {
        return Some(format!(
            "an account has at most {} passkeys; remove one first",
            passkey::MAX_PASSKEYS
        ));
    }
    if admin
        .passkeys
        .iter()
        .any(|stored| passkey::same_name(&stored.name, name))
    {
        return Some(format!(
            "you already have a passkey named '{name}'; choose another name"
        ));
    }
    None
}

/// An admin's second factors in words: "authenticator app", "2 passkeys",
/// "authenticator app and 1 passkey".
fn factors_text(app: bool, passkeys: usize) -> String {
    let keys = match passkeys {
        1 => "1 passkey".to_owned(),
        count => format!("{count} passkeys"),
    };
    match (app, passkeys) {
        (true, 0) => "authenticator app".to_owned(),
        (true, _) => format!("authenticator app and {keys}"),
        (false, _) => keys,
    }
}

/// How many panel sessions a change ended, in words.
fn sessions_ended(ended: usize) -> String {
    match ended {
        0 => "no session was open".to_owned(),
        1 => "ended 1 session".to_owned(),
        ended => format!("ended {ended} sessions"),
    }
}

fn role_word(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
    }
}

fn role_with_article(role: Role) -> &'static str {
    match role {
        Role::Owner => "an owner",
        Role::Operator => "an operator",
        Role::Viewer => "a viewer",
    }
}

fn disconnected(ended: usize) -> String {
    match ended {
        0 => "no VPN session was connected from it".to_owned(),
        1 => "disconnected 1 VPN session from it".to_owned(),
        ended => format!("disconnected {ended} VPN sessions from it"),
    }
}

/// The session in `sessions` whose VPN address is `address`: the one a
/// browser that reached the portal through the tunnel is in.
fn vpn_session_at(sessions: &[VpnSession], address: IpAddr) -> Result<Option<u64>, String> {
    for vpn in sessions {
        for text in [&vpn.vpn_ipv4, &vpn.vpn_ipv6].into_iter().flatten() {
            let ip = text
                .parse::<IpAddr>()
                .map_err(|error| format!("occtl gave '{text}' as a VPN address: {error}"))?;
            if ip.to_canonical() == address {
                return Ok(Some(vpn.id));
            }
        }
    }
    Ok(None)
}

/// The password a change to a VPN user sets.
enum Chosen {
    Password(Zeroizing<String>),
    /// The typed password cannot be used, for this reason.
    Refused(String),
}

/// The typed password, when it can be used and has at least `min`
/// characters, or a generated one when none was typed.
fn chosen_password(typed: Option<&str>, min: usize) -> Result<Chosen, String> {
    Ok(match typed {
        Some(password) => match vpnusers::check_password(password, min) {
            Ok(()) => Chosen::Password(Zeroizing::new(password.to_owned())),
            Err(message) => Chosen::Refused(message),
        },
        None => Chosen::Password(Zeroizing::new(passphrase::generate()?)),
    })
}

/// Checks a new admin password: at least `min` and at most
/// `MAX_PASSWORD_LEN` characters, not only whitespace, and not the current
/// password.
pub fn check_new_password(new: &str, current: &str, min: usize) -> Result<(), String> {
    let length = new.chars().count();
    if length < min {
        return Err(format!(
            "the password must be at least {min} characters long"
        ));
    }
    if length > MAX_PASSWORD_LEN {
        return Err(format!(
            "the password must be at most {MAX_PASSWORD_LEN} characters long"
        ));
    }
    if new.chars().all(char::is_whitespace) {
        return Err("the password cannot be only spaces".to_owned());
    }
    if secret::equal(new.as_bytes(), current.as_bytes()) {
        return Err("the new password must differ from the current one".to_owned());
    }
    Ok(())
}

/// How the first admin came to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootstrap {
    /// Admins already existed; nothing was created.
    Existing,
    /// Created with the password from PANEL_ADMIN_PASSWORD_FILE.
    FromFile { name: String },
    /// Created with a one-time password, to be shown once and replaced at the
    /// first sign-in.
    OneTime { name: String, password: String },
}

/// Creates the first admin, an owner, when there is no admin at all.
pub fn bootstrap(
    store: &mut Store,
    audit: &mut Audit,
    hasher: &Hasher,
    policy: &Policy,
    name: &str,
    password_file: Option<&Path>,
    now: u64,
) -> Result<Bootstrap, String> {
    if !store.is_empty() {
        return Ok(Bootstrap::Existing);
    }
    let name = store::canonical_name(name).map_err(|error| format!("PANEL_ADMIN_USER: {error}"))?;
    let (password, one_time) = match password_file {
        Some(path) => (read_password_file(path, policy.min_password_length)?, false),
        None => (Zeroizing::new(secret::one_time_password()?), true),
    };
    let password_hash = hasher.hash(&password)?;
    let admin = Admin {
        name: name.clone(),
        role: Role::Owner,
        password_hash,
        must_change_password: one_time,
        totp_secret: None,
        last_totp_step: None,
        enrollment_open: true,
        failed_logins: 0,
        locked_until: None,
        created: now,
        last_login: None,
        passkeys: Vec::new(),
        passkey_user: None,
    };
    store.add(admin)?;
    store.save()?;
    let detail = match one_time {
        true => "first admin created as owner with a one-time password",
        false => "first admin created as owner with the password from PANEL_ADMIN_PASSWORD_FILE",
    };
    audit.record(
        now,
        &name,
        LOCAL,
        "admin.bootstrap",
        Outcome::Allowed,
        detail,
    )?;
    match one_time {
        true => Ok(Bootstrap::OneTime {
            name,
            password: password.to_string(),
        }),
        false => Ok(Bootstrap::FromFile { name }),
    }
}

/// Reads a password from a file such as a Docker secret: the whole file,
/// without one trailing line break. The text is wiped from memory when
/// dropped.
fn read_password_file(path: &Path, min: usize) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|error| format!("PANEL_ADMIN_PASSWORD_FILE: {}: {error}", path.display()))?,
    );
    if text.ends_with("\r\n") {
        let length = text.len() - 2;
        text.truncate(length);
    } else if text.ends_with('\n') {
        let length = text.len() - 1;
        text.truncate(length);
    }
    check_new_password(&text, "", min)
        .map_err(|message| format!("PANEL_ADMIN_PASSWORD_FILE: {}: {message}", path.display()))?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::Kit;
    use crate::occtl::{Fake, Status};
    use crate::overrides::{Form as OverridesForm, Owner};
    use crate::passkey::tests::Browser;
    use crate::testdir::TestDir;
    use crate::vpnusers::FakeUsers;

    const PASSWORD: &str = "correct horse battery staple";
    const LAN: &str = "192.168.1.20";
    const VPN: &str = "192.168.255.40";
    const DOCKER_HOST: &str = "10.89.0.1";

    /// Writes the configuration ocserv runs with into `dir`, with a
    /// one-time password file in its sign-in method when `codes`.
    fn write_ocserv_config(dir: &Path, codes: bool) {
        let auth = if codes {
            "plain[passwd=/config/ocpasswd,otp=/config/users.oath]"
        } else {
            "plain[passwd=/config/ocpasswd]"
        };
        fs::write(
            dir.join("ocserv.conf"),
            format!(
                "auth = \"{auth}\"\nmax-ban-score = 60\nban-time = 600\n\
                 ipv4-network = 192.168.255.0/24\ndns = 9.9.9.9\nroute = default\n\
                 config-per-user = {}\nconfig-per-group = {}\nserver-cert = {}\n",
                dir.join("config-per-user").display(),
                dir.join("config-per-group").display(),
                dir.join("server-cert.pem").display()
            ),
        )
        .unwrap();
    }

    fn policy() -> Policy {
        Policy {
            lan_networks: net::parse_list("192.168.1.0/24").unwrap(),
            max_failures: 3,
            lockout: 900,
            min_password_length: 12,
            reauth: 600,
        }
    }

    struct Fixture {
        dir: TestDir,
        service: Service,
        firewall: crate::firewall::Fake,
    }

    impl Fixture {
        /// A service with one owner, `alex`, whose account is in the given state.
        fn new(edit: impl FnOnce(&mut Admin)) -> Fixture {
            let dir = TestDir::new();
            let hasher = Hasher::new(64, 1).unwrap();
            let mut store = Store::open(&dir.path().join("admins.json")).unwrap();
            let mut admin = Admin {
                name: "alex".to_owned(),
                role: Role::Owner,
                password_hash: hasher.hash(PASSWORD).unwrap(),
                must_change_password: false,
                totp_secret: None,
                last_totp_step: None,
                enrollment_open: false,
                failed_logins: 0,
                locked_until: None,
                created: 0,
                last_login: None,
                passkeys: Vec::new(),
                passkey_user: None,
            };
            edit(&mut admin);
            store.add(admin).unwrap();
            store.save().unwrap();
            let audit = Audit::open(&dir.path().join("audit.log")).unwrap();
            let ocserv_config = dir.path().join("ocserv.conf");
            fs::create_dir_all(dir.path().join("config-per-user")).unwrap();
            fs::create_dir_all(dir.path().join("config-per-group")).unwrap();
            fs::write(dir.path().join("server-cert.pem"), kit::SAMPLE_CERT).unwrap();
            write_ocserv_config(dir.path(), false);
            fs::copy(&ocserv_config, dir.path().join("rendered.conf")).unwrap();
            let state = dir.path().join("panel-settings");
            fs::write(
                &state,
                "DNS_SERVERS\treload\tdefault\t9.9.9.9,1.1.1.1\n\
                 MAX_CLIENTS\treload\tenvironment\t64\n\
                 IDLE_TIMEOUT\treload\tOCSERV_CONF_IDLE_TIMEOUT\t\n\
                 NAT\tstart\tdefault\ttrue\n\
                 TUNNEL_MODE\tstart\tdefault\tall\n\
                 TUNNEL_ROUTES\tstart\tdefault\t\n",
            )
            .unwrap();
            let renderer = server_settings::Fake {
                start: server_settings::read_state(&state).unwrap().unwrap(),
                config: dir.path().join("rendered.conf"),
                stored: dir.path().join("settings.env"),
            };
            let firewall = crate::firewall::Fake::default();
            let service = Service::new(
                policy(),
                store,
                audit,
                hasher,
                Sessions::new(1800, 43_200),
                300,
                Vpn {
                    control: Box::new(Fake::sample(0)),
                    users: Box::new(FakeUsers::sample()),
                    history: History::new(24, 10).unwrap(),
                    ocserv_config,
                    events: EventLog::new(24),
                    address: VpnAddress {
                        host: crate::config::Host::Name("vpn.example.com".to_owned()),
                        port: 4443,
                    },
                    blocklist: Blocklist::open(
                        &dir.path().join("blocklist.json"),
                        blocklist::AutoBlock {
                            bans: 3,
                            window: 86_400,
                            duration: 86_400,
                        },
                    )
                    .unwrap(),
                    firewall: Box::new(firewall.clone()),
                    docker_hosts: vec![DOCKER_HOST.parse().unwrap()],
                    settings: SettingsFiles {
                        state,
                        stored: dir.path().join("settings.env"),
                    },
                    renderer: Box::new(renderer),
                    certificate_files: vec![
                        (
                            "Certificate authority".to_owned(),
                            dir.path().join("server-cert.pem"),
                        ),
                        ("Admin panel".to_owned(), dir.path().join("missing.pem")),
                    ],
                    client_certificates: Records::open(
                        &dir.path().join("client-certificates.json"),
                    )
                    .unwrap(),
                    authority: Box::new(crate::clientcerts::Fake::new(MOMENT)),
                    client_cert_days: 365,
                    local_networks: vec![Network::parse("172.17.0.0/16").unwrap()],
                    sites: Sites::open(&dir.path().join("site-rules.json")).unwrap(),
                    source_check: true,
                    countries: countries::Setup {
                        environment: countries::Environment {
                            ports: vec![4443, 8443],
                            ..countries::Environment::default()
                        },
                        stored: dir.path().join("country-rules.json"),
                        database: Ok(countries::sample::named()),
                        maxmind: geoip::Maxmind {
                            environment: None,
                            key_file: geoip::key_file(dir.path()),
                            database_file: geoip::database_file(dir.path()),
                            candidate: None,
                            reread: false,
                            busy: false,
                            last: None,
                            wake: None,
                        },
                    },
                    alerts: Alerts::open(
                        &dir.path().join("alerts.json"),
                        &dir.path().join("country-drops.json"),
                        None,
                        "vpn.example.com".to_owned(),
                        None,
                        MOMENT,
                    )
                    .unwrap(),
                    passkeys: passkey::relying_party(
                        &crate::config::Host::Name("vpn.example.com".to_owned()),
                        8443,
                        std::time::Duration::from_secs(300),
                    ),
                    locations: Locations {
                        environment: location::Environment::default(),
                        stored: dir.path().join("location-checks.json"),
                        atlas: Some(test_atlas()),
                        learning: location::Learning::open(&dir.path().join("locations.json"))
                            .unwrap(),
                        wake: None,
                        last: None,
                        users_page: "https://vpn.example.com:8443/users".to_owned(),
                    },
                },
            );
            Fixture {
                dir,
                service,
                firewall,
            }
        }

        /// The networks the fake firewall drops.
        fn dropped(&self) -> Vec<String> {
            self.firewall.blocked.lock().unwrap().clone()
        }

        /// The site-to-site plan the fake firewall loaded last.
        fn site_plan(&self) -> Option<Plan> {
            self.firewall.sites.lock().unwrap().clone()
        }

        /// Makes the configuration ocserv runs with ask every user for a
        /// code after the password.
        fn codes_on(&self) {
            write_ocserv_config(self.dir.path(), true);
        }

        fn login(&mut self, name: &str, password: &str, from: &str, now: u64) -> Response {
            self.service.handle(
                Request::Login {
                    name: name.to_owned(),
                    password: password.to_owned(),
                    from: from.to_owned(),
                },
                now,
            )
        }

        fn audit(&self) -> String {
            fs::read_to_string(self.dir.path().join("audit.log")).unwrap()
        }

        fn stored(&self) -> Admin {
            Store::open(&self.dir.path().join("admins.json"))
                .unwrap()
                .get("alex")
                .cloned()
                .unwrap()
        }
    }

    fn signed_in(response: Response) -> (String, String, Scope) {
        match response {
            Response::SignedIn {
                session,
                csrf,
                scope,
                ..
            } => (session, csrf, scope),
            other => panic!("expected a sign-in, got {other:?}"),
        }
    }

    #[test]
    fn a_password_alone_signs_in_from_the_lan() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, _csrf, scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 10));
        assert_eq!(scope, Scope::Full);
        let whoami = fixture.service.handle(Request::Whoami { session }, 11);
        assert!(
            matches!(whoami, Response::Admin { ref name, role: Role::Owner, .. } if name == "alex")
        );
        assert_eq!(fixture.stored().last_login, Some(10));
        assert!(
            fixture
                .audit()
                .contains("password only, from a LAN network")
        );
    }

    #[test]
    fn names_are_matched_in_lower_case() {
        let mut fixture = Fixture::new(|_admin| {});
        signed_in(fixture.login("ALEX", PASSWORD, LAN, 10));
    }

    #[test]
    fn outside_the_lan_a_second_factor_is_required() {
        let mut fixture = Fixture::new(|_admin| {});
        assert_eq!(
            fixture.login("alex", PASSWORD, VPN, 10),
            Response::SecondFactorNotEnrolled
        );
        assert!(fixture.audit().contains("the account has none"));
    }

    #[test]
    fn an_enrolled_factor_is_asked_for_outside_the_lan() {
        let mut fixture =
            Fixture::new(|admin| admin.totp_secret = Some("JBSWY3DPEHPK3PXP".to_owned()));
        assert!(matches!(
            fixture.login("alex", PASSWORD, VPN, 10),
            Response::SecondFactorRequired { .. }
        ));
        let (_session, _csrf, scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 11));
        assert_eq!(scope, Scope::Full);
    }

    #[test]
    fn a_new_account_gets_an_enrollment_only_session_outside_the_lan() {
        let mut fixture = Fixture::new(|admin| {
            admin.enrollment_open = true;
            admin.must_change_password = true;
        });
        let response = fixture.login("alex", PASSWORD, VPN, 10);
        assert!(matches!(
            response,
            Response::SignedIn {
                must_change_password: true,
                ..
            }
        ));
        let (_session, _csrf, scope) = signed_in(response);
        assert_eq!(scope, Scope::Enrollment);
        assert!(fixture.audit().contains("enrollment-only session"));
    }

    #[test]
    fn wrong_passwords_lock_the_account() {
        let mut fixture = Fixture::new(|_admin| {});
        assert_eq!(fixture.login("alex", "wrong", LAN, 10), Response::Denied);
        assert_eq!(fixture.login("alex", "wrong", LAN, 11), Response::Denied);
        assert_eq!(
            fixture.login("alex", "wrong", "192.168.1.21", 12),
            Response::Locked { retry_after: 900 }
        );
        assert_eq!(fixture.stored().locked_until, Some(912));
        assert_eq!(
            fixture.login("alex", PASSWORD, "192.168.1.22", 13),
            Response::Locked { retry_after: 899 }
        );
        signed_in(fixture.login("alex", PASSWORD, "192.168.1.22", 912));
        assert_eq!(fixture.stored().failed_logins, 0);
    }

    #[test]
    fn a_right_password_resets_the_count() {
        let mut fixture = Fixture::new(|_admin| {});
        assert_eq!(fixture.login("alex", "wrong", LAN, 10), Response::Denied);
        assert_eq!(fixture.login("alex", "wrong", LAN, 11), Response::Denied);
        signed_in(fixture.login("alex", PASSWORD, LAN, 12));
        assert_eq!(fixture.login("alex", "wrong", LAN, 13), Response::Denied);
        assert_eq!(fixture.stored().locked_until, None);
    }

    #[test]
    fn unknown_names_are_refused_like_wrong_passwords() {
        let mut fixture = Fixture::new(|_admin| {});
        assert_eq!(
            fixture.login("mallory", PASSWORD, LAN, 10),
            Response::Denied
        );
        assert_eq!(
            fixture.login("bad name!", PASSWORD, LAN, 11),
            Response::Denied
        );
        let audit = fixture.audit();
        assert!(audit.contains("no admin of that name"), "{audit}");
        assert!(
            audit.contains("\"detail\":\"not an admin name: only letters"),
            "{audit}"
        );
    }

    #[test]
    fn an_address_is_blocked_after_failures_across_names() {
        let mut fixture = Fixture::new(|_admin| {});
        let attacker = "203.0.113.9";
        for (name, now) in [("a1", 10), ("a2", 11), ("a3", 12)] {
            assert_eq!(
                fixture.login(name, PASSWORD, attacker, now),
                Response::Denied
            );
        }
        assert_eq!(
            fixture.login("alex", PASSWORD, attacker, 13),
            Response::Locked { retry_after: 899 }
        );
        signed_in(fixture.login("alex", PASSWORD, LAN, 14));
    }

    #[test]
    fn a_malformed_address_is_an_error() {
        let mut fixture = Fixture::new(|_admin| {});
        assert!(matches!(
            fixture.login("alex", PASSWORD, "nowhere", 10),
            Response::Error { .. }
        ));
    }

    #[test]
    fn logging_out_ends_the_session() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 10));
        assert_eq!(
            fixture.service.handle(
                Request::Logout {
                    session: session.clone()
                },
                11
            ),
            Response::Done
        );
        assert_eq!(
            fixture.service.handle(
                Request::Whoami {
                    session: session.clone()
                },
                12
            ),
            Response::Denied
        );
        assert_eq!(
            fixture.service.handle(Request::Logout { session }, 13),
            Response::Done
        );
    }

    fn change(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        current: &str,
        new: &str,
        now: u64,
    ) -> Response {
        fixture.service.handle(
            Request::ChangePassword {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                current: current.to_owned(),
                new: new.to_owned(),
            },
            now,
        )
    }

    #[test]
    fn replacing_the_password() {
        let mut fixture = Fixture::new(|admin| admin.must_change_password = true);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 10));
        let (other, _other_csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 11));
        let new = "a much longer passphrase";
        assert_eq!(
            change(&mut fixture, &session, "forged", PASSWORD, new, 12),
            Response::Denied
        );
        assert_eq!(
            change(&mut fixture, &session, &csrf, "wrong", new, 13),
            Response::Denied
        );
        assert!(matches!(
            change(&mut fixture, &session, &csrf, PASSWORD, "short", 14),
            Response::Invalid { .. }
        ));
        assert!(matches!(
            change(&mut fixture, &session, &csrf, PASSWORD, PASSWORD, 15),
            Response::Invalid { .. }
        ));
        assert_eq!(
            change(&mut fixture, &session, &csrf, PASSWORD, new, 16),
            Response::Done
        );
        assert!(!fixture.stored().must_change_password);
        assert_eq!(
            fixture
                .service
                .handle(Request::Whoami { session: other }, 17),
            Response::Denied
        );
        assert!(matches!(
            fixture.service.handle(Request::Whoami { session }, 18),
            Response::Admin { .. }
        ));
        assert_eq!(fixture.login("alex", PASSWORD, LAN, 19), Response::Denied);
        signed_in(fixture.login("alex", new, LAN, 20));
        let audit = fixture.audit();
        assert!(audit.contains("CSRF token"), "{audit}");
        assert!(
            audit.contains("password replaced; ended 1 other session\""),
            "{audit}"
        );
    }

    #[test]
    fn guessing_the_current_password_locks_the_account_and_ends_its_sessions() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, 10));
        assert_eq!(
            change(
                &mut fixture,
                &session,
                &csrf,
                "guess 1",
                "new passphrase 1",
                11
            ),
            Response::Denied
        );
        assert_eq!(
            change(
                &mut fixture,
                &session,
                &csrf,
                "guess 2",
                "new passphrase 1",
                12
            ),
            Response::Denied
        );
        assert_eq!(
            change(
                &mut fixture,
                &session,
                &csrf,
                "guess 3",
                "new passphrase 1",
                13
            ),
            Response::Denied
        );
        assert_eq!(
            fixture.service.handle(Request::Whoami { session }, 14),
            Response::Denied
        );
        assert!(fixture.stored().locked_until.is_some());
    }

    #[test]
    fn new_password_rules() {
        assert!(check_new_password("twelve chars", "", 12).is_ok());
        assert!(check_new_password("eleven char", "", 12).is_err());
        assert!(check_new_password("            ", "", 12).is_err());
        assert!(check_new_password("same password", "same password", 12).is_err());
        assert!(check_new_password(&"x".repeat(MAX_PASSWORD_LEN + 1), "", 12).is_err());
        assert!(
            check_new_password(
                "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
                "",
                12
            )
            .is_ok()
        );
    }

    /// "12345678901234567890", the RFC 6238 test secret.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /// A moment whose TOTP code is 005924 for `SECRET`.
    const MOMENT: u64 = 1_234_567_890;

    fn pending_token(response: Response) -> String {
        match response {
            Response::SecondFactorRequired { pending } => pending,
            other => panic!("expected a pending sign-in, got {other:?}"),
        }
    }

    fn second(fixture: &mut Fixture, pending: &str, code: &str, now: u64) -> Response {
        fixture.service.handle(
            Request::SecondFactor {
                pending: pending.to_owned(),
                code: code.to_owned(),
            },
            now,
        )
    }

    #[test]
    fn a_totp_code_completes_the_sign_in_once() {
        let mut fixture = Fixture::new(|admin| admin.totp_secret = Some(SECRET.to_owned()));
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT));
        let (_session, _csrf, scope) = signed_in(second(&mut fixture, &pending, "005924", MOMENT));
        assert_eq!(scope, Scope::Full);
        assert_eq!(
            second(&mut fixture, &pending, "005924", MOMENT),
            Response::Denied
        );
        let again = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 1));
        assert_eq!(
            second(&mut fixture, &again, "005924", MOMENT + 1),
            Response::Denied
        );
        assert!(fixture.audit().contains("password and TOTP code"));
    }

    #[test]
    fn wrong_totp_codes_count_toward_the_lockout() {
        let mut fixture = Fixture::new(|admin| admin.totp_secret = Some(SECRET.to_owned()));
        for now in [MOMENT, MOMENT + 1] {
            let pending = pending_token(fixture.login("alex", PASSWORD, VPN, now));
            assert_eq!(
                second(&mut fixture, &pending, "000000", now),
                Response::Denied
            );
        }
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 2));
        assert_eq!(
            second(&mut fixture, &pending, "000000", MOMENT + 2),
            Response::Locked { retry_after: 900 }
        );
        assert!(fixture.audit().contains("wrong TOTP code"));
    }

    #[test]
    fn enrolling_totp_opens_the_enrollment_session_and_closes_enrollment() {
        let mut fixture = Fixture::new(|admin| admin.enrollment_open = true);
        let (session, csrf, scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        assert_eq!(scope, Scope::Enrollment);
        let begun = fixture.service.handle(
            Request::TotpBegin {
                session: session.clone(),
                csrf: csrf.clone(),
            },
            MOMENT,
        );
        let Response::TotpSecret { secret, uri } = begun else {
            panic!("expected a TOTP secret, got {begun:?}");
        };
        assert!(uri.contains(&secret), "{uri}");
        let code = format!("{:06}", totp::code(&secret, MOMENT / totp::STEP).unwrap());
        let wrong = fixture.service.handle(
            Request::TotpConfirm {
                session: session.clone(),
                csrf: csrf.clone(),
                code: "000000".to_owned(),
            },
            MOMENT,
        );
        assert!(matches!(wrong, Response::Invalid { .. }));
        let confirmed = fixture.service.handle(
            Request::TotpConfirm {
                session: session.clone(),
                csrf,
                code,
            },
            MOMENT,
        );
        assert_eq!(confirmed, Response::Done);
        let whoami = fixture
            .service
            .handle(Request::Whoami { session }, MOMENT + 1);
        assert!(matches!(
            whoami,
            Response::Admin {
                scope: Scope::Full,
                ..
            }
        ));
        let stored = fixture.stored();
        assert!(!stored.enrollment_open);
        assert_eq!(stored.totp_secret, Some(secret));
        pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 2));
    }

    #[test]
    fn totp_enrollment_waits_for_the_one_time_password_to_be_replaced() {
        let mut fixture = Fixture::new(|admin| {
            admin.enrollment_open = true;
            admin.must_change_password = true;
        });
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        let begun = fixture
            .service
            .handle(Request::TotpBegin { session, csrf }, MOMENT);
        assert!(matches!(begun, Response::Invalid { .. }), "{begun:?}");
    }

    fn end(fixture: &mut Fixture, session: &str, csrf: &str, id: u64) -> Response {
        fixture.service.handle(
            Request::EndSession {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                id,
            },
            MOMENT,
        )
    }

    fn vpn_sessions(fixture: &mut Fixture, session: &str) -> Response {
        fixture.service.handle(
            Request::ListSessions {
                session: session.to_owned(),
            },
            MOMENT,
        )
    }

    #[test]
    fn an_owner_sees_the_server_and_ends_a_vpn_session() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let status = fixture.service.handle(
            Request::ServerStatus {
                session: session.clone(),
            },
            MOMENT,
        );
        assert!(
            matches!(
                status,
                Response::Server {
                    server: Status::Online {
                        active_sessions: 2,
                        ..
                    }
                }
            ),
            "{status:?}"
        );
        assert_eq!(end(&mut fixture, &session, &csrf, 246), Response::Done);
        let Response::Sessions { sessions, .. } = vpn_sessions(&mut fixture, &session) else {
            panic!("expected the session list");
        };
        assert_eq!(sessions.iter().map(|vpn| vpn.id).collect::<Vec<_>>(), [245]);
        assert!(fixture.audit().contains("ended session 246 of sam"));
        assert!(matches!(
            end(&mut fixture, &session, &csrf, 246),
            Response::Invalid { .. }
        ));
    }

    #[test]
    fn a_viewer_sees_the_sessions_but_cannot_end_one() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        assert!(matches!(
            vpn_sessions(&mut fixture, &session),
            Response::Sessions { .. }
        ));
        assert!(matches!(
            end(&mut fixture, &session, &csrf, 245),
            Response::Invalid { .. }
        ));
        assert!(fixture.audit().contains("viewers cannot change the server"));
        let Response::Sessions { sessions, .. } = vpn_sessions(&mut fixture, &session) else {
            panic!("expected the session list");
        };
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn ending_a_vpn_session_needs_the_csrf_token() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        assert_eq!(end(&mut fixture, &session, "forged", 245), Response::Denied);
    }

    #[test]
    fn an_enrollment_only_session_cannot_see_the_server() {
        let mut fixture = Fixture::new(|admin| admin.enrollment_open = true);
        let (session, csrf, scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        assert_eq!(scope, Scope::Enrollment);
        assert_eq!(vpn_sessions(&mut fixture, &session), Response::Denied);
        assert_eq!(
            fixture.service.handle(
                Request::ServerStatus {
                    session: session.clone()
                },
                MOMENT
            ),
            Response::Denied
        );
        assert_eq!(end(&mut fixture, &session, &csrf, 245), Response::Denied);
    }

    fn change_user(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        change: UserChange,
    ) -> Response {
        fixture.service.handle(
            Request::ChangeVpnUser {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                change,
            },
            MOMENT,
        )
    }

    fn vpn_users(fixture: &mut Fixture, session: &str) -> Vec<vpnusers::VpnUser> {
        let listed = fixture.service.handle(
            Request::ListVpnUsers {
                session: session.to_owned(),
            },
            MOMENT,
        );
        let Response::VpnUsers { users, .. } = listed else {
            panic!("expected the user list, got {listed:?}");
        };
        users
    }

    fn client_certificates(fixture: &mut Fixture, session: &str) -> Vec<ClientCertificate> {
        let listed = fixture.service.handle(
            Request::ClientCertificates {
                session: session.to_owned(),
            },
            MOMENT,
        );
        let Response::ClientCertificates { certificates, days } = listed else {
            panic!("expected the client certificates, got {listed:?}");
        };
        assert_eq!(days, 365);
        certificates
    }

    fn issued_of(response: Response) -> IssuedCertificate {
        match response {
            Response::ClientCertificateIssued { issued } => *issued,
            other => panic!("expected an issued certificate, got {other:?}"),
        }
    }

    const REQUEST: &str =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";

    #[test]
    fn certificates_are_issued_renewed_and_revoked_for_vpn_users() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let issue = |fixture: &mut Fixture, user: &str, how: IssueHow| {
            fixture.service.handle(
                Request::IssueClientCertificate {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    user: user.to_owned(),
                    how,
                },
                MOMENT,
            )
        };
        let renew = |fixture: &mut Fixture, serial: &str| {
            fixture.service.handle(
                Request::RenewClientCertificate {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    serial: serial.to_owned(),
                },
                MOMENT,
            )
        };
        let revoke = |fixture: &mut Fixture, serial: &str| {
            fixture.service.handle(
                Request::RevokeClientCertificate {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    serial: serial.to_owned(),
                },
                MOMENT,
            )
        };
        let keyed = issued_of(issue(
            &mut fixture,
            "sam",
            IssueHow::KeyFile {
                cipher: Cipher::Aes256,
            },
        ));
        let key_file = keyed.key_file.clone().unwrap();
        assert_eq!(key_file.cipher, Cipher::Aes256);
        assert!(
            key_file.passphrase.split('-').count() >= 6,
            "five words, which may hold hyphens, and a number"
        );
        let p12 = data_encoding::BASE64
            .decode(key_file.p12_base64.as_bytes())
            .unwrap();
        assert!(
            String::from_utf8(p12)
                .unwrap()
                .contains(&key_file.passphrase)
        );
        assert_eq!(keyed.not_after, MOMENT + 365 * 86_400);
        let requested = issued_of(issue(
            &mut fixture,
            "sam",
            IssueHow::Request {
                pem: REQUEST.to_owned(),
            },
        ));
        assert!(requested.key_file.is_none());
        assert!(matches!(
            issue(
                &mut fixture,
                "sam",
                IssueHow::Request {
                    pem: "not a request".to_owned()
                }
            ),
            Response::Invalid { .. }
        ));
        assert!(matches!(
            issue(
                &mut fixture,
                "nobody",
                IssueHow::KeyFile {
                    cipher: Cipher::Aes256
                }
            ),
            Response::Invalid { .. }
        ));
        let listed = client_certificates(&mut fixture, &session);
        let serials: Vec<&str> = listed.iter().map(|issued| issued.serial.as_str()).collect();
        assert_eq!(serials, [requested.serial.as_str(), keyed.serial.as_str()]);
        assert_eq!(listed[1].groups, ["staff"]);
        assert_eq!(
            (listed[0].method, listed[1].method),
            (Method::Request, Method::KeyFile)
        );
        let again = issued_of(renew(&mut fixture, &requested.serial));
        assert!(again.key_file.is_none());
        let older = issued_of(issue(
            &mut fixture,
            "sam",
            IssueHow::KeyFile {
                cipher: Cipher::TripleDes,
            },
        ));
        let rekeyed = issued_of(renew(&mut fixture, &older.serial));
        assert_eq!(rekeyed.key_file.unwrap().cipher, Cipher::TripleDes);
        assert_eq!(revoke(&mut fixture, &keyed.serial), Response::Done);
        assert!(matches!(
            revoke(&mut fixture, &keyed.serial),
            Response::Invalid { .. }
        ));
        assert!(matches!(
            renew(&mut fixture, &keyed.serial),
            Response::Invalid { .. }
        ));
        let remove = UserChange::Remove {
            name: "sam".to_owned(),
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, remove),
            Response::Done
        );
        let listed = client_certificates(&mut fixture, &session);
        assert_eq!(listed.len(), 5);
        assert!(listed.iter().all(|issued| issued.revoked.is_some()));
        let audit = fixture.audit();
        assert!(
            audit.contains("issued a certificate for sam in a key file encrypted with AES-256"),
            "{audit}"
        );
        assert!(
            audit.contains("issued a certificate for sam for the key of a signing request"),
            "{audit}"
        );
        assert!(
            audit.contains("renewed a certificate for sam for the key it had"),
            "{audit}"
        );
        assert!(
            audit.contains(&format!("revoked the certificate {} of sam", keyed.serial)),
            "{audit}"
        );
        assert!(
            audit.contains("removed sam and revoked their 4 certificates"),
            "{audit}"
        );
        assert!(!audit.contains(&key_file.passphrase), "{audit}");
    }

    #[test]
    fn a_viewer_sees_the_certificates_but_cannot_issue_or_revoke_one() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        assert!(client_certificates(&mut fixture, &session).is_empty());
        let issued = fixture.service.handle(
            Request::IssueClientCertificate {
                session: session.clone(),
                csrf: csrf.clone(),
                user: "sam".to_owned(),
                how: IssueHow::KeyFile {
                    cipher: Cipher::Aes256,
                },
            },
            MOMENT,
        );
        assert!(matches!(issued, Response::Invalid { .. }), "{issued:?}");
        let revoked = fixture.service.handle(
            Request::RevokeClientCertificate {
                session,
                csrf,
                serial: "01".to_owned(),
            },
            MOMENT,
        );
        assert!(matches!(revoked, Response::Invalid { .. }), "{revoked:?}");
    }

    /// The kit a change answers with.
    fn kit_of(response: Response) -> Kit {
        match response {
            Response::Kit { kit } => *kit,
            other => panic!("expected an onboarding kit, got {other:?}"),
        }
    }

    #[test]
    fn an_owner_adds_changes_locks_and_removes_vpn_users() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = |groups: &str| UserChange::Add {
            name: "jo".to_owned(),
            groups: groups.to_owned(),
            password: Some("jo-first-password".to_owned()),
        };
        let kit = kit_of(change_user(
            &mut fixture,
            &session,
            &csrf,
            add("staff, admins"),
        ));
        assert_eq!(kit.password.as_deref(), Some("jo-first-password"));
        assert_eq!(kit.address, "vpn.example.com:4443");
        assert_eq!(kit.pin, kit::SAMPLE_PIN);
        assert!(kit.authenticator.is_none() && !kit.codes);
        assert!(matches!(
            change_user(&mut fixture, &session, &csrf, add("")),
            Response::Invalid { .. }
        ));
        let set = UserChange::SetPassword {
            name: "jo".to_owned(),
            password: Some("jo-second-password".to_owned()),
        };
        let kit = kit_of(change_user(&mut fixture, &session, &csrf, set));
        assert_eq!(kit.password.as_deref(), Some("jo-second-password"));
        assert_eq!(kit.groups, ["staff", "admins"]);
        let jo = vpn_users(&mut fixture, &session)
            .into_iter()
            .find(|user| user.name == "jo")
            .unwrap();
        assert_eq!(jo.groups, ["staff", "admins"]);
        let lock = UserChange::Lock {
            name: "sam".to_owned(),
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, lock),
            Response::Done
        );
        assert!(
            matches!(vpn_users(&mut fixture, &session).iter().find(|user| user.name == "sam"), Some(sam) if sam.locked)
        );
        let remove = UserChange::Remove {
            name: "jo".to_owned(),
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, remove),
            Response::Done
        );
        assert!(
            !vpn_users(&mut fixture, &session)
                .iter()
                .any(|user| user.name == "jo")
        );
        let audit = fixture.audit();
        assert!(audit.contains("added jo in staff, admins"), "{audit}");
        assert!(audit.contains("replaced the password of jo"), "{audit}");
        assert!(
            audit.contains("locked sam and ended their sessions"),
            "{audit}"
        );
        assert!(audit.contains("removed jo"), "{audit}");
        assert!(
            !audit.contains("jo-first-password") && !audit.contains("jo-second-password"),
            "{audit}"
        );
    }

    #[test]
    fn a_users_groups_are_changed_checked_and_audited() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let set = |groups: &str| UserChange::SetGroups {
            name: "sam".to_owned(),
            groups: groups.to_owned(),
        };
        let groups_of_sam = |fixture: &mut Fixture| {
            vpn_users(fixture, &session)
                .into_iter()
                .find(|user| user.name == "sam")
                .unwrap()
                .groups
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, set("lab, staff")),
            Response::Done
        );
        assert_eq!(groups_of_sam(&mut fixture), ["lab", "staff"]);
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, set("lab,staff")),
            Response::Done
        );
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, set("")),
            Response::Done
        );
        assert!(groups_of_sam(&mut fixture).is_empty());
        assert!(matches!(
            change_user(&mut fixture, &session, &csrf, set("two words")),
            Response::Invalid { .. }
        ));
        let unknown = UserChange::SetGroups {
            name: "nobody".to_owned(),
            groups: "lab".to_owned(),
        };
        assert!(matches!(
            change_user(&mut fixture, &session, &csrf, unknown),
            Response::Invalid { .. }
        ));
        let audit = fixture.audit();
        assert!(
            audit.contains("set the groups of sam to lab, staff"),
            "{audit}"
        );
        assert!(audit.contains("took sam out of every group"), "{audit}");
        assert_eq!(audit.matches("vpn.user.groups").count(), 2, "{audit}");
    }

    #[test]
    fn vpn_user_changes_are_checked() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let bad_name = UserChange::Add {
            name: "-l".to_owned(),
            groups: String::new(),
            password: Some("a-long-enough-password".to_owned()),
        };
        let empty_password = UserChange::Add {
            name: "jo".to_owned(),
            groups: String::new(),
            password: Some(String::new()),
        };
        let short_password = UserChange::SetPassword {
            name: "sam".to_owned(),
            password: Some("eleven-char".to_owned()),
        };
        let unknown = UserChange::Unlock {
            name: "nobody".to_owned(),
        };
        for refused in [bad_name, empty_password, short_password, unknown] {
            assert!(matches!(
                change_user(&mut fixture, &session, &csrf, refused),
                Response::Invalid { .. }
            ));
        }
        assert_eq!(vpn_users(&mut fixture, &session).len(), 3);
    }

    #[test]
    fn with_codes_on_a_new_user_gets_an_authenticator_key_and_a_generated_password() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = UserChange::Add {
            name: "casey".to_owned(),
            groups: "staff".to_owned(),
            password: None,
        };
        let kit = kit_of(change_user(&mut fixture, &session, &csrf, add));
        let password = kit.password.clone().unwrap();
        assert!(password.split('-').count() >= 6, "{password}");
        let authenticator = kit.authenticator.clone().unwrap();
        assert!(
            authenticator.uri.contains("casey%40vpn.example.com"),
            "{}",
            authenticator.uri
        );
        assert!(kit.codes);
        let casey = vpn_users(&mut fixture, &session)
            .into_iter()
            .find(|user| user.name == "casey")
            .unwrap();
        assert!(casey.otp);
        let audit = fixture.audit();
        assert!(
            audit.contains(
                "added casey in staff with a generated password and an authenticator key"
            ),
            "{audit}"
        );
        assert!(
            !audit.contains(&password) && !audit.contains(&authenticator.key),
            "{audit}"
        );
    }

    #[test]
    fn an_authenticator_key_is_reset_only_while_the_vpn_asks_for_codes() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let reset = || UserChange::ResetOtp {
            name: "sam".to_owned(),
        };
        assert!(matches!(
            change_user(&mut fixture, &session, &csrf, reset()),
            Response::Invalid { .. }
        ));
        fixture.codes_on();
        let kit = kit_of(change_user(&mut fixture, &session, &csrf, reset()));
        assert!(kit.password.is_none());
        assert!(kit.authenticator.is_some());
        assert!(
            vpn_users(&mut fixture, &session)
                .iter()
                .any(|user| user.name == "sam" && user.otp)
        );
        let audit = fixture.audit();
        assert!(
            audit.contains("gave sam a new authenticator key"),
            "{audit}"
        );
    }

    #[test]
    fn removing_a_user_removes_their_authenticator_key() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let remove = UserChange::Remove {
            name: "alex".to_owned(),
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, remove),
            Response::Done
        );
        let audit = fixture.audit();
        assert!(
            audit.contains("removed alex and their authenticator key"),
            "{audit}"
        );
    }

    #[test]
    fn a_server_the_kit_cannot_describe_changes_nothing() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        fs::remove_file(fixture.dir.path().join("server-cert.pem")).unwrap();
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = UserChange::Add {
            name: "casey".to_owned(),
            groups: String::new(),
            password: None,
        };
        let refused = change_user(&mut fixture, &session, &csrf, add);
        assert!(
            matches!(&refused, Response::Error { message } if message.contains("server-cert.pem")),
            "{refused:?}"
        );
        assert!(
            !vpn_users(&mut fixture, &session)
                .iter()
                .any(|user| user.name == "casey")
        );
    }

    fn portal_login(
        fixture: &mut Fixture,
        name: &str,
        password: &str,
        code: Option<&str>,
        from: &str,
    ) -> PortalResponse {
        let request = PortalRequest::Login {
            name: name.to_owned(),
            password: password.to_owned(),
            code: code.map(str::to_owned),
            from: from.to_owned(),
        };
        match fixture.service.handle(Request::Portal { request }, MOMENT) {
            Response::Portal { response } => response,
            other => panic!("expected a portal answer, got {other:?}"),
        }
    }

    fn portal(fixture: &mut Fixture, request: PortalRequest) -> PortalResponse {
        match fixture.service.handle(Request::Portal { request }, MOMENT) {
            Response::Portal { response } => response,
            other => panic!("expected a portal answer, got {other:?}"),
        }
    }

    #[test]
    fn a_vpn_user_signs_in_to_the_portal_with_their_vpn_password() {
        let mut fixture = Fixture::new(|_admin| {});
        let PortalResponse::SignedIn {
            session,
            user,
            scope,
            ..
        } = portal_login(&mut fixture, "sam", "sam-password", None, VPN)
        else {
            panic!("sam was not signed in");
        };
        assert_eq!((user.as_str(), scope), ("sam", PortalScope::Full));
        for (name, password) in [
            ("sam", "wrong"),
            ("riley", "riley-password"),
            ("nobody", "x"),
        ] {
            assert_eq!(
                portal_login(&mut fixture, name, password, None, LAN),
                PortalResponse::Denied,
                "{name}"
            );
        }
        let whoami = portal(
            &mut fixture,
            PortalRequest::Whoami {
                session: session.clone(),
            },
        );
        assert!(matches!(whoami, PortalResponse::User { ref user, .. } if user == "sam"));
        let ended = PortalRequest::Logout {
            session: session.clone(),
        };
        assert_eq!(portal(&mut fixture, ended), PortalResponse::Done);
        assert_eq!(
            portal(&mut fixture, PortalRequest::Whoami { session }),
            PortalResponse::Denied
        );
        let audit = fixture.audit();
        for detail in [
            "password; the VPN asks for no codes",
            "wrong password",
            "the VPN user is locked",
            "no VPN user of that name",
            "\"action\":\"portal.logout\"",
        ] {
            assert!(audit.contains(detail), "{detail}: {audit}");
        }
        assert!(!audit.contains("sam-password"), "{audit}");
    }

    #[test]
    fn with_codes_on_the_portal_asks_for_a_code_or_offers_only_a_key() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        let asked = || PortalRequest::Code {
            pending: String::new(),
            code: String::new(),
        };
        let PortalResponse::CodeRequired { pending } =
            portal_login(&mut fixture, "alex", "alex-password", None, VPN)
        else {
            panic!("no code was asked for");
        };
        let wrong = PortalRequest::Code {
            pending: pending.clone(),
            code: "000000".to_owned(),
        };
        assert_eq!(portal(&mut fixture, wrong), PortalResponse::Denied);
        let spent = PortalRequest::Code {
            pending,
            code: "123456".to_owned(),
        };
        assert_eq!(portal(&mut fixture, spent), PortalResponse::Denied);
        assert_eq!(portal(&mut fixture, asked()), PortalResponse::Denied);
        let PortalResponse::CodeRequired { pending } =
            portal_login(&mut fixture, "alex", "alex-password", None, VPN)
        else {
            panic!("no code was asked for");
        };
        let right = PortalRequest::Code {
            pending,
            code: "123456".to_owned(),
        };
        assert!(matches!(
            portal(&mut fixture, right),
            PortalResponse::SignedIn {
                scope: PortalScope::Full,
                ..
            }
        ));
        assert_eq!(
            portal_login(&mut fixture, "alex", "alex-password", Some("000000"), VPN),
            PortalResponse::Denied
        );
        assert!(matches!(
            portal_login(&mut fixture, "alex", "alex-password", Some("123456"), VPN),
            PortalResponse::SignedIn {
                scope: PortalScope::Full,
                ..
            }
        ));
        assert!(matches!(
            portal_login(&mut fixture, "sam", "sam-password", None, VPN),
            PortalResponse::SignedIn {
                scope: PortalScope::EnrollKey,
                ..
            }
        ));
    }

    /// The codes `authenticator` gives at the step of `now` and either side.
    fn codes_near(authenticator: &Authenticator, now: u64) -> Vec<String> {
        let step = now / totp::STEP;
        (step - 1..=step + 1)
            .map(|step| format!("{:06}", totp::code(&authenticator.key, step).unwrap()))
            .collect()
    }

    #[test]
    fn a_keyless_user_sets_up_a_key_and_gets_the_full_portal() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        let PortalResponse::SignedIn {
            session,
            csrf,
            scope: PortalScope::EnrollKey,
            ..
        } = portal_login(&mut fixture, "sam", "sam-password", None, VPN)
        else {
            panic!("sam was not offered a key");
        };
        let begin = |given: &str| PortalRequest::KeyBegin {
            session: session.clone(),
            csrf: given.to_owned(),
            old_code: None,
        };
        assert_eq!(
            portal(&mut fixture, begin("forged")),
            PortalResponse::Denied
        );
        let PortalResponse::Key {
            authenticator,
            wrong: false,
        } = portal(&mut fixture, begin(&csrf))
        else {
            panic!("no key was issued");
        };
        assert!(
            authenticator.uri.contains("sam%40vpn.example.com"),
            "{}",
            authenticator.uri
        );
        let confirm = |code: &str| PortalRequest::KeyConfirm {
            session: session.clone(),
            csrf: csrf.clone(),
            code: code.to_owned(),
        };
        let near = codes_near(&authenticator, MOMENT);
        let wrong = ["000000", "111111", "222222", "333333"]
            .into_iter()
            .find(|candidate| !near.iter().any(|code| code == candidate))
            .unwrap();
        assert_eq!(
            portal(&mut fixture, confirm(wrong)),
            PortalResponse::Key {
                authenticator: authenticator.clone(),
                wrong: true,
            }
        );
        assert_eq!(
            portal(&mut fixture, confirm(&near[1])),
            PortalResponse::Done
        );
        assert!(matches!(
            portal(
                &mut fixture,
                PortalRequest::Whoami {
                    session: session.clone()
                }
            ),
            PortalResponse::User {
                scope: PortalScope::Full,
                ..
            }
        ));
        assert!(matches!(
            portal(&mut fixture, begin(&csrf)),
            PortalResponse::Invalid { ref message } if message.contains("current authenticator")
        ));
        let audit = fixture.audit();
        for detail in [
            "\"action\":\"portal.key.begin\"",
            "the code did not match the new authenticator key",
            "authenticator key set up; the session has the full portal",
        ] {
            assert!(audit.contains(detail), "{detail}: {audit}");
        }
        assert!(!audit.contains(&authenticator.key), "{audit}");
    }

    #[test]
    fn a_password_change_keeps_the_browsers_vpn_session_and_ends_the_others() {
        let mut fixture = Fixture::new(|_admin| {});
        let PortalResponse::SignedIn { session, csrf, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, "192.168.255.3")
        else {
            panic!("sam was not signed in through the tunnel");
        };
        let PortalResponse::SignedIn { session: other, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, LAN)
        else {
            panic!("sam was not signed in from the LAN");
        };
        let account = PortalRequest::Account {
            session: session.clone(),
        };
        let PortalResponse::Account {
            sessions,
            this_session,
            recent: true,
            ..
        } = portal(&mut fixture, account.clone())
        else {
            panic!("no account page for a fresh sign-in");
        };
        assert_eq!((sessions.len(), this_session), (1, Some(246)));
        let change = |current: &str, new: &str| PortalRequest::ChangePassword {
            session: session.clone(),
            csrf: csrf.clone(),
            current: current.to_owned(),
            new: new.to_owned(),
        };
        assert!(matches!(
            portal(&mut fixture, change("wrong", "sam-new-password")),
            PortalResponse::Invalid { ref message } if message.contains("current password")
        ));
        assert!(matches!(
            portal(&mut fixture, change("sam-password", "eleven-char")),
            PortalResponse::Invalid { ref message } if message.contains("at least 12")
        ));
        assert_eq!(
            portal(&mut fixture, change("sam-password", "sam-new-password")),
            PortalResponse::Done
        );
        assert_eq!(
            portal(&mut fixture, PortalRequest::Whoami { session: other }),
            PortalResponse::Denied
        );
        let PortalResponse::Account { sessions, .. } = portal(&mut fixture, account) else {
            panic!("the changing session lost its account page");
        };
        assert_eq!(sessions.len(), 1, "the browser's own VPN session stays");
        let audit = fixture.audit();
        assert!(
            audit.contains("password changed; ended 0 other VPN and 1 other portal sessions"),
            "{audit}"
        );
        assert!(audit.contains("wrong current password"), "{audit}");
        assert!(!audit.contains("sam-new-password"), "{audit}");
    }

    #[test]
    fn a_user_ends_only_their_own_vpn_sessions_and_changes_the_password_only_soon_after_signing_in()
    {
        let mut fixture = Fixture::new(|_admin| {});
        let PortalResponse::SignedIn { session, csrf, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, LAN)
        else {
            panic!("sam was not signed in");
        };
        let end = |id| PortalRequest::EndSession {
            session: session.clone(),
            csrf: csrf.clone(),
            id,
        };
        assert!(matches!(
            portal(&mut fixture, end(245)),
            PortalResponse::Invalid { .. }
        ));
        assert_eq!(portal(&mut fixture, end(246)), PortalResponse::Done);
        assert!(matches!(
            portal(&mut fixture, end(246)),
            PortalResponse::Invalid { .. }
        ));
        assert!(fixture.audit().contains("ended VPN session 246"));
        let late = PortalRequest::ChangePassword {
            session,
            csrf,
            current: "sam-password".to_owned(),
            new: "sam-new-password".to_owned(),
        };
        match fixture
            .service
            .handle(Request::Portal { request: late }, MOMENT + 600)
        {
            Response::Portal {
                response: PortalResponse::Invalid { message },
            } => assert!(message.contains("sign in again"), "{message}"),
            other => panic!("expected a request for a fresh sign-in, got {other:?}"),
        }
    }

    #[test]
    fn a_user_replaces_their_key_only_with_a_code_from_it() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        let PortalResponse::SignedIn { session, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, VPN)
        else {
            panic!("sam was not signed in");
        };
        assert!(matches!(
            portal(&mut fixture, PortalRequest::Account { session }),
            PortalResponse::Invalid { .. }
        ));
        let PortalResponse::SignedIn { session, csrf, .. } =
            portal_login(&mut fixture, "alex", "alex-password", Some("123456"), VPN)
        else {
            panic!("alex was not signed in");
        };
        let begin = |old: Option<&str>| PortalRequest::KeyBegin {
            session: session.clone(),
            csrf: csrf.clone(),
            old_code: old.map(str::to_owned),
        };
        assert!(matches!(
            portal(&mut fixture, begin(None)),
            PortalResponse::Invalid { ref message } if message.contains("current authenticator")
        ));
        assert!(matches!(
            portal(&mut fixture, begin(Some("000000"))),
            PortalResponse::Invalid { ref message } if message.contains("did not match")
        ));
        let PortalResponse::Key { authenticator, .. } = portal(&mut fixture, begin(Some("123456")))
        else {
            panic!("no replacement key was issued");
        };
        let confirm = PortalRequest::KeyConfirm {
            session: session.clone(),
            csrf: csrf.clone(),
            code: codes_near(&authenticator, MOMENT).swap_remove(1),
        };
        assert_eq!(portal(&mut fixture, confirm), PortalResponse::Done);
        let audit = fixture.audit();
        assert!(
            audit.contains("authenticator key replaced; the old key no longer works"),
            "{audit}"
        );
        assert!(
            audit.contains("a wrong code from the current authenticator key"),
            "{audit}"
        );
    }

    #[test]
    fn the_portal_home_gives_the_kit_only_to_a_full_session() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.codes_on();
        let PortalResponse::SignedIn { session, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, VPN)
        else {
            panic!("sam was not signed in");
        };
        assert!(matches!(
            portal(&mut fixture, PortalRequest::Home { session }),
            PortalResponse::Home {
                kit: None,
                needs_key: true,
                ..
            }
        ));
        let PortalResponse::SignedIn { session, .. } =
            portal_login(&mut fixture, "alex", "alex-password", Some("123456"), VPN)
        else {
            panic!("alex was not signed in");
        };
        let PortalResponse::Home {
            user,
            kit: Some(kit),
            needs_key: false,
            ..
        } = portal(&mut fixture, PortalRequest::Home { session })
        else {
            panic!("alex got no kit");
        };
        assert_eq!(
            (
                user.as_str(),
                kit.user.as_str(),
                kit.address.as_str(),
                kit.codes
            ),
            ("alex", "alex", "vpn.example.com:4443", true)
        );
        assert_eq!((kit.password, kit.authenticator), (None, None));
    }

    #[test]
    fn no_key_is_issued_while_codes_are_off_and_an_issued_key_waits_only_so_long() {
        let mut fixture = Fixture::new(|_admin| {});
        let PortalResponse::SignedIn { session, csrf, .. } =
            portal_login(&mut fixture, "sam", "sam-password", None, VPN)
        else {
            panic!("sam was not signed in");
        };
        let begin = PortalRequest::KeyBegin {
            session: session.clone(),
            csrf: csrf.clone(),
            old_code: None,
        };
        assert!(matches!(
            portal(&mut fixture, begin.clone()),
            PortalResponse::Invalid { ref message } if message.contains("asks for no codes")
        ));
        fixture.codes_on();
        let PortalResponse::Key { authenticator, .. } = portal(&mut fixture, begin) else {
            panic!("no key was issued");
        };
        let late = MOMENT + 300;
        let confirm = PortalRequest::KeyConfirm {
            session,
            csrf,
            code: codes_near(&authenticator, late).swap_remove(1),
        };
        match fixture
            .service
            .handle(Request::Portal { request: confirm }, late)
        {
            Response::Portal {
                response: PortalResponse::Invalid { message },
            } => assert!(message.contains("too long"), "{message}"),
            other => panic!("expected the setup to have run out, got {other:?}"),
        }
    }

    #[test]
    fn wrong_portal_passwords_lock_the_user_out_but_not_the_admins() {
        let mut fixture = Fixture::new(|_admin| {});
        for from in ["203.0.113.1", "203.0.113.2", "203.0.113.3"] {
            assert_eq!(
                portal_login(&mut fixture, "sam", "wrong", None, from),
                PortalResponse::Denied
            );
        }
        assert!(matches!(
            portal_login(&mut fixture, "sam", "sam-password", None, "203.0.113.4"),
            PortalResponse::Locked { .. }
        ));
        signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
    }

    #[test]
    fn a_viewer_cannot_change_vpn_users() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let lock = UserChange::Lock {
            name: "sam".to_owned(),
        };
        assert!(matches!(
            change_user(&mut fixture, &session, &csrf, lock),
            Response::Invalid { .. }
        ));
        assert!(
            !vpn_users(&mut fixture, &session)
                .iter()
                .any(|user| user.locked && user.name == "sam")
        );
    }

    fn bans(fixture: &mut Fixture, session: &str) -> Response {
        fixture.service.handle(
            Request::ListBans {
                session: session.to_owned(),
            },
            MOMENT,
        )
    }

    fn set_countries(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        rule: Option<&str>,
        codes: Option<&[&str]>,
    ) -> Response {
        fixture.service.handle(
            Request::SetCountries {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                rule: rule.map(str::to_owned),
                countries: codes.map(|codes| codes.iter().map(|code| (*code).to_owned()).collect()),
            },
            MOMENT,
        )
    }

    fn country_loads(fixture: &Fixture) -> Vec<Option<countries::RuleInput>> {
        fixture.firewall.countries.lock().unwrap().clone()
    }

    fn country_view(fixture: &mut Fixture, session: &str) -> CountryView {
        match bans(fixture, session) {
            Response::Bans { countries, .. } => *countries,
            other => panic!("expected the ban list, got {other:?}"),
        }
    }

    #[test]
    fn country_rules_are_checked_loaded_stored_and_audited() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let both = ["cn", "RU", "cn"];
        assert_eq!(
            set_countries(&mut fixture, &session, &csrf, Some("block"), Some(&both)),
            Response::Done
        );
        let loads = country_loads(&fixture);
        let input = loads.last().unwrap().as_ref().unwrap();
        assert_eq!(input.rule, countries::Rule::Block);
        assert_eq!(
            (&input.codes[..], &input.ports[..]),
            (&["CN".to_owned(), "RU".to_owned()][..], &[4443, 8443][..])
        );
        assert!(fixture.audit().contains("blocked CN, RU at the firewall"));
        let same = ["CN", "RU"];
        assert_eq!(
            set_countries(&mut fixture, &session, &csrf, Some("block"), Some(&same)),
            Response::Done
        );
        assert_eq!(
            country_loads(&fixture).len(),
            1,
            "an unchanged rule loads nothing"
        );
        let refused = set_countries(&mut fixture, &session, &csrf, Some("allow"), Some(&[]));
        assert!(
            matches!(&refused, Response::Invalid { message } if message.contains("at least one country")),
            "{refused:?}"
        );
        let refused = set_countries(&mut fixture, &session, &csrf, Some("block"), Some(&["CHN"]));
        assert!(
            matches!(&refused, Response::Invalid { message } if message.contains("CHN")),
            "{refused:?}"
        );
        assert_eq!(
            set_countries(&mut fixture, &session, &csrf, Some("off"), Some(&["CN"])),
            Response::Done
        );
        assert_eq!(country_loads(&fixture).last(), Some(&None));
        assert!(
            fixture
                .audit()
                .contains("turned the country rules off, keeping CN listed")
        );
        let view = country_view(&mut fixture, &session);
        assert_eq!(
            (view.rule.as_str(), &view.listed[..]),
            ("off", &["CN".to_owned()][..])
        );
        assert_eq!(view.database, Ok("Test-Country".to_owned()));
        assert!(
            view.names
                .contains(&("US".to_owned(), "United States".to_owned()))
        );
        assert!(view.enforceable && !view.rule_from_env && !view.list_from_env);
    }

    #[test]
    fn country_rules_that_would_drop_the_admin_are_refused() {
        let mut fixture = Fixture::new(|admin| admin.totp_secret = Some(SECRET.to_owned()));
        let pending = pending_token(fixture.login("alex", PASSWORD, "203.0.113.9", MOMENT));
        let (session, csrf, _scope) = signed_in(second(&mut fixture, &pending, "005924", MOMENT));
        for (rule, code) in [("block", "US"), ("allow", "CN")] {
            let refused = set_countries(&mut fixture, &session, &csrf, Some(rule), Some(&[code]));
            assert!(
                matches!(&refused, Response::Invalid { message }
                    if message.contains("203.0.113.9 (US)") && message.contains("lock you out")),
                "{refused:?}"
            );
        }
        assert!(country_loads(&fixture).is_empty());
        assert!(!fixture.dir.path().join("country-rules.json").exists());
        assert_eq!(
            set_countries(&mut fixture, &session, &csrf, Some("allow"), Some(&["US"])),
            Response::Done
        );
    }

    #[test]
    fn the_environment_wins_over_the_panels_country_rules() {
        let mut fixture = Fixture::new(|_| {});
        fixture.service.countries.environment.rule = Some("block".to_owned());
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let refused = set_countries(&mut fixture, &session, &csrf, Some("off"), Some(&["IR"]));
        assert!(
            matches!(&refused, Response::Invalid { message } if message.contains("COUNTRY_RULE")),
            "{refused:?}"
        );
        assert_eq!(
            set_countries(&mut fixture, &session, &csrf, None, Some(&["IR"])),
            Response::Done
        );
        let loads = country_loads(&fixture);
        assert_eq!(loads.last().unwrap().as_ref().unwrap().codes, ["IR"]);
        let view = country_view(&mut fixture, &session);
        assert!(view.rule_from_env && !view.list_from_env);
        assert_eq!(view.rule, "block");
    }

    #[test]
    fn the_bans_page_counts_failed_sign_ins_by_country() {
        let mut fixture = Fixture::new(|_| {});
        for from in ["192.0.2.5", "192.0.2.6", "203.0.113.7", "198.51.100.1"] {
            let what = What::SignInFailed {
                user: "mallory".to_owned(),
                from: Some(from.to_owned()),
            };
            fixture
                .service
                .events
                .add(Event { time: MOMENT, what }, None);
        }
        let what = What::Connected {
            user: "bob".to_owned(),
            group: None,
            session: None,
            from: Some("203.0.113.8".to_owned()),
            vpn_ipv4: None,
            vpn_ipv6: None,
            client: None,
        };
        fixture
            .service
            .events
            .add(Event { time: MOMENT, what }, None);
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let view = country_view(&mut fixture, &session);
        assert_eq!(
            view.failed,
            [
                (Some("CN".to_owned()), 2),
                (None, 1),
                (Some("US".to_owned()), 1)
            ]
        );
        assert_eq!(view.connected, ["US"]);
    }

    #[test]
    fn sessions_and_events_carry_the_countries_of_their_addresses() {
        let mut fixture = Fixture::new(|_| {});
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let place = |address: &str, code: &str, name: &str| Place {
            address: address.to_owned(),
            code: code.to_owned(),
            name: name.to_owned(),
        };
        let Response::Sessions { places, .. } = vpn_sessions(&mut fixture, &session) else {
            panic!("expected the session list");
        };
        assert_eq!(
            places,
            Ok(Located {
                database: "Test-Country".to_owned(),
                places: vec![place("203.0.113.20", "US", "United States")],
            }),
            "the session from 198.51.100.7 is in no country"
        );
        let what = What::SignInFailed {
            user: "mallory".to_owned(),
            from: Some("192.0.2.5".to_owned()),
        };
        fixture
            .service
            .events
            .add(Event { time: MOMENT, what }, None);
        let listed = fixture.service.handle(
            Request::ListEvents {
                session: session.clone(),
                after: None,
            },
            MOMENT,
        );
        let Response::Events { places, .. } = listed else {
            panic!("expected the events, got {listed:?}");
        };
        assert_eq!(places.unwrap().places, [place("192.0.2.5", "CN", "China")]);
        fixture.service.countries.database = Err("no database here".to_owned());
        let Response::Sessions { places, .. } = vpn_sessions(&mut fixture, &session) else {
            panic!("expected the session list");
        };
        assert_eq!(places, Err("no database here".to_owned()));
    }

    fn maxmind_key(license: &str) -> geoip::Key {
        geoip::Key {
            account: "123456".to_owned(),
            license: license.to_owned(),
        }
    }

    #[test]
    fn a_maxmind_key_is_kept_only_once_a_download_with_it_works() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let set = |fixture: &mut Fixture, license: &str| {
            fixture.service.handle(
                Request::SetMaxmindKey {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    account: "123456".to_owned(),
                    license: license.to_owned(),
                },
                MOMENT,
            )
        };
        assert_eq!(
            fixture.service.take_geoip_job().unwrap(),
            geoip::Job::Idle,
            "without a key nothing is downloaded"
        );
        assert!(matches!(
            set(&mut fixture, "short"),
            Response::Invalid { .. }
        ));
        assert_eq!(set(&mut fixture, "abc_DEF_123"), Response::Done);
        let busy = set(&mut fixture, "abc_DEF_456");
        assert!(
            matches!(&busy, Response::Invalid { message } if message.contains("under way")),
            "{busy:?}"
        );
        assert_eq!(
            fixture.service.take_geoip_job().unwrap(),
            geoip::Job::Download {
                key: maxmind_key("abc_DEF_123"),
                save: true
            }
        );
        let refused = "MaxMind refused the account ID and license key".to_owned();
        fixture
            .service
            .finish_geoip(MOMENT, Err(refused.clone()), None)
            .unwrap();
        let view = country_view(&mut fixture, &session);
        assert_eq!(view.maxmind_account, None, "a refused key is not kept");
        assert!(!view.maxmind_busy);
        assert_eq!(view.maxmind_last, Some((MOMENT, Err(refused))));
        assert!(fixture.audit().contains("the GeoLite2 download failed"));
        assert!(!fixture.audit().contains("abc_DEF_123"));

        assert_eq!(set(&mut fixture, "abc_DEF_123"), Response::Done);
        let geoip::Job::Download { key, save: true } = fixture.service.take_geoip_job().unwrap()
        else {
            panic!("expected a download that keeps the key");
        };
        geoip::save_key(&geoip::key_file(fixture.dir.path()), &key).unwrap();
        fixture
            .service
            .finish_geoip(
                MOMENT,
                Ok("downloaded MaxMind GeoLite2 Country".to_owned()),
                Some(Ok(countries::sample::named())),
            )
            .unwrap();
        let view = country_view(&mut fixture, &session);
        assert_eq!(view.maxmind_account.as_deref(), Some("123456"));
        assert_eq!(
            fixture.service.take_geoip_job().unwrap(),
            geoip::Job::Download {
                key: maxmind_key("abc_DEF_123"),
                save: false
            },
            "a key without a copy downloads one"
        );
        fixture
            .service
            .finish_geoip(MOMENT, Err("MaxMind cannot be reached".to_owned()), None)
            .unwrap();

        let removed = fixture.service.handle(
            Request::RemoveMaxmindKey {
                session: session.clone(),
                csrf: csrf.clone(),
            },
            MOMENT,
        );
        assert_eq!(removed, Response::Done);
        assert!(!geoip::key_file(fixture.dir.path()).exists());
        assert_eq!(
            fixture.service.take_geoip_job().unwrap(),
            geoip::Job::Reread
        );
    }

    #[test]
    fn the_environment_wins_over_the_panels_maxmind_key() {
        let mut fixture = Fixture::new(|_| {});
        fixture.service.countries.maxmind.environment = Some(maxmind_key("abc_DEF_123"));
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let refused = fixture.service.handle(
            Request::RemoveMaxmindKey {
                session: session.clone(),
                csrf,
            },
            MOMENT,
        );
        assert!(
            matches!(&refused, Response::Invalid { message } if message.contains("environment")),
            "{refused:?}"
        );
        let view = country_view(&mut fixture, &session);
        assert!(view.maxmind_from_env);
        assert_eq!(view.maxmind_account.as_deref(), Some("123456"));
    }

    fn audit_page(fixture: &mut Fixture, session: &str, before: Option<usize>) -> Response {
        fixture.service.handle(
            Request::ListAudit {
                session: session.to_owned(),
                before,
            },
            MOMENT,
        )
    }

    #[test]
    fn an_owner_reads_the_audit_log_newest_first() {
        let mut fixture = Fixture::new(|_| {});
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let Response::Audit { records, older } = audit_page(&mut fixture, &session, None) else {
            panic!("expected a page of the audit log");
        };
        assert_eq!(older, None);
        assert_eq!(records[0].actor, "alex");
        assert_eq!(records[0].action, "login");
        assert!(matches!(
            audit_page(&mut fixture, "no such session", None),
            Response::Denied
        ));
    }

    #[test]
    fn operators_and_viewers_cannot_read_the_audit_log() {
        for role in [Role::Operator, Role::Viewer] {
            let mut fixture = Fixture::new(|admin| admin.role = role);
            let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
            assert!(matches!(
                audit_page(&mut fixture, &session, None),
                Response::Invalid { .. }
            ));
            assert!(
                fixture
                    .audit()
                    .contains("only owners can read the audit log")
            );
        }
    }

    fn change_admin(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        change: AdminChange,
    ) -> Response {
        fixture.service.handle(
            Request::ChangeAdmin {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                change,
            },
            MOMENT,
        )
    }

    fn one_time(response: Response) -> String {
        match response {
            Response::AdminChanged {
                one_time_password: Some(OneTimePassword(password)),
            } => password,
            other => panic!("expected a one-time password, got {other:?}"),
        }
    }

    const CHANGED: Response = Response::AdminChanged {
        one_time_password: None,
    };

    fn change_settings(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        values: &[(&str, &str)],
    ) -> Response {
        fixture.service.handle(
            Request::SetServerSettings {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                values: values
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
            },
            MOMENT,
        )
    }

    fn listed_settings(fixture: &mut Fixture, session: &str) -> Vec<Setting> {
        match fixture.service.handle(
            Request::ServerSettings {
                session: session.to_owned(),
            },
            MOMENT,
        ) {
            Response::ServerSettings {
                settings: Some(settings),
            } => settings,
            other => panic!("expected the settings, got {other:?}"),
        }
    }

    #[test]
    fn every_admin_reads_the_certificates() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let Response::Certificates { certificates } = fixture
            .service
            .handle(Request::Certificates { session }, MOMENT)
        else {
            panic!("expected the certificates");
        };
        let roles: Vec<&str> = certificates
            .iter()
            .map(|certificate| certificate.role.as_str())
            .collect();
        assert_eq!(
            roles,
            ["VPN server", "Certificate authority", "Admin panel"]
        );
        assert_eq!(
            certificates[0]
                .facts
                .as_ref()
                .map(|facts| facts.pin.as_str()),
            Some(kit::SAMPLE_PIN)
        );
        assert!(certificates[2].facts.is_none());
        assert!(
            certificates[2]
                .problem
                .as_deref()
                .is_some_and(|problem| problem.starts_with("it cannot be read"))
        );
    }

    #[test]
    fn a_reloadable_setting_is_stored_and_applied_with_a_reload() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let rendered = fixture.dir.path().join("rendered.conf");
        let next = fs::read_to_string(&rendered)
            .unwrap()
            .replace("dns = 9.9.9.9", "dns = 10.0.0.53");
        fs::write(&rendered, next).unwrap();
        assert_eq!(
            change_settings(
                &mut fixture,
                &session,
                &csrf,
                &[("DNS_SERVERS", " 10.0.0.53 ")]
            ),
            Response::ServerSettingsSaved { reloaded: true }
        );
        let stored = fs::read_to_string(fixture.dir.path().join("settings.env")).unwrap();
        assert!(stored.contains("DNS_SERVERS=10.0.0.53\n"), "{stored}");
        let running = fs::read_to_string(fixture.dir.path().join("ocserv.conf")).unwrap();
        assert!(running.contains("dns = 10.0.0.53"), "{running}");
        let dns = listed_settings(&mut fixture, &session)
            .into_iter()
            .find(|setting| setting.name == "DNS_SERVERS")
            .unwrap();
        assert_eq!(
            (dns.source, dns.running.as_str()),
            (Source::Panel, "10.0.0.53")
        );
        assert!(
            fixture
                .audit()
                .contains("set DNS_SERVERS to 10.0.0.53; applied with a reload")
        );
    }

    #[test]
    fn a_start_setting_is_stored_and_waits_for_the_next_start() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        assert_eq!(
            change_settings(&mut fixture, &session, &csrf, &[("NAT", "false")]),
            Response::ServerSettingsSaved { reloaded: false }
        );
        let nat = listed_settings(&mut fixture, &session)
            .into_iter()
            .find(|setting| setting.name == "NAT")
            .unwrap();
        assert!(nat.pending(), "{nat:?}");
        assert!(
            fixture
                .audit()
                .contains("set NAT to false; applies at the next start")
        );
        assert_eq!(
            change_settings(&mut fixture, &session, &csrf, &[("NAT", "true")]),
            Response::ServerSettingsSaved { reloaded: false }
        );
        assert!(fixture.audit().contains("returned NAT to its default"));
    }

    #[test]
    fn settings_the_panel_does_not_own_or_cannot_check_are_refused() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        for (values, refusal) in [
            (
                &[("MAX_CLIENTS", "10")][..],
                "MAX_CLIENTS is set by the container's environment",
            ),
            (
                &[("IDLE_TIMEOUT", "60")][..],
                "IDLE_TIMEOUT is set by OCSERV_CONF_IDLE_TIMEOUT",
            ),
            (
                &[("DNS_SERVERS", "dns.example.com")][..],
                "is not an IP address",
            ),
            (
                &[("TUNNEL_MODE", "split-include")][..],
                "split-include needs at least one network",
            ),
            (
                &[("LISTEN_PORT", "1")][..],
                "not a setting this page changes",
            ),
        ] {
            let answer = change_settings(&mut fixture, &session, &csrf, values);
            assert!(
                matches!(&answer, Response::Invalid { message } if message.contains(refusal)),
                "{answer:?}"
            );
        }
        assert!(!fixture.dir.path().join("settings.env").exists());
        let mut viewer = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(viewer.login("alex", PASSWORD, LAN, MOMENT));
        assert!(matches!(
            change_settings(&mut viewer, &session, &csrf, &[("NAT", "false")]),
            Response::Invalid { .. }
        ));
        assert!(
            viewer
                .audit()
                .contains("only owners can change the server's settings")
        );
    }

    #[test]
    fn a_configuration_that_cannot_be_built_leaves_the_stored_values() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        fs::remove_file(fixture.dir.path().join("rendered.conf")).unwrap();
        let answer = change_settings(
            &mut fixture,
            &session,
            &csrf,
            &[("DNS_SERVERS", "10.0.0.53")],
        );
        assert!(
            matches!(&answer, Response::Invalid { message } if message.starts_with("nothing was saved")),
            "{answer:?}"
        );
        let stored = fs::read_to_string(fixture.dir.path().join("settings.env")).unwrap();
        assert!(!stored.contains("DNS_SERVERS"), "{stored}");
    }

    #[test]
    fn an_admin_sees_their_account_and_signs_out_everywhere_else() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (here, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let (elsewhere, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let account = |fixture: &mut Fixture, session: &str| {
            fixture.service.handle(
                Request::Account {
                    session: session.to_owned(),
                },
                MOMENT,
            )
        };
        let Response::AdminAccount {
            admin,
            other_sessions,
            passkeys,
            passkeys_unavailable,
            locations_on: false,
        } = account(&mut fixture, &here)
        else {
            panic!("expected the account");
        };
        assert_eq!((admin.name.as_str(), admin.role), ("alex", Role::Viewer));
        assert_eq!(other_sessions, 1);
        assert!(passkeys.is_empty());
        assert_eq!(passkeys_unavailable, None);
        assert_eq!(
            fixture.service.handle(
                Request::EndOtherSessions {
                    session: here.clone(),
                    csrf,
                },
                MOMENT
            ),
            Response::Done
        );
        assert_eq!(account(&mut fixture, &elsewhere), Response::Denied);
        assert!(matches!(
            account(&mut fixture, &here),
            Response::AdminAccount {
                other_sessions: 0,
                ..
            }
        ));
        assert!(
            fixture
                .audit()
                .contains("signed out everywhere else; ended 1 session")
        );
    }

    #[test]
    fn an_owner_adds_an_admin_who_must_replace_a_one_time_password() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "Sam".to_owned(),
            role: Role::Operator,
        };
        let password = one_time(change_admin(&mut fixture, &session, &csrf, add.clone()));
        let listed = match fixture.service.handle(
            Request::ListAdmins {
                session: session.clone(),
            },
            MOMENT,
        ) {
            Response::Admins { admins, .. } => admins,
            other => panic!("expected the admins, got {other:?}"),
        };
        let sam = listed.iter().find(|admin| admin.name == "sam").unwrap();
        assert_eq!(
            (sam.role, sam.must_change_password, sam.second_factor),
            (Role::Operator, true, false)
        );
        assert!(matches!(
            change_admin(&mut fixture, &session, &csrf, add),
            Response::Invalid { .. }
        ));
        assert!(matches!(
            fixture.login("sam", &password, VPN, MOMENT),
            Response::SignedIn {
                must_change_password: true,
                scope: Scope::Enrollment,
                ..
            }
        ));
        let audit = fixture.audit();
        assert!(
            audit.contains("added sam as an operator with a one-time password"),
            "{audit}"
        );
        assert!(!audit.contains(&password));
    }

    #[test]
    fn an_owner_cannot_change_or_remove_their_own_account() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        for change in [
            AdminChange::SetRole {
                name: "alex".to_owned(),
                role: Role::Viewer,
            },
            AdminChange::Remove {
                name: "ALEX".to_owned(),
            },
            AdminChange::ResetPassword {
                name: "alex".to_owned(),
            },
        ] {
            assert!(matches!(
                change_admin(&mut fixture, &session, &csrf, change),
                Response::Invalid { .. }
            ));
        }
        assert_eq!(fixture.stored().role, Role::Owner);
        assert!(
            fixture
                .audit()
                .contains("you cannot change your own account here")
        );
    }

    #[test]
    fn operators_and_viewers_cannot_manage_admins() {
        for role in [Role::Operator, Role::Viewer] {
            let mut fixture = Fixture::new(|admin| admin.role = role);
            let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
            assert!(matches!(
                fixture.service.handle(
                    Request::ListAdmins {
                        session: session.clone()
                    },
                    MOMENT
                ),
                Response::Invalid { .. }
            ));
            let add = AdminChange::Add {
                name: "mallory".to_owned(),
                role: Role::Owner,
            };
            assert!(matches!(
                change_admin(&mut fixture, &session, &csrf, add),
                Response::Invalid { .. }
            ));
            assert!(fixture.service.store.get("mallory").is_none());
            assert!(fixture.audit().contains("only owners can manage admins"));
        }
    }

    #[test]
    fn a_password_reset_ends_the_admins_sessions_and_old_password() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Viewer,
        };
        let first = one_time(change_admin(&mut fixture, &session, &csrf, add));
        let (sam, _csrf, _scope) = signed_in(fixture.login("sam", &first, LAN, MOMENT));
        let reset = AdminChange::ResetPassword {
            name: "sam".to_owned(),
        };
        let second = one_time(change_admin(&mut fixture, &session, &csrf, reset));
        assert_ne!(first, second);
        assert_eq!(
            fixture
                .service
                .handle(Request::Whoami { session: sam }, MOMENT),
            Response::Denied
        );
        assert_eq!(fixture.login("sam", &first, LAN, MOMENT), Response::Denied);
        signed_in(fixture.login("sam", &second, LAN, MOMENT));
        assert!(
            fixture
                .audit()
                .contains("gave sam a one-time password; ended 1 session")
        );
    }

    #[test]
    fn a_second_factor_reset_opens_its_setup_from_anywhere_once() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Operator,
        };
        one_time(change_admin(&mut fixture, &session, &csrf, add));
        let reset = AdminChange::ResetSecondFactor {
            name: "sam".to_owned(),
        };
        assert!(matches!(
            change_admin(&mut fixture, &session, &csrf, reset.clone()),
            Response::Invalid { .. }
        ));
        let sam = fixture.service.store.get_mut("sam").unwrap();
        sam.totp_secret = Some("JBSWY3DPEHPK3PXP".to_owned());
        sam.enrollment_open = false;
        assert_eq!(change_admin(&mut fixture, &session, &csrf, reset), CHANGED);
        let sam = fixture.service.store.get("sam").unwrap();
        assert!(sam.totp_secret.is_none() && sam.enrollment_open);
        assert!(
            fixture
                .audit()
                .contains("removed sam's authenticator app and opened its setup")
        );
    }

    #[test]
    fn an_owner_changes_roles_unlocks_and_removes_admins() {
        let mut fixture = Fixture::new(|_| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Viewer,
        };
        let password = one_time(change_admin(&mut fixture, &session, &csrf, add));
        let promote = AdminChange::SetRole {
            name: "sam".to_owned(),
            role: Role::Operator,
        };
        assert_eq!(
            change_admin(&mut fixture, &session, &csrf, promote.clone()),
            CHANGED
        );
        assert!(matches!(
            change_admin(&mut fixture, &session, &csrf, promote),
            Response::Invalid { .. }
        ));
        let unlock = AdminChange::Unlock {
            name: "sam".to_owned(),
        };
        assert!(matches!(
            change_admin(&mut fixture, &session, &csrf, unlock.clone()),
            Response::Invalid { .. }
        ));
        fixture.service.store.get_mut("sam").unwrap().locked_until = Some(MOMENT + 60);
        assert_eq!(change_admin(&mut fixture, &session, &csrf, unlock), CHANGED);
        let (sam, _csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        let remove = AdminChange::Remove {
            name: "sam".to_owned(),
        };
        assert_eq!(change_admin(&mut fixture, &session, &csrf, remove), CHANGED);
        assert_eq!(
            fixture
                .service
                .handle(Request::Whoami { session: sam }, MOMENT),
            Response::Denied
        );
        assert_eq!(
            fixture.login("sam", &password, LAN, MOMENT),
            Response::Denied
        );
        let saved = Store::open(&fixture.dir.path().join("admins.json")).unwrap();
        assert!(saved.get("sam").is_none());
        let audit = fixture.audit();
        assert!(
            audit.contains("changed sam's role from viewer to operator"),
            "{audit}"
        );
        assert!(audit.contains("unlocked sam"), "{audit}");
        assert!(
            audit.contains("removed sam, who was an operator; ended 1 session"),
            "{audit}"
        );
    }

    #[test]
    fn an_owner_blocks_keeps_and_lifts_networks_but_never_their_own_address() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let block = |network: &str, hours: Option<u64>| Request::Block {
            session: session.clone(),
            csrf: csrf.clone(),
            network: network.to_owned(),
            hours,
        };
        for (network, refusal) in [
            ("192.168.1.0/24", "your own address"),
            (DOCKER_HOST, "always admits"),
            ("127.0.0.1", "always admits"),
            ("not a network", "not an IP network"),
        ] {
            match fixture.service.handle(block(network, Some(24)), MOMENT) {
                Response::Invalid { message } => assert!(message.contains(refusal), "{message}"),
                other => panic!("{network} was not refused: {other:?}"),
            }
        }
        assert_eq!(
            fixture
                .service
                .handle(block("203.0.113.0/24", Some(24)), MOMENT),
            Response::Done
        );
        assert_eq!(fixture.dropped(), ["203.0.113.0/24"]);
        assert!(matches!(
            fixture.service.handle(block("203.0.113.20", None), MOMENT),
            Response::Invalid { ref message } if message.contains("overlaps")
        ));
        let Response::Bans { blocks, auto, .. } = bans(&mut fixture, &session) else {
            panic!("no Bans page");
        };
        assert_eq!(
            (blocks.len(), blocks[0].until, auto.bans),
            (1, Some(MOMENT + 86_400), 3)
        );
        let target = |network: &str| (session.clone(), csrf.clone(), network.to_owned());
        let (session_a, csrf_a, network_a) = target("203.0.113.0/24");
        let keep = Request::KeepBlock {
            session: session_a,
            csrf: csrf_a,
            network: network_a,
        };
        assert_eq!(fixture.service.handle(keep, MOMENT), Response::Done);
        let lift = || Request::Unblock {
            session: session.clone(),
            csrf: csrf.clone(),
            network: "203.0.113.0/24".to_owned(),
        };
        assert_eq!(fixture.service.handle(lift(), MOMENT), Response::Done);
        assert!(fixture.dropped().is_empty());
        assert!(matches!(
            fixture.service.handle(lift(), MOMENT),
            Response::Invalid { .. }
        ));
        let audit = fixture.audit();
        for detail in [
            "blocked 203.0.113.0/24 for 1 day; disconnected 1 VPN session from it",
            "the block of 203.0.113.0/24 stays until it is lifted",
            "lifted the block of 203.0.113.0/24",
        ] {
            assert!(audit.contains(detail), "{detail}: {audit}");
        }
        let mut viewer = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(viewer.login("alex", PASSWORD, LAN, MOMENT));
        let refused = Request::Block {
            session,
            csrf,
            network: "198.51.100.0/24".to_owned(),
            hours: None,
        };
        assert!(matches!(
            viewer.service.handle(refused, MOMENT),
            Response::Invalid { .. }
        ));
        assert!(viewer.dropped().is_empty());
    }

    #[test]
    fn three_bans_within_a_day_block_an_address_until_the_block_runs_out() {
        let mut fixture = Fixture::new(|_admin| {});
        let banned = |time| Event {
            time,
            what: What::Banned {
                address: "198.51.100.7".to_owned(),
                score: 80,
            },
        };
        for time in [MOMENT, MOMENT + 10, MOMENT + 20] {
            fixture
                .service
                .record_events(time, vec![banned(time)])
                .unwrap();
        }
        assert_eq!(fixture.dropped(), ["198.51.100.7/32"]);
        fixture.service.expire_blocks(MOMENT + 20 + 86_399).unwrap();
        assert_eq!(fixture.dropped().len(), 1);
        fixture.service.expire_blocks(MOMENT + 20 + 86_400).unwrap();
        assert!(fixture.dropped().is_empty());
        let audit = fixture.audit();
        for detail in [
            "blocked 198.51.100.7/32: banned 3 times within 1 day; disconnected 1 VPN session from it",
            "the block of 198.51.100.7/32 ran out",
        ] {
            assert!(audit.contains(detail), "{detail}: {audit}");
        }
    }

    fn unban(fixture: &mut Fixture, session: &str, csrf: &str, address: &str) -> Response {
        fixture.service.handle(
            Request::Unban {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                address: address.to_owned(),
            },
            MOMENT,
        )
    }

    #[test]
    fn an_owner_sees_the_bans_with_the_policy_and_lifts_one() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let Response::Bans { banned, policy, .. } = bans(&mut fixture, &session) else {
            panic!("expected the bans");
        };
        assert_eq!(banned.len(), 2);
        assert_eq!((policy.max_score, policy.ban_seconds), (60, 600));
        assert_eq!(policy.wrong_password_points, 10);
        assert_eq!(
            unban(&mut fixture, &session, &csrf, " 203.0.113.250 "),
            Response::Done
        );
        let Response::Bans { banned, points, .. } = bans(&mut fixture, &session) else {
            panic!("expected the bans");
        };
        assert!(!banned.iter().any(|ban| ban.address == "203.0.113.250"));
        assert!(
            points
                .iter()
                .any(|entry| entry.address == "203.0.113.250" && entry.score == 0)
        );
        let audit = fixture.audit();
        assert!(
            audit.contains("lifted the ban on 203.0.113.250 and cleared its points"),
            "{audit}"
        );
    }

    #[test]
    fn unbanning_needs_a_known_address_an_operator_and_the_csrf_token() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        for refused in ["not an address", "-h", "198.51.100.99"] {
            assert!(
                matches!(
                    unban(&mut fixture, &session, &csrf, refused),
                    Response::Invalid { .. }
                ),
                "{refused}"
            );
        }
        assert_eq!(
            unban(&mut fixture, &session, "wrong", "203.0.113.250"),
            Response::Denied
        );
        let mut viewer = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(viewer.login("alex", PASSWORD, LAN, MOMENT));
        assert!(matches!(bans(&mut viewer, &session), Response::Bans { .. }));
        assert!(matches!(
            unban(&mut viewer, &session, &csrf, "203.0.113.250"),
            Response::Invalid { .. }
        ));
        let Response::Bans { banned, .. } = bans(&mut viewer, &session) else {
            panic!("expected the bans");
        };
        assert_eq!(banned.len(), 2);
    }

    #[test]
    fn failed_sign_ins_are_explained_from_the_user_file_and_viewers_see_events() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let failed = |user: &str| Event {
            time: MOMENT,
            what: What::SignInFailed {
                user: user.to_owned(),
                from: Some("203.0.113.9".to_owned()),
            },
        };
        let banned = Event {
            time: MOMENT,
            what: What::Banned {
                address: "203.0.113.9".to_owned(),
                score: 80,
            },
        };
        fixture
            .service
            .record_events(
                MOMENT,
                vec![
                    failed("riley"),
                    failed("nobody"),
                    failed("alex"),
                    failed("sam"),
                    banned,
                ],
            )
            .unwrap();
        let listed = fixture.service.handle(
            Request::ListEvents {
                session: session.clone(),
                after: None,
            },
            MOMENT,
        );
        let Response::Events { events, hours, .. } = listed else {
            panic!("expected the events, got {listed:?}");
        };
        let reasons: Vec<Option<&str>> = events
            .iter()
            .map(|logged| logged.reason.as_deref())
            .collect();
        assert_eq!(
            reasons,
            [
                Some("the account is locked"),
                Some("there is no VPN user by that name"),
                Some("the password or the authenticator code was wrong"),
                Some("the password was wrong"),
                None,
            ]
        );
        assert_eq!(hours, 24);
        let later = fixture.service.handle(
            Request::ListEvents {
                session,
                after: Some(events[3].number),
            },
            MOMENT,
        );
        assert!(matches!(later, Response::Events { events, .. } if events.len() == 1));
        assert_eq!(
            fixture.service.handle(
                Request::ListEvents {
                    session: "not a session".to_owned(),
                    after: None,
                },
                MOMENT,
            ),
            Response::Denied
        );
    }

    fn set_settings(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        owner: Owner,
        name: &str,
        form: Option<OverridesForm>,
    ) -> Response {
        fixture.service.handle(
            Request::SetOverrides {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                owner,
                name: name.to_owned(),
                form,
            },
            MOMENT,
        )
    }

    fn settings_of(fixture: &mut Fixture, session: &str, owner: Owner, name: &str) -> Response {
        fixture.service.handle(
            Request::GetOverrides {
                session: session.to_owned(),
                owner,
                name: name.to_owned(),
            },
            MOMENT,
        )
    }

    #[test]
    fn published_networks_reach_the_firewall_and_lose_egress_with_their_user() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let branch = OverridesForm {
            extra: [("iroute".to_owned(), "10.10.0.0/24".to_owned())].into(),
            ..OverridesForm::default()
        };
        assert_eq!(
            set_settings(
                &mut fixture,
                &session,
                &csrf,
                Owner::User,
                "sam",
                Some(branch)
            ),
            Response::Done
        );
        let net = |text: &str| Network::parse(text).unwrap();
        let plan = fixture.site_plan().unwrap();
        assert_eq!(plan.closed, [net("10.10.0.0/24")]);
        assert!(plan.open.is_empty());
        assert_eq!(plan.clients, [net("192.168.255.0/24")]);
        assert!(plan.checked);
        assert!(fixture.service.sites.set_egress("sam", true).unwrap());
        let remove = UserChange::Remove {
            name: "sam".to_owned(),
        };
        assert_eq!(
            change_user(&mut fixture, &session, &csrf, remove),
            Response::Done
        );
        assert!(!fixture.service.sites.egress("sam"));
        assert_eq!(fixture.site_plan().unwrap().closed, [net("10.10.0.0/24")]);
        let audit = fixture.audit();
        assert!(
            audit.contains("and kept their site's networks inside the VPN"),
            "{audit}"
        );
    }

    fn add_site_rule(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        from: End,
        to: End,
    ) -> Response {
        fixture.service.handle(
            Request::AddSiteRule {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                from,
                to,
            },
            MOMENT,
        )
    }

    fn sites_view(fixture: &mut Fixture, session: &str) -> SitesView {
        match fixture.service.handle(
            Request::SiteRules {
                session: session.to_owned(),
            },
            MOMENT,
        ) {
            Response::SiteRules { view } => *view,
            other => panic!("expected the Sites page, got {other:?}"),
        }
    }

    #[test]
    fn site_rules_are_added_loaded_removed_and_audited() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let net = |text: &str| Network::parse(text).unwrap();
        let staff = || End::Group("staff".to_owned());
        let branch = || End::Network(net("10.10.0.0/24"));
        assert_eq!(
            add_site_rule(&mut fixture, &session, &csrf, staff(), branch()),
            Response::Done
        );
        let plan = fixture.site_plan().unwrap();
        assert_eq!(plan.rules, [(staff(), branch())]);
        assert_eq!(
            plan.members["staff"]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.168.255.3"]
        );
        for (from, to) in [
            (End::Group("nobody".to_owned()), branch()),
            (staff(), branch()),
            (staff(), End::Clients),
        ] {
            let answer = add_site_rule(&mut fixture, &session, &csrf, from, to);
            assert!(matches!(answer, Response::Invalid { .. }), "{answer:?}");
        }
        let view = sites_view(&mut fixture, &session);
        assert_eq!(view.rules.len(), 1);
        assert!(view.groups.contains(&"staff".to_owned()));
        assert!(view.checked && !view.iptables && !view.client_to_client && !view.split);
        let remove = |id: u64| Request::RemoveSiteRule {
            session: session.clone(),
            csrf: csrf.clone(),
            id,
        };
        let id = view.rules[0].id;
        assert_eq!(fixture.service.handle(remove(id), MOMENT), Response::Done);
        assert!(fixture.site_plan().unwrap().rules.is_empty());
        assert!(matches!(
            fixture.service.handle(remove(id), MOMENT),
            Response::Invalid { .. }
        ));
        let egress = |user: &str, on: bool| Request::SetSiteEgress {
            session: session.clone(),
            csrf: csrf.clone(),
            user: user.to_owned(),
            on,
        };
        assert_eq!(
            fixture.service.handle(egress("sam", true), MOMENT),
            Response::Done
        );
        assert!(fixture.service.sites.egress("sam"));
        assert!(matches!(
            fixture.service.handle(egress("nobody", true), MOMENT),
            Response::Invalid { .. }
        ));
        let audit = fixture.audit();
        for line in [
            "let group staff reach 10.10.0.0/24",
            "stopped letting group staff reach 10.10.0.0/24",
            "let the networks sam publishes reach beyond the VPN",
        ] {
            assert!(audit.contains(line), "{line}: {audit}");
        }
    }

    #[test]
    fn iptables_takes_no_group_rule_and_a_viewer_changes_nothing() {
        let mut fixture = Fixture::new(|_admin| {});
        fixture.service.firewall = Box::new(crate::firewall::Fake {
            iptables: true,
            ..crate::firewall::Fake::default()
        });
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let net = |text: &str| Network::parse(text).unwrap();
        let answer = add_site_rule(
            &mut fixture,
            &session,
            &csrf,
            End::Group("staff".to_owned()),
            End::Network(net("10.10.0.0/24")),
        );
        assert!(matches!(answer, Response::Invalid { .. }), "{answer:?}");
        assert_eq!(
            add_site_rule(
                &mut fixture,
                &session,
                &csrf,
                End::Clients,
                End::Network(net("10.10.0.0/24"))
            ),
            Response::Done
        );
        assert!(sites_view(&mut fixture, &session).iptables);
        let mut viewing = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(viewing.login("alex", PASSWORD, LAN, MOMENT));
        assert!(sites_view(&mut viewing, &session).rules.is_empty());
        let answer = add_site_rule(
            &mut viewing,
            &session,
            &csrf,
            End::Clients,
            End::Network(net("10.10.0.0/24")),
        );
        assert!(matches!(answer, Response::Invalid { .. }), "{answer:?}");
        assert!(viewing.site_plan().is_none());
    }

    #[test]
    fn group_and_user_settings_are_written_inherited_and_audited() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let staff = OverridesForm {
            routes: "10.20.0.0/16".to_owned(),
            download: "50".to_owned(),
            ..OverridesForm::default()
        };
        assert_eq!(
            set_settings(
                &mut fixture,
                &session,
                &csrf,
                Owner::Group,
                "staff",
                Some(staff)
            ),
            Response::Done
        );
        let Response::Overrides {
            own,
            group,
            group_settings,
            server,
            readable,
        } = settings_of(&mut fixture, &session, Owner::User, "sam")
        else {
            panic!("expected sam's settings");
        };
        assert_eq!(
            (own, group.as_deref(), readable),
            (None, Some("staff"), true)
        );
        let Some(staff) = group_settings else {
            panic!("expected the settings of staff");
        };
        let inherited = staff.over(&server);
        assert_eq!(inherited.routes, ["10.20.0.0/16"]);
        assert_eq!(inherited.dns, ["9.9.9.9"]);
        assert_eq!(inherited.download, Some(6_250_000));
        let fixed = |address: &str| OverridesForm {
            fixed_ipv4: address.to_owned(),
            ..OverridesForm::default()
        };
        assert_eq!(
            set_settings(
                &mut fixture,
                &session,
                &csrf,
                Owner::User,
                "sam",
                Some(fixed("192.168.255.50"))
            ),
            Response::Done
        );
        for (name, form) in [
            ("alex", Some(fixed("192.168.255.50"))),
            ("alex", Some(fixed("10.0.0.5"))),
            ("nobody", Some(fixed("192.168.255.51"))),
            ("..", Some(OverridesForm::default())),
            ("riley", None),
        ] {
            let owner = if name == ".." {
                Owner::Group
            } else {
                Owner::User
            };
            assert!(
                matches!(
                    set_settings(&mut fixture, &session, &csrf, owner, name, form),
                    Response::Invalid { .. }
                ),
                "{name}"
            );
        }
        let Response::Groups {
            groups,
            server,
            readable,
        } = fixture.service.handle(
            Request::ListGroups {
                session: session.clone(),
            },
            MOMENT,
        )
        else {
            panic!("expected the groups");
        };
        assert!(readable);
        assert_eq!(server.routes, ["default"]);
        let names: Vec<(&str, usize, bool)> = groups
            .iter()
            .map(|group| {
                (
                    group.name.as_str(),
                    group.members.len(),
                    group.settings.is_some(),
                )
            })
            .collect();
        assert_eq!(names, [("contractors", 1, false), ("staff", 1, true)]);
        assert_eq!(
            set_settings(&mut fixture, &session, &csrf, Owner::User, "sam", None),
            Response::Done
        );
        let audit = fixture.audit();
        assert!(
            audit.contains(
                "set the settings of group staff: routes 10.20.0.0/16, download limit 50 Mbps"
            ),
            "{audit}"
        );
        assert!(
            audit.contains("set the settings of user sam: fixed address 192.168.255.50"),
            "{audit}"
        );
        assert!(
            audit.contains("removed the settings of user sam"),
            "{audit}"
        );
    }

    #[test]
    fn viewers_read_settings_but_cannot_change_them() {
        let mut fixture = Fixture::new(|admin| admin.role = Role::Viewer);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        assert!(matches!(
            settings_of(&mut fixture, &session, Owner::Group, "staff"),
            Response::Overrides { own: None, .. }
        ));
        assert!(matches!(
            set_settings(
                &mut fixture,
                &session,
                &csrf,
                Owner::Group,
                "staff",
                Some(OverridesForm::default())
            ),
            Response::Invalid { .. }
        ));
        assert!(matches!(
            settings_of(&mut fixture, &session, Owner::Group, "staff"),
            Response::Overrides { own: None, .. }
        ));
    }

    fn waiting(fixture: &mut Fixture, session: &str, now: u64) -> Response {
        fixture.service.handle(
            Request::TotpPending {
                session: session.to_owned(),
            },
            now,
        )
    }

    #[test]
    fn a_waiting_totp_secret_is_shown_again_until_its_window_ends() {
        let mut fixture = Fixture::new(|admin| admin.enrollment_open = true);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        assert_eq!(
            waiting(&mut fixture, &session, MOMENT),
            Response::NoTotpPending
        );
        let begun = fixture.service.handle(
            Request::TotpBegin {
                session: session.clone(),
                csrf,
            },
            MOMENT,
        );
        assert!(matches!(begun, Response::TotpSecret { .. }), "{begun:?}");
        assert_eq!(waiting(&mut fixture, &session, MOMENT + 299), begun);
        assert_eq!(
            waiting(&mut fixture, &session, MOMENT + 300),
            Response::NoTotpPending
        );
        assert_eq!(
            waiting(&mut fixture, "no such session", MOMENT),
            Response::Denied
        );
    }

    #[test]
    fn a_confirmed_totp_secret_is_no_longer_waiting() {
        let mut fixture = Fixture::new(|admin| admin.enrollment_open = true);
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        let begun = fixture.service.handle(
            Request::TotpBegin {
                session: session.clone(),
                csrf: csrf.clone(),
            },
            MOMENT,
        );
        let Response::TotpSecret { secret, .. } = begun else {
            panic!("expected a TOTP secret, got {begun:?}");
        };
        let code = format!("{:06}", totp::code(&secret, MOMENT / totp::STEP).unwrap());
        let confirmed = fixture.service.handle(
            Request::TotpConfirm {
                session: session.clone(),
                csrf,
                code,
            },
            MOMENT,
        );
        assert_eq!(confirmed, Response::Done);
        assert_eq!(
            waiting(&mut fixture, &session, MOMENT + 1),
            Response::NoTotpPending
        );
    }

    /// The origin the fixture's relying party accepts passkeys from.
    const ORIGIN: &str = "https://vpn.example.com:8443";

    /// Adds a passkey named `name` for the session's admin through
    /// `browser`, as the Account page's script does.
    fn add_passkey(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        browser: &mut Browser,
        name: &str,
        now: u64,
    ) -> Response {
        let begun = fixture.service.handle(
            Request::PasskeyBegin {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                name: name.to_owned(),
            },
            now,
        );
        let Response::PasskeyOptions { options } = begun else {
            return begun;
        };
        fixture.service.handle(
            Request::PasskeyFinish {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                credential: browser.register(&options),
            },
            now,
        )
    }

    /// Completes the sign-in waiting as `pending` with `browser`'s passkey,
    /// as the second-factor page's script does.
    fn sign_with_passkey(
        fixture: &mut Fixture,
        pending: &str,
        browser: &mut Browser,
        now: u64,
    ) -> Response {
        let begun = fixture.service.handle(
            Request::PasskeySignInBegin {
                pending: pending.to_owned(),
            },
            now,
        );
        let Response::PasskeyOptions { options } = begun else {
            return begun;
        };
        fixture.service.handle(
            Request::PasskeySignIn {
                pending: pending.to_owned(),
                credential: browser.sign(&options),
            },
            now,
        )
    }

    /// A passkey record whose credential is never read.
    fn unread_passkey(name: &str) -> StoredPasskey {
        StoredPasskey {
            name: name.to_owned(),
            created: 1,
            last_used: None,
            credential: "{}".to_owned(),
        }
    }

    #[test]
    fn a_first_passkey_finishes_the_setup_and_then_signs_in() {
        let mut fixture = Fixture::new(|admin| admin.enrollment_open = true);
        let (session, csrf, scope) = signed_in(fixture.login("alex", PASSWORD, VPN, MOMENT));
        assert!(matches!(scope, Scope::Enrollment));
        let mut laptop = Browser::at(ORIGIN);
        assert_eq!(
            add_passkey(
                &mut fixture,
                &session,
                &csrf,
                &mut laptop,
                " Work laptop ",
                MOMENT
            ),
            Response::Done
        );
        let stored = fixture.stored();
        assert_eq!(stored.passkeys.len(), 1);
        assert_eq!(stored.passkeys[0].name, "Work laptop");
        assert!(stored.passkey_user.is_some() && !stored.enrollment_open);
        assert!(matches!(
            fixture.service.handle(
                Request::Whoami {
                    session: session.clone()
                },
                MOMENT
            ),
            Response::Admin {
                scope: Scope::Full,
                passkeys: true,
                ..
            }
        ));
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 60));
        assert_eq!(
            fixture.service.handle(
                Request::SecondFactorOptions {
                    pending: pending.clone()
                },
                MOMENT + 60
            ),
            Response::SecondFactorOptions {
                code: false,
                passkey: true
            }
        );
        let (_session, _csrf, scope) = signed_in(sign_with_passkey(
            &mut fixture,
            &pending,
            &mut laptop,
            MOMENT + 60,
        ));
        assert!(matches!(scope, Scope::Full));
        assert_eq!(fixture.stored().passkeys[0].last_used, Some(MOMENT + 60));
        assert_eq!(
            sign_with_passkey(&mut fixture, &pending, &mut laptop, MOMENT + 61),
            Response::Denied
        );
        let audit = fixture.audit();
        assert!(audit.contains("added the passkey 'Work laptop'; the session has full access"));
        assert!(audit.contains("password and passkey 'Work laptop'"));
    }

    #[test]
    fn a_refused_passkey_ends_the_sign_in_and_counts_toward_the_lockout() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let mut laptop = Browser::at(ORIGIN);
        assert_eq!(
            add_passkey(
                &mut fixture,
                &session,
                &csrf,
                &mut laptop,
                "Work laptop",
                MOMENT
            ),
            Response::Done
        );
        let begin = |fixture: &mut Fixture, pending: &str| match fixture.service.handle(
            Request::PasskeySignInBegin {
                pending: pending.to_owned(),
            },
            MOMENT + 10,
        ) {
            Response::PasskeyOptions { options } => options,
            other => panic!("expected the passkey prompt's options, got {other:?}"),
        };
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 10));
        let earlier = begin(&mut fixture, &pending);
        begin(&mut fixture, &pending);
        let stale = fixture.service.handle(
            Request::PasskeySignIn {
                pending: pending.clone(),
                credential: laptop.sign(&earlier),
            },
            MOMENT + 10,
        );
        assert_eq!(
            stale,
            Response::Denied,
            "an answer to an earlier prompt signed in"
        );
        assert_eq!(fixture.stored().failed_logins, 1);
        assert_eq!(
            fixture
                .service
                .handle(Request::PasskeySignInBegin { pending }, MOMENT + 10),
            Response::Denied
        );
        let mut answers = Vec::new();
        for _attempt in 0..2 {
            let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT + 20));
            begin(&mut fixture, &pending);
            answers.push(fixture.service.handle(
                Request::PasskeySignIn {
                    pending,
                    credential: "{}".to_owned(),
                },
                MOMENT + 20,
            ));
        }
        assert_eq!(answers[0], Response::Denied);
        assert!(matches!(answers[1], Response::Locked { .. }));
        assert!(fixture.audit().contains("passkey refused: "));
    }

    #[test]
    fn adding_a_passkey_needs_a_free_name_room_and_a_recent_sign_in() {
        let mut fixture =
            Fixture::new(|admin| admin.totp_secret = Some("JBSWY3DPEHPK3PXP".to_owned()));
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let begin = |fixture: &mut Fixture, name: &str, now: u64| {
            fixture.service.handle(
                Request::PasskeyBegin {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    name: name.to_owned(),
                },
                now,
            )
        };
        let refusal = |response: Response| match response {
            Response::Invalid { message } => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        for bad in [
            "",
            "   ",
            &"k".repeat(passkey::MAX_NAME_CHARS + 1),
            "two\nlines",
        ] {
            refusal(begin(&mut fixture, bad, MOMENT));
        }
        assert!(
            refusal(begin(&mut fixture, "Work laptop", MOMENT + 600)).contains("sign in again")
        );
        let mut yubikey = Browser::at(ORIGIN);
        assert_eq!(
            add_passkey(
                &mut fixture,
                &session,
                &csrf,
                &mut yubikey,
                "YubiKey",
                MOMENT
            ),
            Response::Done
        );
        assert!(refusal(begin(&mut fixture, "yubikey", MOMENT)).contains("already have"));
        for index in 1..passkey::MAX_PASSKEYS {
            let mut key = Browser::at(ORIGIN);
            let name = format!("Key {index}");
            assert_eq!(
                add_passkey(&mut fixture, &session, &csrf, &mut key, &name, MOMENT),
                Response::Done
            );
        }
        assert!(refusal(begin(&mut fixture, "One more", MOMENT)).contains("at most"));
        assert_eq!(fixture.stored().passkeys.len(), passkey::MAX_PASSKEYS);
    }

    #[test]
    fn the_last_second_factor_stays_and_removing_one_needs_a_recent_sign_in() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let remove = |fixture: &mut Fixture, name: &str, now: u64| match fixture.service.handle(
            Request::RemovePasskey {
                session: session.clone(),
                csrf: csrf.clone(),
                name: name.to_owned(),
            },
            now,
        ) {
            Response::Invalid { message } => message,
            other => format!("{other:?}"),
        };
        let mut laptop = Browser::at(ORIGIN);
        assert_eq!(
            add_passkey(
                &mut fixture,
                &session,
                &csrf,
                &mut laptop,
                "Work laptop",
                MOMENT
            ),
            Response::Done
        );
        assert!(remove(&mut fixture, "Work laptop", MOMENT).contains("last passkey"));
        let mut yubikey = Browser::at(ORIGIN);
        assert_eq!(
            add_passkey(
                &mut fixture,
                &session,
                &csrf,
                &mut yubikey,
                "YubiKey",
                MOMENT
            ),
            Response::Done
        );
        assert!(remove(&mut fixture, "Phone", MOMENT).contains("no passkey named"));
        assert!(remove(&mut fixture, "Work laptop", MOMENT + 600).contains("sign in again"));
        assert_eq!(remove(&mut fixture, "Work laptop", MOMENT), "Done");
        let names: Vec<String> = fixture
            .stored()
            .passkeys
            .into_iter()
            .map(|key| key.name)
            .collect();
        assert_eq!(names, ["YubiKey"]);
        assert!(
            fixture
                .audit()
                .contains("removed the passkey 'Work laptop'")
        );
    }

    #[test]
    fn an_owners_reset_removes_the_app_and_every_passkey() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Viewer,
        };
        one_time(change_admin(&mut fixture, &session, &csrf, add));
        let sam = fixture.service.store.get_mut("sam").unwrap();
        sam.totp_secret = Some("JBSWY3DPEHPK3PXP".to_owned());
        sam.enrollment_open = false;
        sam.passkey_user = Some(Uuid::new_v4().to_string());
        sam.passkeys = vec![unread_passkey("Laptop"), unread_passkey("YubiKey")];
        let reset = AdminChange::ResetSecondFactor {
            name: "sam".to_owned(),
        };
        assert_eq!(change_admin(&mut fixture, &session, &csrf, reset), CHANGED);
        let sam = fixture.service.store.get("sam").unwrap();
        assert!(sam.totp_secret.is_none() && sam.passkeys.is_empty());
        assert!(sam.passkey_user.is_none() && sam.enrollment_open);
        assert!(
            fixture
                .audit()
                .contains("removed sam's authenticator app and 2 passkeys and opened its setup")
        );
    }

    #[test]
    fn at_an_ip_address_passkeys_are_refused_with_the_reason() {
        let mut fixture = Fixture::new(|admin| admin.passkeys.push(unread_passkey("Laptop")));
        fixture.service.passkeys = Err(Unavailable::IpAddress);
        assert!(matches!(
            fixture.login("alex", PASSWORD, VPN, MOMENT),
            Response::SecondFactorUnavailable { reason } if reason.contains("IP address")
        ));
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let begun = fixture.service.handle(
            Request::PasskeyBegin {
                session: session.clone(),
                csrf,
                name: "Phone".to_owned(),
            },
            MOMENT,
        );
        assert!(matches!(
            begun,
            Response::Invalid { message } if message.contains("cannot be used here")
        ));
        assert!(matches!(
            fixture.service.handle(Request::Account { session }, MOMENT),
            Response::AdminAccount {
                passkeys_unavailable: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn a_code_for_an_account_without_an_app_counts_as_a_mistake() {
        let mut fixture = Fixture::new(|admin| admin.passkeys.push(unread_passkey("Laptop")));
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT));
        assert_eq!(
            second(&mut fixture, &pending, "123456", MOMENT),
            Response::Denied
        );
        assert_eq!(fixture.stored().failed_logins, 1);
    }

    /// Where the test atlas places addresses: Denver and Moscow.
    const DENVER: &str = "203.0.113.9";
    const MOSCOW: &str = "192.0.2.9";

    /// Denver at 203.0.113.0/24 and Moscow at 192.0.2.0/24, each with its
    /// network.
    fn test_atlas() -> location::Atlas {
        use crate::countries::sample::{database_of, double, map, string, uint32};
        let city = |country: &str, lat: f64, lon: f64| {
            map(&[
                ("country", map(&[("iso_code", string(country))])),
                (
                    "location",
                    map(&[("latitude", double(lat)), ("longitude", double(lon))]),
                ),
            ])
        };
        let network = |number: u32| map(&[("autonomous_system_number", uint32(number))]);
        let cities = database_of(
            "Test-City",
            &[
                ("203.0.113.0/24", city("US", 39.74, -104.99)),
                ("192.0.2.0/24", city("RU", 55.76, 37.62)),
            ],
        );
        let networks = database_of(
            "Test-ASN",
            &[
                ("203.0.113.0/24", network(7922)),
                ("192.0.2.0/24", network(8359)),
            ],
        );
        location::Atlas::from_bytes(cities, Some(networks)).unwrap()
    }

    /// Turns the location checks on, as an owner does on the panel.
    fn locations_on(fixture: &Fixture) {
        location::Stored {
            on: true,
            refresh_hours: 6,
        }
        .save(&fixture.service.locations.stored)
        .unwrap();
    }

    #[test]
    fn an_implausible_admin_sign_in_is_refused_once_learned_and_flagged_before() {
        let secret = "JBSWY3DPEHPK3PXP";
        let mut fixture = Fixture::new(|admin| admin.totp_secret = Some(secret.to_owned()));
        locations_on(&fixture);
        let pending = pending_token(fixture.login("alex", PASSWORD, MOSCOW, MOMENT));
        let code = format!("{:06}", totp::code(secret, MOMENT / totp::STEP).unwrap());
        signed_in(second(&mut fixture, &pending, &code, MOMENT));
        let learned = fixture
            .service
            .locations
            .learning
            .history(AccountKind::Admin, "alex")
            .unwrap();
        assert_eq!(learned.sign_ins, 1);
        let denver = location::Place {
            lat: 39.74,
            lon: -104.99,
            country: Some("US".to_owned()),
            asn: Some(7922),
        };
        let history = fixture
            .service
            .locations
            .learning
            .history_mut(AccountKind::Admin, "alex");
        *history = location::History::default();
        for day in 0..40 {
            history.learn(&Sighting {
                time: MOMENT + day * 86_400,
                place: Some(denver.clone()),
                devices: Vec::new(),
            });
        }
        let now = MOMENT + 39 * 86_400 + 3600;
        assert_eq!(
            fixture.login("alex", PASSWORD, MOSCOW, now),
            Response::LocationRefused
        );
        assert!(
            fixture
                .audit()
                .contains("Refused alex's sign-in to the panel from 192.0.2.9")
        );
        assert!(matches!(
            fixture.login("alex", PASSWORD, DENVER, now + 60),
            Response::SecondFactorRequired { .. }
        ));
        fixture
            .service
            .locations
            .learning
            .history_mut(AccountKind::Admin, "alex")
            .vacation_until = Some(now + 86_400);
        assert!(matches!(
            fixture.login("alex", PASSWORD, MOSCOW, now + 120),
            Response::SecondFactorRequired { .. }
        ));
        assert!(fixture.audit().contains("which is unusual"));
    }

    #[test]
    fn only_an_owner_turns_location_checks_on_and_the_environment_wins() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let set = |fixture: &mut Fixture, on: bool, hours: &str| {
            fixture.service.handle(
                Request::SetLocationChecks {
                    session: session.clone(),
                    csrf: csrf.clone(),
                    on,
                    refresh_hours: hours.to_owned(),
                },
                MOMENT,
            )
        };
        assert!(matches!(
            set(&mut fixture, true, "0"),
            Response::Invalid { .. }
        ));
        assert_eq!(set(&mut fixture, true, "12"), Response::Done);
        assert!(fixture.service.location_checks_on().unwrap());
        assert_eq!(
            fixture
                .service
                .location_plan()
                .unwrap()
                .map(|(_key, wait)| wait),
            Some(12 * 3600)
        );
        assert_eq!(set(&mut fixture, false, "12"), Response::Done);
        assert!(fixture.service.locations.atlas.is_none());
        assert_eq!(fixture.service.location_plan().unwrap(), None);
        fixture.service.locations.environment.on = Some(true);
        assert!(matches!(
            set(&mut fixture, false, "12"),
            Response::Invalid { message } if message.contains("LOCATION_CHECKS")
        ));
        assert!(
            fixture.audit().contains(
                "turned the location checks on; the databases are checked every 12 hours"
            )
        );
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Operator,
        };
        let password = one_time(change_admin(&mut fixture, &session, &csrf, add));
        let (sam, sam_csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        let refused = fixture.service.handle(
            Request::SetLocationChecks {
                session: sam,
                csrf: sam_csrf,
                on: true,
                refresh_hours: "6".to_owned(),
            },
            MOMENT,
        );
        assert!(
            matches!(refused, Response::Invalid { message } if message.contains("only owners"))
        );
    }

    /// alex's VPN sign-in from `from` in session 300, with the client alex
    /// uses.
    fn vpn_sign_in(from: &str) -> VpnSignIn {
        VpnSignIn {
            user: "alex".to_owned(),
            from: from.to_owned(),
            session: Some(300),
            devices: vec!["Open AnyConnect VPN Agent v9.12".to_owned()],
        }
    }

    /// Checks `sign_in` at `now` and returns the verdict delivered.
    fn check_vpn(fixture: &mut Fixture, sign_in: &VpnSignIn, now: u64) -> LocationVerdict {
        let mut delivered = None;
        let checked = fixture
            .service
            .check_vpn_sign_in(sign_in, now, &mut |verdict| {
                delivered = Some(verdict.clone());
                Ok(())
            });
        assert!(
            matches!(checked, VpnCheck::Answered { unsaved: None }),
            "{checked:?}"
        );
        delivered.unwrap()
    }

    /// What the location checks put on the Live events page, oldest first.
    fn location_events(fixture: &Fixture) -> Vec<What> {
        fixture
            .service
            .events
            .after(None)
            .into_iter()
            .map(|logged| logged.event.what)
            .filter(|what| {
                matches!(
                    what,
                    What::LocationRefused { .. }
                        | What::LocationFlagged { .. }
                        | What::LocationUnchecked { .. }
                )
            })
            .collect()
    }

    /// Gives alex's VPN account 40 days of sign-ins from Denver with its
    /// usual client.
    fn learn_denver(fixture: &mut Fixture) {
        let history = fixture
            .service
            .locations
            .learning
            .history_mut(AccountKind::Vpn, "alex");
        for day in 0..40 {
            history.learn(&Sighting {
                time: MOMENT + day * 86_400,
                place: Some(location::Place {
                    lat: 39.74,
                    lon: -104.99,
                    country: Some("US".to_owned()),
                    asn: Some(7922),
                }),
                devices: vec!["Open AnyConnect VPN Agent v9.12".to_owned()],
            });
        }
    }

    fn vpn_history(fixture: &Fixture) -> location::History {
        fixture
            .service
            .locations
            .learning
            .history(AccountKind::Vpn, "alex")
            .unwrap()
            .clone()
    }

    #[test]
    fn an_implausible_vpn_sign_in_is_refused_once_learned_and_flagged_on_vacation() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        choose(&mut fixture, &session, &csrf, &[Topic::Locations]);
        add_channel(&mut fixture, &session, &csrf, hook(1));
        locations_on(&fixture);
        learn_denver(&mut fixture);
        let now = MOMENT + 39 * 86_400 + 3600;
        assert_eq!(
            check_vpn(&mut fixture, &vpn_sign_in(DENVER), now),
            LocationVerdict::Allow
        );
        let refused = check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), now + 60);
        assert!(
            matches!(&refused, LocationVerdict::Refuse { score: 100, reasons }
                if reasons.iter().any(|reason| reason.starts_with("a session is open"))),
            "{refused:?}"
        );
        let messages = sent(&mut fixture, now + 60);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            messages[0].contains("Refused alex's VPN sign-in from 192.0.2.9"),
            "{messages:?}"
        );
        assert_eq!(vpn_history(&fixture).sign_ins, 41);
        assert!(!vpn_history(&fixture).countries.contains_key("RU"));
        fixture
            .service
            .locations
            .learning
            .history_mut(AccountKind::Vpn, "alex")
            .vacation_until = Some(now + 86_400);
        assert!(matches!(
            check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), now + 120),
            LocationVerdict::Flag { score: 100, .. }
        ));
        assert_eq!(vpn_history(&fixture).sign_ins, 42);
        let events = location_events(&fixture);
        assert!(
            matches!(&events[..], [
                What::LocationRefused { user, from, score: 100, .. },
                What::LocationFlagged { .. },
            ] if user == "alex" && from == MOSCOW),
            "{events:?}"
        );
    }

    #[test]
    fn a_vpn_check_answered_too_late_records_and_learns_nothing() {
        let mut fixture = Fixture::new(|_admin| {});
        locations_on(&fixture);
        learn_denver(&mut fixture);
        let now = MOMENT + 39 * 86_400 + 3600;
        for from in [MOSCOW, DENVER] {
            let checked =
                fixture
                    .service
                    .check_vpn_sign_in(&vpn_sign_in(from), now, &mut |_verdict| {
                        Err("a message could not be written: Broken pipe (os error 32)".to_owned())
                    });
            assert!(
                matches!(&checked, VpnCheck::Undelivered { problem } if problem.contains("Broken pipe")),
                "{checked:?}"
            );
        }
        assert!(location_events(&fixture).is_empty());
        assert_eq!(vpn_history(&fixture).sign_ins, 40);
    }

    #[test]
    fn a_vpn_check_that_cannot_run_lets_the_client_in_and_says_so() {
        let mut fixture = Fixture::new(|_admin| {});
        locations_on(&fixture);
        let verdict = check_vpn(&mut fixture, &vpn_sign_in("not an address"), MOMENT);
        assert!(
            matches!(&verdict, LocationVerdict::Unchecked { problem } if problem.contains("is not an IP address")),
            "{verdict:?}"
        );
        let unanswered = What::LocationUnchecked {
            user: "sam".to_owned(),
            from: Some("198.51.100.7".to_owned()),
            problem: "the admin panel's helper gave no answer within 5 seconds".to_owned(),
        };
        fixture
            .service
            .record_events(
                MOMENT + 5,
                vec![Event {
                    time: MOMENT + 5,
                    what: unanswered,
                }],
            )
            .unwrap();
        let events = location_events(&fixture);
        assert!(
            matches!(&events[..], [
                What::LocationUnchecked { user: first, .. },
                What::LocationUnchecked { user: second, .. },
            ] if first == "alex" && second == "sam"),
            "{events:?}"
        );
    }

    #[test]
    fn an_admin_allows_the_place_of_a_refused_vpn_sign_in() {
        let mut fixture = Fixture::new(|_admin| {});
        locations_on(&fixture);
        learn_denver(&mut fixture);
        let now = MOMENT + 39 * 86_400 + 3600;
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, now));
        assert!(matches!(
            check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), now),
            LocationVerdict::Refuse { .. }
        ));
        let refused = |fixture: &mut Fixture| {
            let request = Request::ListVpnUsers {
                session: session.clone(),
            };
            match fixture.service.handle(request, now + 30) {
                Response::VpnUsers { refused, .. } => refused,
                other => panic!("expected the VPN users, got {other:?}"),
            }
        };
        let listed = refused(&mut fixture);
        assert!(
            matches!(&listed[..], [RefusedSignIn { user, from, known: false, .. }]
                if user == "alex" && from == MOSCOW),
            "{listed:?}"
        );
        let allow = |fixture: &mut Fixture, user: &str| {
            let request = Request::AllowPlace {
                session: session.clone(),
                csrf: csrf.clone(),
                user: user.to_owned(),
                from: MOSCOW.to_owned(),
            };
            fixture.service.handle(request, now + 60)
        };
        assert!(matches!(
            allow(&mut fixture, "nobody"),
            Response::Invalid { message } if message.contains("no VPN user")
        ));
        assert_eq!(allow(&mut fixture, "alex"), Response::Done);
        assert!(matches!(
            &refused(&mut fixture)[..],
            [RefusedSignIn { known: true, .. }]
        ));
        let audit = fixture.audit();
        assert!(
            audit.contains("allowed 192.0.2.9") && audit.contains("for alex's VPN sign-ins"),
            "{audit}"
        );
        fixture.service.control = Box::new(Fake {
            sessions: Vec::new(),
            ..Fake::sample(0)
        });
        assert_eq!(
            check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), now + 120),
            LocationVerdict::Allow
        );
    }

    #[test]
    fn vacations_are_set_for_oneself_or_by_an_operator_and_end_within_60_days() {
        let mut fixture = Fixture::new(|_admin| {});
        locations_on(&fixture);
        let (alex, alex_csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Viewer,
        };
        let password = one_time(change_admin(&mut fixture, &alex, &alex_csrf, add));
        let (sam, sam_csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        let vacation = |fixture: &mut Fixture,
                        (session, csrf): (&str, &str),
                        kind: AccountKind,
                        name: &str,
                        until: Option<&str>| {
            fixture.service.handle(
                Request::SetVacation {
                    session: session.to_owned(),
                    csrf: csrf.to_owned(),
                    kind,
                    name: name.to_owned(),
                    until: until.map(str::to_owned),
                },
                MOMENT,
            )
        };
        let by_alex = (alex.as_str(), alex_csrf.as_str());
        let by_sam = (sam.as_str(), sam_csrf.as_str());
        let end_of = |date: &str| crate::clock::date_start(date).unwrap() + 86_400;
        assert_eq!(
            vacation(
                &mut fixture,
                by_alex,
                AccountKind::Vpn,
                "alex",
                Some("2009-04-14")
            ),
            Response::Done
        );
        assert_eq!(
            fixture
                .service
                .vacation_of(AccountKind::Vpn, "alex", MOMENT),
            Some(end_of("2009-04-14"))
        );
        for (name, until) in [
            ("alex", "2009-04-15"),
            ("alex", "2009-02-12"),
            ("nobody", "2009-03-01"),
        ] {
            assert!(
                matches!(
                    vacation(&mut fixture, by_alex, AccountKind::Vpn, name, Some(until)),
                    Response::Invalid { .. }
                ),
                "{name} {until}"
            );
        }
        assert!(matches!(
            vacation(&mut fixture, by_sam, AccountKind::Vpn, "alex", None),
            Response::Invalid { message } if message.contains("only for yourself")
        ));
        assert_eq!(
            vacation(
                &mut fixture,
                by_sam,
                AccountKind::Admin,
                "sam",
                Some("2009-02-13")
            ),
            Response::Done
        );
        assert_eq!(
            fixture
                .service
                .vacation_of(AccountKind::Admin, "sam", MOMENT),
            Some(end_of("2009-02-13"))
        );
        assert_eq!(
            fixture
                .service
                .vacation_of(AccountKind::Admin, "sam", end_of("2009-02-13")),
            None
        );
        assert_eq!(
            vacation(&mut fixture, by_alex, AccountKind::Vpn, "alex", None),
            Response::Done
        );
        assert_eq!(
            fixture
                .service
                .vacation_of(AccountKind::Vpn, "alex", MOMENT),
            None
        );
        let audit = fixture.audit();
        assert!(audit.contains("set the vacation of VPN user alex through 2009-04-14"));
        assert!(audit.contains("ended the vacation of VPN user alex"));
        assert!(audit.contains("set their own vacation through 2009-02-13"));
        assert!(audit.contains("viewers set a vacation only for themselves"));
    }

    #[test]
    fn the_bans_page_shows_the_location_setting_its_data_and_the_last_check() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, _csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let view = |fixture: &mut Fixture| match bans(fixture, &session) {
            Response::Bans { locations, .. } => *locations,
            other => panic!("expected the Bans page, got {other:?}"),
        };
        let off = view(&mut fixture);
        assert!(!off.on && off.refresh_hours == 6, "{off:?}");
        assert!(!off.on_from_env && !off.refresh_from_env && off.last.is_none());
        assert_eq!(off.city.map(|city| city.kind), Some("Test-City".to_owned()));
        assert_eq!(
            off.networks.map(|networks| networks.kind),
            Some("Test-ASN".to_owned())
        );
        locations_on(&fixture);
        fixture.service.locations.environment.refresh_hours = Some(24);
        let installed = vec!["DB-IP dbip-city-lite-2009-02".to_owned()];
        fixture
            .service
            .note_location_check(MOMENT + 60, Ok(installed.clone()));
        let on = view(&mut fixture);
        assert!(on.on && on.refresh_hours == 24, "{on:?}");
        assert!(on.refresh_from_env && !on.on_from_env);
        assert_eq!(on.last, Some((MOMENT + 60, Ok(installed))));
    }

    #[test]
    fn with_the_location_checks_off_a_vpn_sign_in_is_let_in_unlearned() {
        let mut fixture = Fixture::new(|_admin| {});
        assert_eq!(
            check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), MOMENT),
            LocationVerdict::Allow
        );
        locations_on(&fixture);
        fixture.service.locations.atlas = None;
        assert_eq!(
            check_vpn(&mut fixture, &vpn_sign_in(MOSCOW), MOMENT),
            LocationVerdict::Allow
        );
        assert!(
            fixture
                .service
                .locations
                .learning
                .history(AccountKind::Vpn, "alex")
                .is_none()
        );
        assert!(location_events(&fixture).is_empty());
    }

    fn empty_store(dir: &TestDir) -> (Store, Audit, Hasher) {
        (
            Store::open(&dir.path().join("admins.json")).unwrap(),
            Audit::open(&dir.path().join("audit.log")).unwrap(),
            Hasher::new(64, 1).unwrap(),
        )
    }

    #[test]
    fn the_first_admin_gets_a_one_time_password() {
        let dir = TestDir::new();
        let (mut store, mut audit, hasher) = empty_store(&dir);
        let created =
            bootstrap(&mut store, &mut audit, &hasher, &policy(), "Admin", None, 5).unwrap();
        let Bootstrap::OneTime { name, password } = created else {
            panic!("expected a one-time password, got {created:?}");
        };
        assert_eq!(name, "admin");
        let admin = store.get("admin").cloned().unwrap();
        assert_eq!(admin.role, Role::Owner);
        assert!(admin.must_change_password);
        assert!(admin.enrollment_open);
        assert!(hasher.verify(&password, &admin.password_hash).unwrap());
        assert!(
            Store::open(&dir.path().join("admins.json"))
                .unwrap()
                .get("admin")
                .is_some()
        );
        let log = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains("admin.bootstrap"), "{log}");
        assert!(
            !log.contains(&password),
            "the one-time password reached the audit log"
        );
        let again =
            bootstrap(&mut store, &mut audit, &hasher, &policy(), "admin", None, 6).unwrap();
        assert_eq!(again, Bootstrap::Existing);
    }

    #[test]
    fn the_first_admin_can_come_from_a_password_file() {
        let dir = TestDir::new();
        let (mut store, mut audit, hasher) = empty_store(&dir);
        let file = dir.path().join("secret");
        fs::write(&file, "from a docker secret\n").unwrap();
        let created = bootstrap(
            &mut store,
            &mut audit,
            &hasher,
            &policy(),
            "admin",
            Some(&file),
            5,
        )
        .unwrap();
        assert_eq!(
            created,
            Bootstrap::FromFile {
                name: "admin".to_owned()
            }
        );
        let admin = store.get("admin").cloned().unwrap();
        assert!(!admin.must_change_password);
        assert!(
            hasher
                .verify("from a docker secret", &admin.password_hash)
                .unwrap()
        );
    }

    #[test]
    fn a_short_password_file_is_refused() {
        let dir = TestDir::new();
        let (mut store, mut audit, hasher) = empty_store(&dir);
        let file = dir.path().join("secret");
        fs::write(&file, "short\n").unwrap();
        let error = bootstrap(
            &mut store,
            &mut audit,
            &hasher,
            &policy(),
            "admin",
            Some(&file),
            5,
        )
        .unwrap_err();
        assert!(error.contains("PANEL_ADMIN_PASSWORD_FILE"), "{error}");
        assert!(store.is_empty());
    }

    fn alerts_of(fixture: &mut Fixture, session: &str) -> AlertsView {
        let request = Request::Alerts {
            session: session.to_owned(),
        };
        match fixture.service.handle(request, MOMENT) {
            Response::Alerts { view } => *view,
            other => panic!("expected the Alerts page, got {other:?}"),
        }
    }

    fn choose(fixture: &mut Fixture, session: &str, csrf: &str, topics: &[Topic]) {
        let request = Request::SetAlertTopics {
            session: session.to_owned(),
            csrf: csrf.to_owned(),
            topics: topics.to_vec(),
        };
        assert_eq!(fixture.service.handle(request, MOMENT), Response::Done);
    }

    fn hook(n: u32) -> ChannelEntry {
        ChannelEntry::Webhook {
            url: format!("https://hooks.example.com/alerts/{n}-abcdefghijkl"),
        }
    }

    fn add_channel(
        fixture: &mut Fixture,
        session: &str,
        csrf: &str,
        channel: ChannelEntry,
    ) -> Response {
        let request = Request::AddAlertChannel {
            session: session.to_owned(),
            csrf: csrf.to_owned(),
            channel,
        };
        fixture.service.handle(request, MOMENT)
    }

    /// The messages due at `now`, each finished as sent, as "admin: text".
    fn sent(fixture: &mut Fixture, now: u64) -> Vec<String> {
        let due = fixture.service.take_alerts(now);
        due.into_iter()
            .map(|delivery| {
                fixture
                    .service
                    .finish_alert(now, delivery.channel, Tried::Sent)
                    .unwrap();
                format!("{}: {}", delivery.admin, delivery.text)
            })
            .collect()
    }

    #[test]
    fn an_admin_chooses_alerts_and_adds_tests_and_removes_a_channel() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        choose(
            &mut fixture,
            &session,
            &csrf,
            &[Topic::Blocks, Topic::SignIns],
        );
        assert_eq!(
            add_channel(&mut fixture, &session, &csrf, hook(1)),
            Response::Done
        );
        let public = ChannelEntry::Webhook {
            url: "http://203.0.113.5/hook".to_owned(),
        };
        assert!(matches!(
            add_channel(&mut fixture, &session, &csrf, public),
            Response::Invalid { .. }
        ));
        let view = alerts_of(&mut fixture, &session);
        assert_eq!(view.topics, [Topic::Blocks, Topic::SignIns]);
        assert!(view.owner && !view.mail_set && !view.country_rules_on);
        assert_eq!(view.channels.len(), 1);
        let id = view.channels[0].id;
        let test = |id| Request::TestAlertChannel {
            session: session.clone(),
            csrf: csrf.clone(),
            id,
        };
        assert_eq!(fixture.service.handle(test(id), MOMENT), Response::Done);
        assert_eq!(
            alerts_of(&mut fixture, &session).channels[0].status.pending,
            1
        );
        let messages = sent(&mut fixture, MOMENT);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("A test message"), "{messages:?}");
        assert!(matches!(
            fixture.service.handle(test(id + 1), MOMENT),
            Response::Invalid { .. }
        ));
        let remove = Request::RemoveAlertChannel {
            session: session.clone(),
            csrf: csrf.clone(),
            id,
        };
        assert_eq!(fixture.service.handle(remove, MOMENT), Response::Done);
        assert!(alerts_of(&mut fixture, &session).channels.is_empty());
        let audit = fixture.audit();
        for detail in [
            "chose alerts for automatic blocks, sign-ins from outside the trusted networks",
            "added a webhook channel: hooks.example.com …ijkl",
            "an http:// URL sends alerts unencrypted",
            "asked for a test message on the webhook channel hooks.example.com …ijkl",
            "sent 1 alert to alex's webhook channel hooks.example.com …ijkl",
            "removed the webhook channel hooks.example.com …ijkl",
        ] {
            assert!(audit.contains(detail), "{detail}: {audit}");
        }
        assert!(!audit.contains("abcdefghijkl"), "{audit}");
    }

    #[test]
    fn sign_ins_from_outside_alert_the_owners_and_the_admin_alone() {
        let mut fixture = Fixture::new(|admin| admin.totp_secret = Some(SECRET.to_owned()));
        let (alex, alex_csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add_sam = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Operator,
        };
        let password = one_time(change_admin(&mut fixture, &alex, &alex_csrf, add_sam));
        let (sam, sam_csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        for (session, csrf, n) in [(&alex, &alex_csrf, 1), (&sam, &sam_csrf, 2)] {
            choose(&mut fixture, session, csrf, &[Topic::SignIns]);
            add_channel(&mut fixture, session, csrf, hook(n));
        }
        assert!(
            sent(&mut fixture, MOMENT).is_empty(),
            "a sign-in from the LAN alerted"
        );
        let pending = pending_token(fixture.login("alex", PASSWORD, VPN, MOMENT));
        signed_in(second(&mut fixture, &pending, "005924", MOMENT));
        assert_eq!(
            sent(&mut fixture, MOMENT),
            [
                "alex: 23:31 UTC  alex signed in to the panel from 192.168.255.40, outside the \
              trusted networks, with a password and an authenticator code"
            ]
        );
        signed_in(fixture.login("sam", &password, VPN, MOMENT + 120));
        let mut both = sent(&mut fixture, MOMENT + 120);
        both.sort();
        assert_eq!(both.len(), 2, "{both:?}");
        assert!(both[0].starts_with("alex: ") && both[1].starts_with("sam: "));
        assert!(
            both[0].contains(
                "sam signed in to the panel from 192.168.255.40, outside the trusted \
                 networks, with a password, to set up an authenticator app"
            ),
            "{both:?}"
        );
    }

    #[test]
    fn an_automatic_block_alerts_those_who_chose_it() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        choose(&mut fixture, &session, &csrf, &[Topic::Blocks]);
        add_channel(&mut fixture, &session, &csrf, hook(1));
        let banned = |time| Event {
            time,
            what: What::Banned {
                address: "203.0.113.7".to_owned(),
                score: 80,
            },
        };
        for time in [MOMENT, MOMENT + 10, MOMENT + 20] {
            fixture
                .service
                .record_events(time, vec![banned(time)])
                .unwrap();
        }
        let messages = sent(&mut fixture, MOMENT + 20);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            messages[0].contains(
                "Blocked 203.0.113.7/32 (United States) at the firewall for 1 day: banned 3 \
                 times within 1 day"
            ),
            "{messages:?}"
        );
    }

    #[test]
    fn only_an_owner_sets_the_mail_server_and_a_saved_password_stays_with_its_server() {
        let mut fixture = Fixture::new(|_admin| {});
        let (session, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let entry = |host: &str, security: &str, password: &str| MailEntry {
            host: host.to_owned(),
            port: String::new(),
            security: security.to_owned(),
            user: "alerts@example.com".to_owned(),
            password: password.to_owned(),
            from: "alerts@example.com".to_owned(),
        };
        let set = |fixture: &mut Fixture, session: &str, csrf: &str, server: MailEntry| {
            let request = Request::SetMailServer {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
                server,
            };
            fixture.service.handle(request, MOMENT)
        };
        let saved = entry("smtp.example.com", "starttls", "correct horse");
        assert_eq!(set(&mut fixture, &session, &csrf, saved), Response::Done);
        let mail = alerts_of(&mut fixture, &session).mail.unwrap();
        assert_eq!((mail.port, mail.password_set), (587, true));
        let kept = entry("smtp.example.com", "tls", "");
        assert_eq!(set(&mut fixture, &session, &csrf, kept), Response::Done);
        let mail = alerts_of(&mut fixture, &session).mail.unwrap();
        assert_eq!((mail.port, mail.password_set), (465, true));
        let moved = entry("smtp.elsewhere.example", "tls", "");
        assert!(matches!(
            set(&mut fixture, &session, &csrf, moved),
            Response::Invalid { .. }
        ));
        let plain = entry("192.168.1.2", "plain", "correct horse");
        assert!(matches!(
            set(&mut fixture, &session, &csrf, plain),
            Response::Invalid { .. }
        ));
        let add_sam = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Operator,
        };
        let password = one_time(change_admin(&mut fixture, &session, &csrf, add_sam));
        let (sam, sam_csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        let theirs = entry("smtp.example.com", "tls", "hunter2-hunter2");
        assert_eq!(
            set(&mut fixture, &sam, &sam_csrf, theirs),
            Response::Invalid {
                message: SET_MAIL.to_owned()
            }
        );
        let sam_view = alerts_of(&mut fixture, &sam);
        assert!(sam_view.mail_set && sam_view.mail.is_none() && !sam_view.owner);
        let remove = Request::RemoveMailServer {
            session: session.clone(),
            csrf: csrf.clone(),
        };
        assert_eq!(fixture.service.handle(remove, MOMENT), Response::Done);
        assert!(!alerts_of(&mut fixture, &session).mail_set);
        let audit = fixture.audit();
        assert!(
            audit.contains(
                "set the mail server for email alerts: smtp.example.com:465 with TLS, signing in \
                 as alerts@example.com, from alerts@example.com"
            ),
            "{audit}"
        );
        assert!(
            audit.contains("removed the mail server for email alerts"),
            "{audit}"
        );
        assert!(
            !audit.contains("correct horse") && !audit.contains("hunter2"),
            "{audit}"
        );
    }

    #[test]
    fn a_removed_admin_takes_their_alerts_along() {
        let mut fixture = Fixture::new(|_admin| {});
        let (alex, csrf, _scope) = signed_in(fixture.login("alex", PASSWORD, LAN, MOMENT));
        let add_sam = AdminChange::Add {
            name: "sam".to_owned(),
            role: Role::Viewer,
        };
        let password = one_time(change_admin(&mut fixture, &alex, &csrf, add_sam));
        let (sam, sam_csrf, _scope) = signed_in(fixture.login("sam", &password, LAN, MOMENT));
        choose(&mut fixture, &sam, &sam_csrf, &[Topic::Blocks]);
        assert_eq!(
            add_channel(&mut fixture, &sam, &sam_csrf, hook(1)),
            Response::Done
        );
        let saved = || fs::read_to_string(fixture.dir.path().join("alerts.json")).unwrap();
        assert!(saved().contains("\"sam\""));
        let remove = AdminChange::Remove {
            name: "sam".to_owned(),
        };
        assert_eq!(change_admin(&mut fixture, &alex, &csrf, remove), CHANGED);
        let saved = fs::read_to_string(fixture.dir.path().join("alerts.json")).unwrap();
        assert!(!saved.contains("\"sam\""), "{saved}");
    }
}
