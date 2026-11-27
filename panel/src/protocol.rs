//! The protocol between the web process and the helper, over helper.sock:
//! JSON messages, each preceded by its length as a 4-byte big-endian number.

use std::fmt;
#[cfg(any(unix, test))]
use std::io::{ErrorKind, Read, Write};

#[cfg(any(unix, test))]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

use crate::alerts::{Security, Status as ChannelStatus, Topic};
use crate::audit::Record;
use crate::blocklist::{AutoBlock, Block};
use crate::clientcerts::{Cipher, Method, Revocation};
use crate::events::Logged;
use crate::history::Sample;
use crate::kit::{Authenticator, Facts, Kit};
use crate::location::{Edition, Kind as AccountKind};
use crate::occtl::{Ban, BanPoints, Session as VpnSession, Status};
use crate::overrides::{Form as OverridesForm, Overrides, Owner};
use crate::portal::PortalScope;
use crate::server_settings::Setting;
use crate::serverconf::BanPolicy;
use crate::sessions::Scope;
use crate::sites::{End, Rule};
use crate::store::Role;
use crate::vpnusers::VpnUser;

/// The largest message either side accepts, in bytes. A longer one is
/// refused from its length alone, before any of it is read.
pub const MAX_MESSAGE: u32 = 1 << 20;

/// What the web process asks of the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Answered with `Pong`.
    Ping,
    /// Checks a password; `from` is the address the browser connected from.
    Login {
        name: String,
        password: String,
        from: String,
    },
    /// Ends a session.
    Logout { session: String },
    /// Describes the admin of a session.
    Whoami { session: String },
    /// Replaces the session admin's password and ends their other sessions.
    ChangePassword {
        session: String,
        csrf: String,
        current: String,
        new: String,
    },
    /// Completes a sign-in whose password was accepted, with a TOTP code.
    SecondFactor { pending: String, code: String },
    /// Starts TOTP enrollment for the session's admin: a new secret to
    /// confirm with a code.
    TotpBegin { session: String, csrf: String },
    /// Confirms TOTP enrollment with a code from the new secret.
    TotpConfirm {
        session: String,
        csrf: String,
        code: String,
    },
    /// The TOTP secret issued to the session's admin and not yet confirmed,
    /// while it is still within its time. Changes nothing.
    TotpPending { session: String },
    /// Starts registering a passkey named `name` for the session's admin:
    /// the options for the browser's passkey prompt.
    PasskeyBegin {
        session: String,
        csrf: String,
        name: String,
    },
    /// Finishes the registration with the browser's answer, as JSON.
    PasskeyFinish {
        session: String,
        csrf: String,
        credential: String,
    },
    /// Removes the session admin's passkey named `name`. Needs full access
    /// and a recent sign-in.
    RemovePasskey {
        session: String,
        csrf: String,
        name: String,
    },
    /// The second factors a sign-in whose password was accepted can be
    /// completed with. Changes nothing.
    SecondFactorOptions { pending: String },
    /// Turns the location checks on or off and sets how often, in hours,
    /// their databases are checked for a newer copy. Needs an owner; a value
    /// the environment sets cannot be changed.
    SetLocationChecks {
        session: String,
        csrf: String,
        on: bool,
        refresh_hours: String,
    },
    /// Starts completing a sign-in whose password was accepted with a
    /// passkey: the options for the browser's passkey prompt.
    PasskeySignInBegin { pending: String },
    /// Completes the sign-in with the browser's answer, as JSON. A refused
    /// answer ends the pending sign-in and counts toward the lockout.
    PasskeySignIn { pending: String, credential: String },
    /// The VPN server's state. Needs a session with full access.
    ServerStatus { session: String },
    /// The connected VPN sessions. Needs a session with full access.
    ListSessions { session: String },
    /// Ends a VPN session and invalidates its cookie, so the client must sign
    /// in again. Needs an owner or operator.
    EndSession {
        session: String,
        csrf: String,
        id: u64,
    },
    /// The VPN users in the password file. Needs a session with full access.
    ListVpnUsers { session: String },
    /// Makes the place of `from` usual for VPN user `user`, as where they
    /// are now, after the location checks refused a sign-in from it. Needs
    /// an owner or operator.
    AllowPlace {
        session: String,
        csrf: String,
        user: String,
        from: String,
    },
    /// Puts a VPN user or an admin on vacation through `until`, a date
    /// written YYYY-MM-DD, or ends their vacation with none: while it lasts,
    /// the location checks alert on an implausible sign-in but never refuse
    /// it. An admin sets their own; an owner or operator sets anyone's.
    SetVacation {
        session: String,
        csrf: String,
        kind: AccountKind,
        name: String,
        until: Option<String>,
    },
    /// The dashboard's samples of the VPN server taken after `since` (Unix
    /// seconds), or all of them. Needs a session with full access.
    History { session: String, since: Option<u64> },
    /// Changes a VPN user. Needs an owner or operator.
    ChangeVpnUser {
        session: String,
        csrf: String,
        change: UserChange,
    },
    /// The banned addresses, the addresses with ban points, and how ocserv
    /// bans. Needs a session with full access.
    ListBans { session: String },
    /// A page of the audit log, newest first, from the lines before line
    /// `before`, or from the newest. Needs an owner with full access.
    ListAudit {
        session: String,
        before: Option<usize>,
    },
    /// The session admin's own account. Needs full access.
    Account { session: String },
    /// Ends every session of the session's admin but this one. Needs full
    /// access.
    EndOtherSessions { session: String, csrf: String },
    /// The certificates the server and the panel use. Needs a session with
    /// full access.
    Certificates { session: String },
    /// The VPN users' client certificates the panel issued, and how long a
    /// new one is valid. Needs a session with full access.
    ClientCertificates { session: String },
    /// Issues a client certificate for a VPN user. Needs an owner or
    /// operator.
    IssueClientCertificate {
        session: String,
        csrf: String,
        user: String,
        how: IssueHow,
    },
    /// Issues a new certificate for the user of the certificate `serial`,
    /// the way that one was issued, naming the user's groups now. Needs an
    /// owner or operator.
    RenewClientCertificate {
        session: String,
        csrf: String,
        serial: String,
    },
    /// Revokes the certificate `serial` and ends its user's VPN sessions.
    /// Needs an owner or operator.
    RevokeClientCertificate {
        session: String,
        csrf: String,
        serial: String,
    },
    /// The server settings the Settings page offers. Needs an owner with
    /// full access.
    ServerSettings { session: String },
    /// Stores the values typed on the Settings page, each a setting and the
    /// text of its field, and applies what a reload can. Needs an owner
    /// with full access.
    SetServerSettings {
        session: String,
        csrf: String,
        values: Vec<(String, String)>,
    },
    /// The admin accounts. Needs an owner with full access.
    ListAdmins { session: String },
    /// Changes an admin account other than the session's own. Needs an
    /// owner with full access.
    ChangeAdmin {
        session: String,
        csrf: String,
        change: AdminChange,
    },
    /// Lifts the ban on an address and clears its points. Needs an owner or
    /// operator.
    Unban {
        session: String,
        csrf: String,
        address: String,
    },
    /// Blocks an address or network at the firewall on every port, for
    /// `hours` or until lifted. Needs an owner or operator.
    Block {
        session: String,
        csrf: String,
        network: String,
        hours: Option<u64>,
    },
    /// Lifts the block of a network. Needs an owner or operator.
    Unblock {
        session: String,
        csrf: String,
        network: String,
    },
    /// Makes the block of a network stay until it is lifted. Needs an owner
    /// or operator.
    KeepBlock {
        session: String,
        csrf: String,
        network: String,
    },
    /// Stores the country rules from the Bans page and loads them into the
    /// firewall: `rule` off, block or allow, and the listed countries'
    /// codes, each none where the environment sets it. Needs an owner with
    /// full access.
    SetCountries {
        session: String,
        csrf: String,
        rule: Option<String>,
        countries: Option<Vec<String>>,
    },
    /// Downloads MaxMind GeoLite2 with an account ID and license key, and
    /// keeps the key once MaxMind accepts it. Needs an owner with full
    /// access.
    SetMaxmindKey {
        session: String,
        csrf: String,
        account: String,
        license: String,
    },
    /// Removes the MaxMind key the panel keeps and its GeoLite2 copy, so the
    /// country rules read DB-IP Lite again. Needs an owner with full access.
    RemoveMaxmindKey { session: String, csrf: String },
    /// What the Alerts page shows the session's admin: the topics they
    /// chose, their channels and how each did last, and the mail server.
    /// Needs full access.
    Alerts { session: String },
    /// Replaces the topics that alert the session's admin. Needs full
    /// access.
    SetAlertTopics {
        session: String,
        csrf: String,
        topics: Vec<Topic>,
    },
    /// Adds a channel for the session's admin. Needs full access.
    AddAlertChannel {
        session: String,
        csrf: String,
        channel: ChannelEntry,
    },
    /// Removes the session's admin's channel `id`. Needs full access.
    RemoveAlertChannel {
        session: String,
        csrf: String,
        id: u32,
    },
    /// Sends a test message to the session's admin's channel `id`. Needs
    /// full access.
    TestAlertChannel {
        session: String,
        csrf: String,
        id: u32,
    },
    /// Saves the mail server email alerts go through. Needs an owner with
    /// full access, while the environment sets no mail server.
    SetMailServer {
        session: String,
        csrf: String,
        server: MailEntry,
    },
    /// Removes the mail server the panel saved. Needs an owner with full
    /// access.
    RemoveMailServer { session: String, csrf: String },
    /// The live events numbered after `after`, or all that are kept, oldest
    /// first. Needs a session with full access.
    ListEvents { session: String, after: Option<u64> },
    /// The groups the password file names or that have a settings file,
    /// with their members and settings. Needs a session with full access.
    ListGroups { session: String },
    /// A user's or group's own settings and those it inherits. Needs a
    /// session with full access.
    GetOverrides {
        session: String,
        owner: Owner,
        name: String,
    },
    /// Replaces a user's or group's settings, or removes its settings file
    /// when `form` is none. Needs an owner or operator.
    SetOverrides {
        session: String,
        csrf: String,
        owner: Owner,
        name: String,
        form: Option<OverridesForm>,
    },
    /// The site-to-site rules, the users and groups that publish networks,
    /// and what the Sites page notes about them. Needs a session with full
    /// access.
    SiteRules { session: String },
    /// Adds a site-to-site rule that lets `from` open connections to `to`.
    /// Needs an owner or operator.
    AddSiteRule {
        session: String,
        csrf: String,
        from: End,
        to: End,
    },
    /// Removes the site-to-site rule `id`. Needs an owner or operator.
    RemoveSiteRule {
        session: String,
        csrf: String,
        id: u64,
    },
    /// Lets the networks `user` publishes reach beyond the VPN, or keeps
    /// them inside it. Needs an owner or operator.
    SetSiteEgress {
        session: String,
        csrf: String,
        user: String,
        on: bool,
    },
    /// A request of the VPN user portal, answered with `Response::Portal`.
    Portal { request: PortalRequest },
}

/// What the web process asks of the helper for the VPN user portal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortalRequest {
    /// Signs a VPN user in with their VPN password, and their code when the
    /// VPN asks for one; `from` is the address the browser connected from.
    Login {
        name: String,
        password: String,
        code: Option<String>,
        from: String,
    },
    /// Completes a sign-in whose password was right with the code, while
    /// the VPN asks for codes.
    Code { pending: String, code: String },
    /// Describes the VPN user of a portal session.
    Whoami { session: String },
    /// Issues the session's user a new authenticator key to confirm with a
    /// code, while the VPN asks for codes. A user who has a key replaces it
    /// only with `old_code`, a code from it.
    KeyBegin {
        session: String,
        csrf: String,
        old_code: Option<String>,
    },
    /// The session's user's account: their VPN sessions, their key, and
    /// whether they signed in recently enough to change the password.
    Account { session: String },
    /// Replaces the session's user's password, which must be `current`, and
    /// ends their other sessions: every VPN session but the one the
    /// browser signed in through, and every other portal session.
    ChangePassword {
        session: String,
        csrf: String,
        current: String,
        new: String,
    },
    /// Ends one of the session's user's own VPN sessions.
    EndSession {
        session: String,
        csrf: String,
        id: u64,
    },
    /// Saves the issued key when `code` matches it, and gives an
    /// enrollment-only session the full portal.
    KeyConfirm {
        session: String,
        csrf: String,
        code: String,
    },
    /// What the portal's home page shows the session's user: how to reach
    /// the server and set up a client, as the onboarding kit gives it
    /// without a password or a key.
    Home { session: String },
    /// Ends a portal session.
    Logout { session: String },
}

/// What the helper answers the portal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortalResponse {
    SignedIn {
        session: String,
        csrf: String,
        user: String,
        scope: PortalScope,
        expires: u64,
    },
    /// The password was right and the VPN asks for a code, which completes
    /// the sign-in through `PortalRequest::Code` with `pending`.
    CodeRequired {
        pending: String,
    },
    User {
        user: String,
        scope: PortalScope,
        csrf: String,
        expires: u64,
    },
    Home {
        user: String,
        scope: PortalScope,
        csrf: String,
        /// How to connect; none for a session that may only set up a key.
        kit: Option<Box<Kit>>,
        /// Whether the VPN asks for codes and the user has no key, so the
        /// page offers to set one up.
        needs_key: bool,
    },
    /// A new authenticator key waiting for its first code; `wrong` when the
    /// code given for it did not match.
    Key {
        authenticator: Authenticator,
        wrong: bool,
    },
    Account {
        user: String,
        csrf: String,
        /// Whether the VPN asks for codes, and whether the user has a key.
        codes: bool,
        has_key: bool,
        /// Whether the sign-in is recent enough to change the password.
        recent: bool,
        /// The user's VPN sessions.
        sessions: Vec<VpnSession>,
        /// The VPN session the browser signed in through, if it did.
        this_session: Option<u64>,
    },
    Done,
    /// Refused: a wrong password or code, an unknown or locked user, a
    /// session that ended. The page says no more than that.
    Denied,
    Locked {
        retry_after: u64,
    },
    Invalid {
        message: String,
    },
    Error {
        message: String,
    },
}

/// A VPN sign-in that ocserv's session script asks the helper to check, on
/// the location socket, which root alone reaches and which takes nothing
/// else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnSignIn {
    pub user: String,
    /// The address the client connects from.
    pub from: String,
    /// The session's ID as occtl lists it, which the check leaves out of the
    /// user's open sessions.
    pub session: Option<u64>,
    /// The device's type and platform, and the client's user agent, as
    /// ocserv reports them.
    pub devices: Vec<String>,
}

impl VpnSignIn {
    /// The sign-in ocserv's session script reports, from the variables
    /// ocserv sets for it: USERNAME, IP_REAL, ID, DEVICE_TYPE,
    /// DEVICE_PLATFORM and USER_AGENT. The device's type and platform make
    /// one device, and the user agent, which names the client's version,
    /// another.
    #[cfg(any(unix, test))]
    pub fn from_script(get: impl Fn(&str) -> Option<String>) -> Result<VpnSignIn, String> {
        let text = |name: &str| get(name).filter(|value| !value.is_empty());
        let user = text("USERNAME").ok_or_else(|| "USERNAME is not set".to_owned())?;
        let from = text("IP_REAL").ok_or_else(|| "IP_REAL is not set".to_owned())?;
        let session = match text("ID") {
            Some(id) => Some(
                id.parse()
                    .map_err(|error| format!("ID is not a whole number: '{id}': {error}"))?,
            ),
            None => None,
        };
        let device = match (text("DEVICE_TYPE"), text("DEVICE_PLATFORM")) {
            (Some(kind), Some(platform)) => Some(format!("{kind} on {platform}")),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        };
        Ok(VpnSignIn {
            user,
            from,
            session,
            devices: device.into_iter().chain(text("USER_AGENT")).collect(),
        })
    }
}

/// What the location check of a VPN sign-in found. Every verdict but
/// `Allow` is on the Live events page and in the alerts already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocationVerdict {
    /// Let in: the checks are off or have no databases yet, or the sign-in
    /// fits.
    Allow,
    /// Let in, and unusual.
    Flag { score: u32, reasons: Vec<String> },
    /// Refused.
    Refuse { score: u32, reasons: Vec<String> },
    /// Let in without a check, which could not run.
    Unchecked { problem: String },
}

/// A group as the Groups page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    /// The users whose password file lines name the group.
    pub members: Vec<String>,
    /// The group's own settings; none when it has no settings file.
    pub settings: Option<Overrides>,
}

/// A change to a VPN user. A password left out is generated. A change that
/// sets a password or an authenticator key is answered with the user's
/// onboarding kit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserChange {
    /// Adds a user; `groups` is the comma-separated list typed in the form.
    /// When the VPN asks for codes, the user also gets an authenticator key.
    Add {
        name: String,
        groups: String,
        password: Option<String>,
    },
    SetPassword {
        name: String,
        password: Option<String>,
    },
    /// Sets the user's groups to `groups`, the comma-separated list typed in
    /// the form, keeping their password; ocserv uses them from the user's
    /// next connection.
    SetGroups {
        name: String,
        groups: String,
    },
    /// Gives the user a new authenticator key in place of the one they had.
    ResetOtp {
        name: String,
    },
    /// Locks a user and ends their sessions.
    Lock {
        name: String,
    },
    Unlock {
        name: String,
    },
    /// Removes a user and ends their sessions.
    Remove {
        name: String,
    },
}

impl UserChange {
    pub fn name(&self) -> &str {
        match self {
            UserChange::Add { name, .. }
            | UserChange::SetPassword { name, .. }
            | UserChange::SetGroups { name, .. }
            | UserChange::ResetOtp { name }
            | UserChange::Lock { name }
            | UserChange::Unlock { name }
            | UserChange::Remove { name } => name,
        }
    }

    /// What the audit log calls the change.
    pub fn action(&self) -> &'static str {
        match self {
            UserChange::Add { .. } => "vpn.user.add",
            UserChange::SetPassword { .. } => "vpn.user.password",
            UserChange::SetGroups { .. } => "vpn.user.groups",
            UserChange::ResetOtp { .. } => "vpn.user.otp",
            UserChange::Lock { .. } => "vpn.user.lock",
            UserChange::Unlock { .. } => "vpn.user.unlock",
            UserChange::Remove { .. } => "vpn.user.remove",
        }
    }

    /// Wipes the password the change carries, if any.
    pub fn wipe(&mut self) {
        match self {
            UserChange::Add { password, .. } | UserChange::SetPassword { password, .. } => {
                if let Some(password) = password {
                    password.zeroize();
                }
            }
            UserChange::SetGroups { .. }
            | UserChange::ResetOtp { .. }
            | UserChange::Lock { .. }
            | UserChange::Unlock { .. }
            | UserChange::Remove { .. } => {}
        }
    }
}

/// A change an owner makes to an admin account. A change that gives the
/// admin a one-time password is answered with it, to be handed over once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminChange {
    /// Adds an admin with a one-time password, open to set up a second
    /// factor from anywhere once.
    Add {
        name: String,
        role: Role,
    },
    SetRole {
        name: String,
        role: Role,
    },
    /// Gives the admin a one-time password and ends their sessions.
    ResetPassword {
        name: String,
    },
    /// Removes the admin's authenticator app, opens its setup from anywhere
    /// once, and ends their sessions.
    ResetSecondFactor {
        name: String,
    },
    /// Lifts a lockout after wrong passwords.
    Unlock {
        name: String,
    },
    /// Removes the admin and ends their sessions.
    Remove {
        name: String,
    },
}

impl AdminChange {
    pub fn name(&self) -> &str {
        match self {
            AdminChange::Add { name, .. }
            | AdminChange::SetRole { name, .. }
            | AdminChange::ResetPassword { name }
            | AdminChange::ResetSecondFactor { name }
            | AdminChange::Unlock { name }
            | AdminChange::Remove { name } => name,
        }
    }

    /// What the audit log calls the change.
    pub fn action(&self) -> &'static str {
        match self {
            AdminChange::Add { .. } => "admin.add",
            AdminChange::SetRole { .. } => "admin.role",
            AdminChange::ResetPassword { .. } => "admin.password.reset",
            AdminChange::ResetSecondFactor { .. } => "admin.totp.reset",
            AdminChange::Unlock { .. } => "admin.unlock",
            AdminChange::Remove { .. } => "admin.remove",
        }
    }
}

/// A certificate the server or the panel uses, as the Certificates page
/// shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateEntry {
    /// What uses it, in words.
    pub role: String,
    pub path: String,
    pub facts: Option<Facts>,
    /// Why its facts could not be read.
    pub problem: Option<String>,
}

/// How a client certificate's key comes to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IssueHow {
    /// The helper makes the key and hands it out once in a key file.
    KeyFile { cipher: Cipher },
    /// The user made the key, which the PEM signing request carries.
    Request { pem: String },
}

/// A client certificate as the Certificates page lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificate {
    pub serial: String,
    pub user: String,
    pub groups: Vec<String>,
    pub method: Method,
    pub by: String,
    pub issued: u64,
    pub not_after: u64,
    pub revoked: Option<Revocation>,
}

/// A certificate just issued, on its way to the page that hands it out
/// once: the certificate, and the key file with its passphrase when the
/// helper made the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCertificate {
    pub user: String,
    pub serial: String,
    pub not_after: u64,
    /// The URL a client opens and the server key's pin, for the
    /// instructions that come with the certificate.
    pub url: String,
    pub pin: String,
    /// The certificate in PEM.
    pub certificate: String,
    pub key_file: Option<KeyFileDownload>,
}

/// A PKCS#12 key file, in base64, and the passphrase that opens it. Its
/// `Debug` leaves both out, and both are wiped when it is dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFileDownload {
    pub cipher: Cipher,
    pub p12_base64: String,
    pub passphrase: String,
}

impl fmt::Debug for KeyFileDownload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KeyFileDownload({:?}, ..)", self.cipher)
    }
}

impl Drop for KeyFileDownload {
    fn drop(&mut self) {
        self.p12_base64.zeroize();
        self.passphrase.zeroize();
    }
}

/// A one-time password on its way to the page that shows it once. Its
/// `Debug` leaves the password out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OneTimePassword(pub String);

impl fmt::Debug for OneTimePassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimePassword(..)")
    }
}

/// A channel as an admin enters it on the Alerts page, before the helper
/// checks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelEntry {
    /// An ntfy topic; an empty server is ntfy.sh and an empty token none.
    Ntfy {
        server: String,
        topic: String,
        token: String,
    },
    Telegram {
        token: String,
        chat: String,
    },
    Webhook {
        url: String,
    },
    Email {
        address: String,
    },
}

impl ChannelEntry {
    /// Wipes the secrets the entry carries.
    pub fn wipe(&mut self) {
        match self {
            ChannelEntry::Ntfy { topic, token, .. } => {
                topic.zeroize();
                token.zeroize();
            }
            ChannelEntry::Telegram { token, .. } => token.zeroize(),
            ChannelEntry::Webhook { url } => url.zeroize(),
            ChannelEntry::Email { .. } => {}
        }
    }
}

/// The mail server as an owner enters it on the Alerts page: the port as
/// typed, empty for the security's usual one, and the password, empty to
/// keep the one saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailEntry {
    pub host: String,
    pub port: String,
    pub security: String,
    pub user: String,
    pub password: String,
    pub from: String,
}

impl MailEntry {
    pub fn wipe(&mut self) {
        self.password.zeroize();
    }
}

/// An admin account as the Admins page lists it, without its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSummary {
    pub name: String,
    pub role: Role,
    /// Whether the admin has an authenticator app, a passkey or both.
    pub second_factor: bool,
    pub authenticator_app: bool,
    pub passkeys: usize,
    /// Whether the admin still has a one-time password to replace.
    pub must_change_password: bool,
    /// Unix time until which sign-in is refused, while it lasts.
    pub locked_until: Option<u64>,
    pub created: u64,
    pub last_login: Option<u64>,
    /// Unix time the admin's vacation ends, while it lasts.
    pub vacation_until: Option<u64>,
}

/// One of an admin's passkeys as their Account page lists it, without its
/// credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyView {
    pub name: String,
    pub created: u64,
    pub last_used: Option<u64>,
}

/// What the helper answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Pong {
        version: String,
    },
    SignedIn {
        session: String,
        csrf: String,
        admin: String,
        role: Role,
        scope: Scope,
        must_change_password: bool,
        expires: u64,
    },
    /// The password was right and a second factor is due.
    SecondFactorRequired {
        pending: String,
    },
    /// The password was right, but outside the LAN a second factor is
    /// required and this account has none.
    SecondFactorNotEnrolled,
    /// The password was right, but the account's only second factor is
    /// passkeys, which cannot be used at the panel's address, for `reason`.
    SecondFactorUnavailable {
        reason: String,
    },
    /// The password was right, but the location checks refused the sign-in:
    /// it does not fit where the account usually signs in from.
    LocationRefused,
    /// The second factors a sign-in whose password was accepted can be
    /// completed with.
    SecondFactorOptions {
        code: bool,
        passkey: bool,
    },
    /// The options for the browser's passkey prompt, as JSON.
    PasskeyOptions {
        options: String,
    },
    /// Refused: a wrong password, an unknown admin, a session that ended.
    Denied,
    /// Refused for `retry_after` seconds.
    Locked {
        retry_after: u64,
    },
    Admin {
        name: String,
        role: Role,
        scope: Scope,
        /// The session's CSRF token, for the forms on the page being built.
        csrf: String,
        must_change_password: bool,
        expires: u64,
        /// Whether passkeys can be registered and used at the panel's
        /// address.
        passkeys: bool,
    },
    Done,
    /// A new TOTP secret and the URI an authenticator reads from a QR code.
    TotpSecret {
        secret: String,
        uri: String,
    },
    /// No TOTP secret is waiting for confirmation.
    NoTotpPending,
    Server {
        server: Status,
    },
    Sessions {
        sessions: Vec<VpnSession>,
        /// The countries of the addresses the sessions come from, or why
        /// there is no country database to find them in.
        places: Result<Located, String>,
    },
    VpnUsers {
        users: Vec<VpnUser>,
        /// Whether the VPN asks every user for a code after the password,
        /// so that a user without an authenticator key cannot sign in.
        codes: bool,
        /// The VPN sign-ins the location checks refused in the events kept,
        /// newest first, and the countries of their addresses.
        refused: Vec<RefusedSignIn>,
        places: Result<Located, String>,
        /// Whether the location checks are on, and the users on vacation,
        /// with when each vacation ends.
        locations_on: bool,
        vacations: Vec<(String, u64)>,
    },
    History {
        /// Seconds between samples.
        interval: u64,
        samples: Vec<Sample>,
    },
    Bans {
        banned: Vec<Ban>,
        /// Every address with ban points, including the banned ones.
        points: Vec<BanPoints>,
        policy: BanPolicy,
        /// The firewall's blocklist.
        blocks: Vec<Block>,
        /// When automatic blocks happen; 0 bans for none.
        auto: AutoBlock,
        countries: Box<CountryView>,
        locations: Box<LocationView>,
    },
    Events {
        events: Vec<Logged>,
        /// The helper's retention for events, in hours.
        hours: u64,
        /// The countries of the addresses the events name, or why there is
        /// no country database to find them in.
        places: Result<Located, String>,
    },
    Audit {
        /// Newest first.
        records: Vec<Record>,
        /// The `before` that asks for the next older page, if there is one.
        older: Option<usize>,
    },
    Admins {
        admins: Vec<AdminSummary>,
        /// Whether the location checks are on, so vacations count.
        locations_on: bool,
    },
    Certificates {
        certificates: Vec<CertificateEntry>,
    },
    /// The VPN users' client certificates, newest first, and the days a new
    /// one is valid.
    ClientCertificates {
        certificates: Vec<ClientCertificate>,
        days: u64,
    },
    /// A client certificate was issued.
    ClientCertificateIssued {
        issued: Box<IssuedCertificate>,
    },
    /// The server settings; none when the server runs an operator's own
    /// configuration file, whose settings the panel does not change.
    ServerSettings {
        settings: Option<Vec<Setting>>,
    },
    /// The settings were stored.
    ServerSettingsSaved {
        /// Whether ocserv reloaded to apply them now.
        reloaded: bool,
    },
    /// The session admin's own account.
    AdminAccount {
        admin: AdminSummary,
        /// The admin's live sessions besides this one.
        other_sessions: usize,
        /// The admin's passkeys, in the order they were added.
        passkeys: Vec<PasskeyView>,
        /// Why passkeys cannot be registered or used at the panel's address,
        /// when they cannot.
        passkeys_unavailable: Option<String>,
        /// Whether the location checks are on, so a vacation counts.
        locations_on: bool,
    },
    /// The admin change was made.
    AdminChanged {
        /// The one-time password the change set, to hand to the admin.
        one_time_password: Option<OneTimePassword>,
    },
    Groups {
        groups: Vec<Group>,
        /// The server's settings, which a group's empty fields inherit.
        server: Overrides,
        /// Whether ocserv reads per-group settings files at all.
        readable: bool,
    },
    Overrides {
        /// The settings in the user's or group's own file; none when it has
        /// none.
        own: Option<Box<Overrides>>,
        /// For a user, the group whose settings they inherit: their first.
        group: Option<String>,
        /// That group's own settings; none when it has no settings file.
        group_settings: Option<Box<Overrides>>,
        /// The server's settings, which the rest inherit.
        server: Box<Overrides>,
        /// Whether ocserv reads such settings files at all.
        readable: bool,
    },
    /// The Sites page's contents.
    SiteRules {
        view: Box<SitesView>,
    },
    /// The Alerts page's contents.
    Alerts {
        view: Box<AlertsView>,
    },
    /// A VPN user's onboarding kit, after a change that set their password
    /// or authenticator key. The helper keeps neither, so this is the only
    /// time either is shown.
    Kit {
        kit: Box<Kit>,
    },
    /// The request was understood but its input is not acceptable.
    Invalid {
        message: String,
    },
    /// The helper failed to carry out the request.
    Error {
        message: String,
    },
    /// The answer to a portal request.
    Portal {
        response: PortalResponse,
    },
}

/// The countries of the addresses an answer names, and the database that
/// placed them, whose makers a page showing them credits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Located {
    /// What the country database calls itself, as DBIP-Country-Lite.
    pub database: String,
    pub places: Vec<Place>,
}

/// The country the country database places an address in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Place {
    /// The address as the event or session gives it.
    pub address: String,
    /// The country's ISO 3166 code in capitals, and its name.
    pub code: String,
    pub name: String,
}

/// The country rules as the Bans page shows them, with the countries of
/// the events kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountryView {
    /// off, block or allow: the rule in force.
    pub rule: String,
    /// The listed countries in force, as codes in capitals.
    pub listed: Vec<String>,
    /// Whether the environment sets the rule, and the list, which the panel
    /// then cannot change.
    pub rule_from_env: bool,
    pub list_from_env: bool,
    /// Whether the firewall carries country rules: false on legacy
    /// iptables.
    pub enforceable: bool,
    /// What the country database calls itself, as DBIP-Country-Lite; or
    /// why it could not be read.
    pub database: Result<String, String>,
    /// Every country the database knows, by code, with its name.
    pub names: Vec<(String, String)>,
    /// Failed sign-ins of the events kept by the country of their address,
    /// most first; an address in no country counts under none.
    pub failed: Vec<(Option<String>, u64)>,
    /// The countries VPN users connected from in the events kept.
    pub connected: Vec<String>,
    /// The hours of events kept.
    pub hours: u64,
    /// When the database in use was built, in Unix seconds; 0 without one.
    pub built: u64,
    /// The account ID of the MaxMind key in force, never its license key,
    /// and whether the environment sets the key.
    pub maxmind_account: Option<String>,
    pub maxmind_from_env: bool,
    /// Whether a GeoLite2 download is under way, and the last one's time
    /// and outcome.
    pub maxmind_busy: bool,
    pub maxmind_last: Option<(u64, Result<String, String>)>,
}

/// A VPN sign-in the location checks refused, as the VPN users page lists
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedSignIn {
    pub user: String,
    pub from: String,
    /// Unix seconds.
    pub time: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    /// Whether the place is among the user's usual places now, as once an
    /// admin allowed it.
    pub known: bool,
}

/// The location checks as the Bans page shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocationView {
    /// Whether the checks are on, and every how many hours their databases
    /// are checked for newer copies: the setting in force.
    pub on: bool,
    pub refresh_hours: u64,
    /// Whether LOCATION_CHECKS and LOCATION_REFRESH_HOURS set them, which
    /// the panel then cannot change.
    pub on_from_env: bool,
    pub refresh_from_env: bool,
    /// The city database and the network database read now; none while the
    /// checks are off or before the first download.
    pub city: Option<Edition>,
    pub networks: Option<Edition>,
    /// When the databases were last checked for newer copies, and what that
    /// installed, or why it failed.
    pub last: Option<(u64, Result<Vec<String>, String>)>,
}

/// What the Alerts page shows an admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsView {
    /// The topics the admin chose.
    pub topics: Vec<Topic>,
    /// Whether the admin is an owner, whose sign-in alerts cover every
    /// admin's and who sets the mail server.
    pub owner: bool,
    pub channels: Vec<ChannelView>,
    pub max_channels: usize,
    /// Whether a mail server is set, from the environment or the panel.
    pub mail_set: bool,
    pub mail_from_env: bool,
    /// The mail server in force without its password, for an owner.
    pub mail: Option<MailView>,
    /// Whether the country rules drop anything: on, and on nftables.
    pub country_rules_on: bool,
}

/// One of an admin's channels as the Alerts page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelView {
    pub id: u32,
    /// The kind in words, and what may be shown of where it goes.
    pub kind: String,
    pub label: String,
    /// Whether its messages travel without encryption.
    pub unencrypted: bool,
    pub added: u64,
    pub status: ChannelStatus,
}

/// The mail server as an owner sees it: everything but the password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailView {
    /// The server in words.
    pub label: String,
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub user: Option<String>,
    pub password_set: bool,
    pub from: String,
}

/// What the Sites page shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SitesView {
    pub rules: Vec<Rule>,
    /// Each user or group that publishes networks.
    pub sites: Vec<Site>,
    /// The groups a rule can name: those the password file names or that
    /// have a settings file.
    pub groups: Vec<String>,
    /// Whether the firewall checks where tunnel traffic comes from, without
    /// which the rules open nothing.
    pub checked: bool,
    /// Whether the firewall is legacy iptables, which carries out only the
    /// rules between networks.
    pub iptables: bool,
    /// Whether CLIENT_TO_CLIENT lets every tunnel reach every other.
    pub client_to_client: bool,
    /// Whether clients send only the networks the server routes to them
    /// through the tunnel.
    pub split: bool,
}

/// A user or group that publishes networks, as the Sites page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub owner: Owner,
    pub name: String,
    pub networks: Vec<String>,
    /// Whether its networks reach beyond the VPN.
    pub egress: bool,
    /// Whether one of its sessions is connected now.
    pub connected: bool,
}

/// Reads one message. `Ok(None)` means the peer closed the connection
/// between messages; a connection closed inside a message is an error.
#[cfg(any(unix, test))]
pub fn read_message(reader: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut first = [0u8; 1];
    let count = loop {
        match reader.read(&mut first) {
            Ok(count) => break count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("a message could not be read: {error}")),
        }
    };
    if count == 0 {
        return Ok(None);
    }
    let mut rest = [0u8; 3];
    reader
        .read_exact(&mut rest)
        .map_err(|error| format!("a message length could not be read: {error}"))?;
    let length = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]);
    if length > MAX_MESSAGE {
        return Err(format!(
            "a message of {length} bytes is longer than the {MAX_MESSAGE} bytes accepted"
        ));
    }
    let size = usize::try_from(length)
        .map_err(|error| format!("a message length does not fit in memory: {error}"))?;
    let mut body = vec![0u8; size];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("a message body could not be read: {error}"))?;
    Ok(Some(body))
}

/// Writes one message.
#[cfg(any(unix, test))]
pub fn write_message(writer: &mut impl Write, body: &[u8]) -> Result<(), String> {
    let length = u32::try_from(body.len())
        .map_err(|error| format!("a message is too long to send: {error}"))?;
    if length > MAX_MESSAGE {
        return Err(format!(
            "a message of {length} bytes is longer than the {MAX_MESSAGE} bytes accepted"
        ));
    }
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(body))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("a message could not be sent: {error}"))
}

/// Encodes a request or response as JSON.
#[cfg(any(unix, test))]
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("a message could not be encoded: {error}"))
}

/// Decodes a request or response from JSON.
#[cfg(any(unix, test))]
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes)
        .map_err(|error| format!("a message could not be decoded: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn messages_round_trip() {
        let mut wire = Vec::new();
        write_message(&mut wire, b"{\"op\":\"ping\"}").unwrap();
        write_message(&mut wire, b"second").unwrap();
        let mut reader = Cursor::new(wire);
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            b"{\"op\":\"ping\"}"
        );
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), b"second");
        assert_eq!(read_message(&mut reader).unwrap(), None);
    }

    #[test]
    fn a_connection_cut_inside_a_message_is_an_error() {
        let mut wire = Vec::new();
        write_message(&mut wire, b"complete message").unwrap();
        for cut in [1, 3, 6] {
            let mut reader = Cursor::new(wire[..cut].to_vec());
            assert!(read_message(&mut reader).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn a_vpn_sign_in_is_read_from_the_connect_variables() {
        let read = |variables: &[(&str, &str)]| {
            VpnSignIn::from_script(|name: &str| {
                variables
                    .iter()
                    .find(|(key, _value)| *key == name)
                    .map(|(_key, value)| (*value).to_owned())
            })
        };
        let full = [
            ("USERNAME", "alex"),
            ("IP_REAL", "203.0.113.9"),
            ("ID", "4242"),
            ("DEVICE_TYPE", "iPhone14,2"),
            ("DEVICE_PLATFORM", "apple-ios"),
            ("USER_AGENT", "AnyConnect iPhone 4.10"),
        ];
        assert_eq!(
            read(&full).unwrap(),
            VpnSignIn {
                user: "alex".to_owned(),
                from: "203.0.113.9".to_owned(),
                session: Some(4242),
                devices: vec![
                    "iPhone14,2 on apple-ios".to_owned(),
                    "AnyConnect iPhone 4.10".to_owned()
                ],
            }
        );
        let bare = [
            ("USERNAME", "sam"),
            ("IP_REAL", "198.51.100.7"),
            ("DEVICE_PLATFORM", "linux-64"),
            ("DEVICE_TYPE", ""),
        ];
        assert_eq!(
            read(&bare).unwrap(),
            VpnSignIn {
                user: "sam".to_owned(),
                from: "198.51.100.7".to_owned(),
                session: None,
                devices: vec!["linux-64".to_owned()],
            }
        );
        assert!(read(&[("IP_REAL", "198.51.100.7")]).is_err());
        assert!(read(&[("USERNAME", "sam")]).is_err());
        assert!(
            read(&[
                ("USERNAME", "sam"),
                ("IP_REAL", "198.51.100.7"),
                ("ID", "x")
            ])
            .unwrap_err()
            .contains("ID is not a whole number")
        );
    }

    #[test]
    fn oversized_messages_are_refused_unread() {
        let mut reader = Cursor::new((MAX_MESSAGE + 1).to_be_bytes().to_vec());
        assert!(read_message(&mut reader).is_err());
        let mut wire = Vec::new();
        let too_long = vec![0u8; (MAX_MESSAGE + 1) as usize];
        assert!(write_message(&mut wire, &too_long).is_err());
        assert!(wire.is_empty());
    }

    #[test]
    fn requests_have_a_stable_json_form() {
        let login = Request::Login {
            name: "alex".to_owned(),
            password: "pw".to_owned(),
            from: "192.168.1.20".to_owned(),
        };
        let json = String::from_utf8(encode(&login).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"op":"login","name":"alex","password":"pw","from":"192.168.1.20"}"#
        );
        assert_eq!(decode::<Request>(json.as_bytes()).unwrap(), login);
        assert_eq!(
            decode::<Request>(br#"{"op":"ping"}"#).unwrap(),
            Request::Ping
        );
    }

    #[test]
    fn unknown_operations_and_fields_are_refused() {
        assert!(decode::<Request>(br#"{"op":"delete_everything"}"#).is_err());
        assert!(decode::<Request>(br#"{"op":"logout","session":"t","extra":1}"#).is_err());
        assert!(decode::<Request>(br#"{"op":"logout"}"#).is_err());
        assert!(decode::<Request>(b"not json").is_err());
    }

    #[test]
    fn responses_round_trip() {
        let signed_in = Response::SignedIn {
            session: "s".to_owned(),
            csrf: "c".to_owned(),
            admin: "alex".to_owned(),
            role: Role::Owner,
            scope: Scope::Enrollment,
            must_change_password: true,
            expires: 42,
        };
        let json = encode(&signed_in).unwrap();
        assert_eq!(decode::<Response>(&json).unwrap(), signed_in);
        let text = String::from_utf8(json).unwrap();
        assert!(text.contains(r#""status":"signed_in""#), "{text}");
        assert!(text.contains(r#""scope":"enrollment""#), "{text}");
        assert!(text.contains(r#""role":"owner""#), "{text}");
    }
}
