//! Admin alerts: the events each admin wants to hear about and the channels
//! that carry them, the panel's mail server for email, the outbox that
//! combines a minute's alerts into one message per channel and tries each
//! message three times, and the country rules' drops counted toward the
//! daily summary. What admins chose and the mail server live in alerts.json
//! in the panel's data directory, the day's drops in country-drops.json
//! beside it, both readable by root only; the outbox lives in memory.
//! `alert_send` does the sending.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::config::Host;
use crate::net::Network;
use crate::{clock, files, store, units};

/// The version of alerts.json this program reads and writes.
const FORMAT_VERSION: u32 = 1;

/// The most channels one admin may add.
pub const MAX_CHANNELS: usize = 10;

/// Seconds after a message goes to a channel during which more alerts for
/// it wait, to go together in the next message.
pub const COMBINE_SECONDS: u64 = 60;

/// Seconds after a message's first try at which its second and third tries
/// start; a message whose third try fails is given up.
pub const RETRY_AFTER: [u64; 2] = [60, 600];

/// How long one try may wait to connect, and how long it may take in all.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TRY_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest text of one message, in characters: Discord's limit, the
/// smallest of the services alerts go to.
pub const MAX_TEXT: usize = 2000;

/// The most alerts one message holds; those after them are only counted.
const MAX_LINES: usize = 50;

/// The longest URL an admin may enter.
const MAX_URL: usize = 2048;

/// The ntfy server a channel uses when the admin names none.
pub const NTFY_SH: &str = "https://ntfy.sh";

const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

/// The networks an http:// URL may reach: private, shared and link-local
/// addresses, where an alert stays on the admin's own networks.
const PRIVATE: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

/// What an alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    /// An address the firewall blocked after repeated bans.
    Blocks,
    /// A sign-in to the panel from outside the trusted networks.
    SignIns,
    /// What the country rules dropped the day before, once a day.
    CountryDrops,
    /// A sign-in the location checks refused or flagged, or a VPN sign-in
    /// they could not check.
    Locations,
}

impl Topic {
    pub const ALL: [Topic; 4] = [
        Topic::Blocks,
        Topic::SignIns,
        Topic::CountryDrops,
        Topic::Locations,
    ];

    /// The topic's name in forms and the audit log.
    pub fn key(self) -> &'static str {
        match self {
            Topic::Blocks => "blocks",
            Topic::SignIns => "sign_ins",
            Topic::CountryDrops => "country_drops",
            Topic::Locations => "locations",
        }
    }

    pub fn parse(key: &str) -> Option<Topic> {
        Topic::ALL.into_iter().find(|topic| topic.key() == key)
    }

    /// The topic in words, for the audit log.
    pub fn words(self) -> &'static str {
        match self {
            Topic::Blocks => "automatic blocks",
            Topic::SignIns => "sign-ins from outside the trusted networks",
            Topic::CountryDrops => "the country rules' daily drops",
            Topic::Locations => "sign-ins the location checks refused, flagged or could not check",
        }
    }

    /// What a message holding one alert of the topic is titled.
    fn heading(self) -> &'static str {
        match self {
            Topic::Blocks => "automatic block",
            Topic::SignIns => "sign-in from outside",
            Topic::CountryDrops => "country rule drops",
            Topic::Locations => "location check",
        }
    }
}

/// Text that is never shown or logged in full once it is saved: a token, a
/// password, or a URL or topic name that works as one. Its `Debug` leaves
/// it out, and it is wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(text: String) -> Secret {
        Secret(text)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Its last four characters after an ellipsis, when it is long enough
    /// that they give nothing away, so an admin can tell two apart.
    pub fn hint(&self) -> String {
        let count = self.0.chars().count();
        if count < 12 {
            return "…".to_owned();
        }
        let tail: String = self.0.chars().skip(count - 4).collect();
        format!("…{tail}")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(hidden)")
    }
}

/// Where one channel's messages go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// A topic on ntfy.sh or on the admin's own ntfy server, with the access
    /// token a protected topic needs. On ntfy.sh the topic's name is what
    /// keeps others from reading it.
    Ntfy {
        server: String,
        topic: Secret,
        token: Option<Secret>,
    },
    /// A Telegram chat, through the admin's own bot.
    Telegram { token: Secret, chat: String },
    /// A URL alerts are posted to: Discord, Slack, Gotify, Home Assistant
    /// and the like. Its path or query usually holds a token.
    Webhook { url: Secret },
    /// An email address, through the panel's mail server.
    Email { address: String },
}

impl Target {
    /// The channel's kind in words.
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Ntfy { .. } => "ntfy",
            Target::Telegram { .. } => "Telegram",
            Target::Webhook { .. } => "webhook",
            Target::Email { .. } => "email",
        }
    }

    /// The channel's kind in words after its article: "an ntfy".
    pub fn kind_with_article(&self) -> &'static str {
        match self {
            Target::Ntfy { .. } => "an ntfy",
            Target::Telegram { .. } => "a Telegram",
            Target::Webhook { .. } => "a webhook",
            Target::Email { .. } => "an email",
        }
    }

    /// What the Alerts page and the audit log show of it: enough to tell
    /// channels apart, and no secret in full.
    pub fn label(&self) -> String {
        match self {
            Target::Ntfy {
                server,
                topic,
                token,
            } => {
                let token = match token {
                    Some(_token) => ", with an access token",
                    None => "",
                };
                format!("{}, topic {}{token}", authority_of(server), topic.hint())
            }
            Target::Telegram { chat, .. } => format!("chat {chat}"),
            Target::Webhook { url } => format!("{} {}", authority_of(url.expose()), url.hint()),
            Target::Email { address } => address.clone(),
        }
    }

    /// Whether its messages travel without encryption: an http:// URL, which
    /// only reaches private addresses.
    pub fn unencrypted(&self) -> bool {
        match self {
            Target::Ntfy { server, .. } => server.starts_with("http://"),
            Target::Webhook { url } => url.expose().starts_with("http://"),
            Target::Telegram { .. } | Target::Email { .. } => false,
        }
    }
}

/// The host and port of `url`, up to its path: the part that may be shown.
fn authority_of(url: &str) -> &str {
    let after = match url.split_once("://") {
        Some((_scheme, after)) => after,
        None => url,
    };
    match after.find(['/', '?', '#']) {
        Some(end) => &after[..end],
        None => after,
    }
}

/// One channel an admin added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub id: u32,
    pub target: Target,
    /// Unix time it was added.
    pub added: u64,
}

/// What one admin chose: the topics that reach them, and where.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub topics: BTreeSet<Topic>,
    pub channels: Vec<Channel>,
}

/// How the panel's mail server is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// TLS from the first byte, usually on port 465.
    Tls,
    /// A plain connection that turns to TLS before anything is sent,
    /// usually on port 587.
    Starttls,
    /// No encryption, to a relay that takes no password, usually on port 25.
    Plain,
}

impl Security {
    pub const ALL: [Security; 3] = [Security::Tls, Security::Starttls, Security::Plain];

    pub fn key(self) -> &'static str {
        match self {
            Security::Tls => "tls",
            Security::Starttls => "starttls",
            Security::Plain => "plain",
        }
    }

    pub fn parse(key: &str) -> Option<Security> {
        Security::ALL
            .into_iter()
            .find(|security| security.key() == key)
    }

    pub fn default_port(self) -> u16 {
        match self {
            Security::Tls => 465,
            Security::Starttls => 587,
            Security::Plain => 25,
        }
    }

    pub fn words(self) -> &'static str {
        match self {
            Security::Tls => "TLS",
            Security::Starttls => "STARTTLS",
            Security::Plain => "no encryption",
        }
    }
}

/// The mail server email alerts go through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailServer {
    pub host: String,
    pub port: u16,
    pub security: Security,
    /// The sign-in, which a plain connection never carries.
    pub user: Option<String>,
    pub password: Option<Secret>,
    /// The address alerts come from.
    pub from: String,
}

impl MailServer {
    /// The server in words, without its password.
    pub fn label(&self) -> String {
        let user = match &self.user {
            Some(user) => format!(", signing in as {user}"),
            None => String::new(),
        };
        format!(
            "{}:{} with {}{user}, from {}",
            self.host,
            self.port,
            self.security.words(),
            self.from
        )
    }
}

/// Checks a mail server: a host, a port, a sign-in given in full or not at
/// all and never over a plain connection, and a From address.
pub fn check_mail(server: &MailServer) -> Result<(), String> {
    Host::parse(&server.host)
        .map_err(|error| format!("the mail server's host is not valid: {error}"))?;
    if server.port == 0 {
        return Err("the mail server's port is a number from 1 to 65535".to_owned());
    }
    match (&server.user, &server.password) {
        (None, None) => {}
        (Some(user), Some(password)) => {
            if server.security == Security::Plain {
                return Err(
                    "a plain connection would send the password unencrypted; use TLS or \
                     STARTTLS, or leave the user name and password out for a relay that takes \
                     none"
                        .to_owned(),
                );
            }
            if user.is_empty()
                || user.len() > 256
                || user.chars().any(|character| character.is_control())
            {
                return Err("the user name is 1 to 256 characters, without line breaks".to_owned());
            }
            let password = password.expose();
            if password.is_empty()
                || password.len() > 1024
                || password.chars().any(|character| character.is_control())
            {
                return Err("the password is 1 to 1024 characters, without line breaks".to_owned());
            }
        }
        (Some(_user), None) => {
            return Err("give the password with the user name, or neither".to_owned());
        }
        (None, Some(_password)) => {
            return Err("give the user name with the password, or neither".to_owned());
        }
    }
    check_address(&server.from).map_err(|error| format!("the From address is not valid: {error}"))
}

/// Checks an email address as lettre will send to it.
pub fn check_address(address: &str) -> Result<(), String> {
    if address.len() > 254 {
        return Err("an email address is at most 254 characters".to_owned());
    }
    match address.parse::<lettre::Address>() {
        Ok(_parsed) => Ok(()),
        Err(error) => Err(format!("'{address}' is not an email address: {error}")),
    }
}

/// The mail server PANEL_SMTP_HOST and the variables beside it give, which
/// wins over the one the panel saved. PANEL_SMTP_SECURITY is `tls`,
/// `starttls` or `plain`, and `starttls` when unset; PANEL_SMTP_PORT is the
/// usual port of that security when unset.
pub fn environment_mail<F>(get: &F) -> Result<Option<MailServer>, String>
where
    F: Fn(&str) -> Option<OsString>,
{
    let text = |name: &'static str| {
        crate::config::text(get, name)
            .map_err(|error| error.to_string())
            .map(|value| value.map(|value| value.trim().to_owned()))
    };
    let Some(host) = text("PANEL_SMTP_HOST")? else {
        for name in [
            "PANEL_SMTP_PORT",
            "PANEL_SMTP_SECURITY",
            "PANEL_SMTP_USER",
            "PANEL_SMTP_PASSWORD",
            "PANEL_SMTP_FROM",
        ] {
            if text(name)?.is_some() {
                return Err(format!("{name} is set without PANEL_SMTP_HOST"));
            }
        }
        return Ok(None);
    };
    let security = match text("PANEL_SMTP_SECURITY")? {
        None => Security::Starttls,
        Some(value) => Security::parse(&value.to_ascii_lowercase()).ok_or_else(|| {
            format!("PANEL_SMTP_SECURITY: '{value}' is not tls, starttls or plain")
        })?,
    };
    let port = match text("PANEL_SMTP_PORT")? {
        None => security.default_port(),
        Some(value) => port_number(&value).map_err(|error| format!("PANEL_SMTP_PORT: {error}"))?,
    };
    let Some(from) = text("PANEL_SMTP_FROM")? else {
        return Err(
            "PANEL_SMTP_FROM is not set, but PANEL_SMTP_HOST is: give the address alerts come \
             from"
                .to_owned(),
        );
    };
    let password =
        crate::config::text(get, "PANEL_SMTP_PASSWORD").map_err(|error| error.to_string())?;
    let server = MailServer {
        host,
        port,
        security,
        user: text("PANEL_SMTP_USER")?,
        password: password.map(Secret::new),
        from,
    };
    check_mail(&server).map_err(|error| format!("PANEL_SMTP_HOST and the rest: {error}"))?;
    Ok(Some(server))
}

/// A port number from 1 to 65535, written in decimal digits only.
pub fn port_number(text: &str) -> Result<u16, String> {
    let refused = || format!("'{text}' is not a whole number from 1 to 65535");
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    match text.parse::<u16>() {
        Ok(0) => Err(refused()),
        Ok(port) => Ok(port),
        Err(error) => Err(format!("{} ({error})", refused())),
    }
}

/// Whether `address` is on a private, shared or link-local network.
pub fn is_private(address: IpAddr) -> Result<bool, String> {
    let address = address.to_canonical();
    for text in PRIVATE {
        if Network::parse(text)?.contains(address) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// An ntfy server or webhook URL, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub secure: bool,
    pub host: Host,
    pub port: u16,
}

/// Checks an ntfy server or webhook URL: https:// anywhere, or http:// to a
/// host on private networks, and no user name or password in it. A host
/// name behind http:// is resolved when a message is sent, not here.
pub fn parse_url(text: &str) -> Result<Url, String> {
    if text.len() > MAX_URL {
        return Err(format!("a URL is at most {MAX_URL} characters"));
    }
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("a URL has no spaces or line breaks".to_owned());
    }
    let (secure, after) = if let Some(after) = text.strip_prefix("https://") {
        (true, after)
    } else if let Some(after) = text.strip_prefix("http://") {
        (false, after)
    } else {
        return Err("give the URL with https:// or http:// at the start".to_owned());
    };
    let end = match after.find(['/', '?', '#']) {
        Some(end) => end,
        None => after.len(),
    };
    let authority = &after[..end];
    if after[end..].contains('#') {
        return Err("leave the part after # out of the URL".to_owned());
    }
    if authority.contains('@') {
        return Err(
            "leave any user name and password out of the URL; an ntfy access token has a field \
             of its own"
                .to_owned(),
        );
    }
    let (host_text, port_text) = match authority.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((inside, "")) => (inside, None),
            Some((inside, after)) => match after.strip_prefix(':') {
                Some(port) => (inside, Some(port)),
                None => return Err(format!("'{authority}' is not a host and port")),
            },
            None => {
                return Err(format!(
                    "'{authority}' opens an IPv6 address but never closes it"
                ));
            }
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let host = Host::parse(host_text).map_err(|error| format!("the URL's host: {error}"))?;
    let port = match port_text {
        None if secure => 443,
        None => 80,
        Some(port) => port_number(port).map_err(|error| format!("the URL's port: {error}"))?,
    };
    if !secure
        && let Host::Address(address) = &host
        && !is_private(*address)?
    {
        return Err(format!(
            "an http:// URL sends alerts unencrypted, so it may only reach private addresses, \
             and {address} is not one; use an https:// URL"
        ));
    }
    Ok(Url { secure, host, port })
}

/// A channel to an ntfy topic, from what an admin entered: the server,
/// ntfy.sh when empty; the topic; and an access token, none when empty.
pub fn ntfy(server: &str, topic: &str, token: &str) -> Result<Target, String> {
    let server = match server.trim().trim_end_matches('/') {
        "" => NTFY_SH.to_owned(),
        server => server.to_owned(),
    };
    parse_url(&server)?;
    let topic = topic.trim();
    if topic.is_empty()
        || topic.len() > 64
        || !topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("an ntfy topic is 1 to 64 letters, digits, hyphens and underscores".to_owned());
    }
    let token = match token.trim() {
        "" => None,
        token if token.len() > 256 || !token.bytes().all(|byte| byte.is_ascii_graphic()) => {
            return Err("an ntfy access token is up to 256 characters, without spaces".to_owned());
        }
        token => Some(Secret::new(token.to_owned())),
    };
    Ok(Target::Ntfy {
        server,
        topic: Secret::new(topic.to_owned()),
        token,
    })
}

/// A channel to a Telegram chat, from the bot's token as BotFather gives
/// it and the chat's number or a public channel's @name.
pub fn telegram(token: &str, chat: &str) -> Result<Target, String> {
    let token = token.trim();
    let valid_token = match token.split_once(':') {
        Some((bot, key)) => {
            !bot.is_empty()
                && bot.len() <= 20
                && bot.bytes().all(|byte| byte.is_ascii_digit())
                && (20..=100).contains(&key.len())
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }
        None => false,
    };
    if !valid_token {
        return Err(
            "a Telegram bot token is the bot's number, a colon and its key, as BotFather gives it"
                .to_owned(),
        );
    }
    let chat = chat.trim();
    let digits = match chat.strip_prefix('-') {
        Some(rest) => rest,
        None => chat,
    };
    let number = !digits.is_empty()
        && digits.len() <= 20
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    let channel = chat.strip_prefix('@').is_some_and(|name| {
        (5..=32).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    if !number && !channel {
        return Err(
            "a Telegram chat is its number, such as 123456789, or a channel's @name".to_owned(),
        );
    }
    Ok(Target::Telegram {
        token: Secret::new(token.to_owned()),
        chat: chat.to_owned(),
    })
}

/// A channel to a webhook URL.
pub fn webhook(url: &str) -> Result<Target, String> {
    let url = url.trim();
    parse_url(url)?;
    Ok(Target::Webhook {
        url: Secret::new(url.to_owned()),
    })
}

/// A channel to an email address.
pub fn email(address: &str) -> Result<Target, String> {
    let address = address.trim();
    check_address(address)?;
    Ok(Target::Email {
        address: address.to_owned(),
    })
}

/// Checks a target read from the file as one an admin entered would be.
fn check_target(target: &Target) -> Result<(), String> {
    let again = match target {
        Target::Ntfy {
            server,
            topic,
            token,
        } => {
            let token = match token {
                Some(token) => token.expose(),
                None => "",
            };
            ntfy(server, topic.expose(), token)?
        }
        Target::Telegram { token, chat } => telegram(token.expose(), chat)?,
        Target::Webhook { url } => webhook(url.expose())?,
        Target::Email { address } => email(address)?,
    };
    if again != *target {
        return Err(format!(
            "a {} channel is not written as the panel writes it",
            target.kind()
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertFile {
    version: u32,
    /// The ID the next channel gets.
    next_id: u32,
    admins: BTreeMap<String, Choice>,
    mail: Option<MailServer>,
}

/// One alert waiting in a message, or a test message when it has no topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub time: u64,
    pub topic: Option<Topic>,
    pub text: String,
}

/// How one try of a message went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tried {
    Sent,
    /// Why it failed, with no secret in it.
    Failed(String),
}

/// A message being tried.
#[derive(Debug)]
struct Attempt {
    lines: Vec<Line>,
    /// Alerts past MAX_LINES, counted but not held.
    overflow: usize,
    tries: u8,
    first: u64,
    due: u64,
    /// Whether the sender has it now.
    out: bool,
}

impl Attempt {
    fn alerts(&self) -> usize {
        self.lines.len() + self.overflow
    }
}

/// What the outbox holds for one channel.
#[derive(Debug, Default)]
struct Queue {
    trying: Option<Attempt>,
    waiting: Vec<Line>,
    overflow: usize,
    /// No new message starts before this time: a minute after the last.
    open_at: u64,
    last: Option<Last>,
}

impl Queue {
    fn push(&mut self, line: Line) {
        if self.waiting.len() < MAX_LINES {
            self.waiting.push(line);
        } else {
            self.overflow += 1;
        }
    }

    /// Moves the alerts waiting into the message being tried, as far as it
    /// holds them.
    fn absorb(&mut self) {
        let Some(attempt) = &mut self.trying else {
            return;
        };
        for line in self.waiting.drain(..) {
            if attempt.lines.len() < MAX_LINES {
                attempt.lines.push(line);
            } else {
                attempt.overflow += 1;
            }
        }
        attempt.overflow += self.overflow;
        self.overflow = 0;
    }
}

/// How a channel's last message went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Last {
    Sent {
        time: u64,
        alerts: usize,
    },
    Failed {
        time: u64,
        alerts: usize,
        error: String,
    },
}

/// What the Alerts page says of a channel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Alerts waiting for a message, or in the one being tried.
    pub pending: usize,
    /// When the next try starts; none while one is under way or nothing
    /// waits.
    pub due: Option<u64>,
    /// The try under way or next, once a message is out or has failed.
    pub trying: Option<u8>,
    pub last: Option<Last>,
}

/// A message due to go, as the sender takes it.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub channel: u32,
    pub admin: String,
    pub target: Target,
    /// The mail server, for an email channel.
    pub mail: Option<MailServer>,
    pub subject: String,
    pub text: String,
    pub alerts: usize,
    pub try_number: u8,
}

/// A message that is done, sent or given up, for the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub admin: String,
    pub kind: &'static str,
    pub label: String,
    pub alerts: usize,
    pub tries: u8,
    /// Why the last try failed, when the message was given up.
    pub error: Option<String>,
}

/// The country rules' drops counted toward one UTC day's summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drops {
    /// The day, as days since 1970-01-01 UTC.
    pub day: u64,
    pub packets: u64,
    pub bytes: u64,
}

/// What the country rules' counter said when it was read and reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counter {
    /// The rules are off or on legacy iptables, so there is no counter.
    Absent,
    /// What it counted since it was last read.
    Read { packets: u64, bytes: u64 },
    /// Why it could not be read.
    Unreadable(String),
}

/// What admins chose, the mail server, the outbox and the day's drops.
pub struct Alerts {
    path: PathBuf,
    file: AlertFile,
    environment_mail: Option<MailServer>,
    /// What messages call the panel: its host name.
    server: String,
    queues: BTreeMap<u32, Queue>,
    drops_path: PathBuf,
    drops: Drops,
    /// When the country rules' counter is next read: the next whole hour.
    next_fold: u64,
    /// Wakes the sender when an alert is raised.
    wake: Option<Sender<()>>,
}

impl Alerts {
    /// Reads alerts.json at `path` and the day's drops at `drops_path`;
    /// missing files are no choices and no drops. A file of another format
    /// version, with unknown fields, an admin name that is not canonical, a
    /// channel ID used twice or a target the panel would not write is
    /// refused, never repaired.
    pub fn open(
        path: &Path,
        drops_path: &Path,
        environment_mail: Option<MailServer>,
        server: String,
        wake: Option<Sender<()>>,
        now: u64,
    ) -> Result<Alerts, String> {
        let file = match fs::read(path) {
            Ok(bytes) => {
                let mut bytes = bytes;
                let parsed: Result<AlertFile, String> = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("{}: {error}", path.display()));
                bytes.zeroize();
                let file = parsed?;
                check_file(&file).map_err(|error| format!("{}: {error}", path.display()))?;
                file
            }
            Err(error) if error.kind() == ErrorKind::NotFound => AlertFile {
                version: FORMAT_VERSION,
                next_id: 1,
                admins: BTreeMap::new(),
                mail: None,
            },
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let drops = match fs::read(drops_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("{}: {error}", drops_path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => Drops {
                day: now / DAY,
                packets: 0,
                bytes: 0,
            },
            Err(error) => return Err(format!("{}: {error}", drops_path.display())),
        };
        Ok(Alerts {
            path: path.to_owned(),
            file,
            environment_mail,
            server,
            queues: BTreeMap::new(),
            drops_path: drops_path.to_owned(),
            drops,
            next_fold: (now / HOUR + 1) * HOUR,
            wake,
        })
    }

    fn save(&self) -> Result<(), String> {
        let mut json = serde_json::to_vec_pretty(&self.file)
            .map_err(|error| format!("{}: {error}", self.path.display()))?;
        let written = files::write_private(&self.path, &json);
        json.zeroize();
        written
    }

    /// What `admin` chose; none when they have chosen nothing.
    pub fn choice(&self, admin: &str) -> Option<&Choice> {
        self.file.admins.get(admin)
    }

    /// Replaces the topics that reach `admin`.
    pub fn set_topics(&mut self, admin: &str, topics: BTreeSet<Topic>) -> Result<(), String> {
        self.file.admins.entry(admin.to_owned()).or_default().topics = topics;
        self.save()
    }

    /// Adds a channel for `admin` and returns its ID, or why it was
    /// refused.
    pub fn add(
        &mut self,
        admin: &str,
        target: Target,
        now: u64,
    ) -> Result<Result<u32, String>, String> {
        let id = self.file.next_id;
        let choice = self.file.admins.entry(admin.to_owned()).or_default();
        if choice.channels.len() >= MAX_CHANNELS {
            return Ok(Err(format!(
                "you have {MAX_CHANNELS} channels, the most an admin may have; remove one first"
            )));
        }
        if choice
            .channels
            .iter()
            .any(|channel| channel.target == target)
        {
            return Ok(Err("you have that channel already".to_owned()));
        }
        let Some(next) = id.checked_add(1) else {
            return Err("the channel IDs have run out".to_owned());
        };
        choice.channels.push(Channel {
            id,
            target,
            added: now,
        });
        self.file.next_id = next;
        self.save()?;
        Ok(Ok(id))
    }

    /// Removes `admin`'s channel `id` and what waits for it; the channel,
    /// when they had it.
    pub fn remove(&mut self, admin: &str, id: u32) -> Result<Option<Channel>, String> {
        let Some(choice) = self.file.admins.get_mut(admin) else {
            return Ok(None);
        };
        let Some(index) = choice.channels.iter().position(|channel| channel.id == id) else {
            return Ok(None);
        };
        let removed = choice.channels.remove(index);
        self.queues.remove(&id);
        self.save()?;
        Ok(Some(removed))
    }

    /// Forgets everything `admin` chose, for an admin who was removed.
    pub fn forget(&mut self, admin: &str) -> Result<(), String> {
        let Some(choice) = self.file.admins.remove(admin) else {
            return Ok(());
        };
        for channel in &choice.channels {
            self.queues.remove(&channel.id);
        }
        self.save()
    }

    /// The mail server in force: the environment's, else the panel's.
    pub fn mail(&self) -> Option<&MailServer> {
        match &self.environment_mail {
            Some(server) => Some(server),
            None => self.file.mail.as_ref(),
        }
    }

    pub fn mail_from_environment(&self) -> bool {
        self.environment_mail.is_some()
    }

    /// The mail server the panel saved, which the environment's overrides.
    pub fn saved_mail(&self) -> Option<&MailServer> {
        self.file.mail.as_ref()
    }

    /// Replaces the panel's mail server, or removes it.
    pub fn set_mail(&mut self, server: Option<MailServer>) -> Result<(), String> {
        self.file.mail = server;
        self.save()
    }

    /// Queues `text` about `topic` for each channel of every admin who
    /// chose the topic and whom `reaches` lets hear of it, and wakes the
    /// sender; how many channels it went to.
    pub fn raise(
        &mut self,
        now: u64,
        topic: Topic,
        text: &str,
        reaches: &dyn Fn(&str) -> bool,
    ) -> usize {
        let mut queued = 0;
        for (admin, choice) in &self.file.admins {
            if !choice.topics.contains(&topic) || !reaches(admin) {
                continue;
            }
            for channel in &choice.channels {
                self.queues.entry(channel.id).or_default().push(Line {
                    time: now,
                    topic: Some(topic),
                    text: text.to_owned(),
                });
                queued += 1;
            }
        }
        if queued > 0 {
            self.wake();
        }
        queued
    }

    /// Queues a test message for `admin`'s channel `id` and wakes the
    /// sender; whether they have that channel.
    pub fn test(&mut self, admin: &str, id: u32, now: u64) -> bool {
        let owned = self
            .file
            .admins
            .get(admin)
            .is_some_and(|choice| choice.channels.iter().any(|channel| channel.id == id));
        if !owned {
            return false;
        }
        let text = format!(
            "A test message from the admin panel at {}, sent when you asked for it on the Alerts \
             page.",
            self.server
        );
        self.queues.entry(id).or_default().push(Line {
            time: now,
            topic: None,
            text,
        });
        self.wake();
        true
    }

    fn wake(&self) {
        if let Some(wake) = &self.wake
            && let Err(error) = wake.send(())
        {
            eprintln!("ocpanel helper: the alert sender could not be woken: {error}");
        }
    }

    /// The messages due at `now`, which the sender now has. A channel that
    /// may start a message starts one with what waits for it.
    pub fn take_due(&mut self, now: u64) -> Vec<Delivery> {
        let mail = self.mail().cloned();
        let owners: BTreeMap<u32, (String, Target)> = self
            .file
            .admins
            .iter()
            .flat_map(|(admin, choice)| {
                choice
                    .channels
                    .iter()
                    .map(move |channel| (channel.id, (admin.clone(), channel.target.clone())))
            })
            .collect();
        self.queues.retain(|id, _queue| owners.contains_key(id));
        let mut due = Vec::new();
        for (id, queue) in &mut self.queues {
            if queue.trying.is_none() && !queue.waiting.is_empty() && now >= queue.open_at {
                queue.trying = Some(Attempt {
                    lines: std::mem::take(&mut queue.waiting),
                    overflow: std::mem::take(&mut queue.overflow),
                    tries: 0,
                    first: now,
                    due: now,
                    out: false,
                });
            }
            if queue
                .trying
                .as_ref()
                .is_some_and(|attempt| attempt.tries > 0 && !attempt.out)
            {
                queue.absorb();
            }
            let Some(attempt) = &mut queue.trying else {
                continue;
            };
            if attempt.out || attempt.due > now {
                continue;
            }
            let Some((admin, target)) = owners.get(id) else {
                continue;
            };
            attempt.out = true;
            let (subject, text) = compose(&self.server, &attempt.lines, attempt.overflow);
            due.push(Delivery {
                channel: *id,
                admin: admin.clone(),
                target: target.clone(),
                mail: match target {
                    Target::Email { .. } => mail.clone(),
                    Target::Ntfy { .. } | Target::Telegram { .. } | Target::Webhook { .. } => None,
                },
                subject,
                text,
                alerts: attempt.alerts(),
                try_number: attempt.tries + 1,
            });
        }
        due
    }

    /// Records how the try of channel `channel`'s message went. A message
    /// that was sent, or whose last try failed, is done, and what to audit
    /// of it comes back; a failed try before the last is tried again later.
    pub fn finish(&mut self, now: u64, channel: u32, tried: Tried) -> Option<Report> {
        let (admin, target) = self.file.admins.iter().find_map(|(admin, choice)| {
            choice
                .channels
                .iter()
                .find(|known| known.id == channel)
                .map(|known| (admin.clone(), known.target.clone()))
        })?;
        let queue = self.queues.get_mut(&channel)?;
        let attempt = queue.trying.as_mut()?;
        attempt.out = false;
        attempt.tries += 1;
        let tries = attempt.tries;
        let alerts = attempt.alerts();
        let error = match tried {
            Tried::Sent => None,
            Tried::Failed(error) => match RETRY_AFTER.get(usize::from(tries) - 1) {
                Some(after) => {
                    attempt.due = attempt.first + after;
                    return None;
                }
                None => Some(error),
            },
        };
        queue.trying = None;
        queue.open_at = now + COMBINE_SECONDS;
        queue.last = Some(match &error {
            None => Last::Sent { time: now, alerts },
            Some(error) => Last::Failed {
                time: now,
                alerts,
                error: error.clone(),
            },
        });
        Some(Report {
            admin,
            kind: target.kind(),
            label: target.label(),
            alerts,
            tries,
            error,
        })
    }

    /// When the outbox next has a message due; none when nothing waits.
    pub fn next_due(&self) -> Option<u64> {
        self.queues
            .values()
            .filter_map(|queue| match &queue.trying {
                Some(attempt) if !attempt.out => Some(attempt.due),
                Some(_out) => None,
                None if !queue.waiting.is_empty() => Some(queue.open_at),
                None => None,
            })
            .min()
    }

    /// What the Alerts page says of channel `id`.
    pub fn status(&self, id: u32) -> Status {
        let Some(queue) = self.queues.get(&id) else {
            return Status::default();
        };
        let waiting = queue.waiting.len() + queue.overflow;
        match &queue.trying {
            Some(attempt) => Status {
                pending: attempt.alerts() + waiting,
                due: (!attempt.out).then_some(attempt.due),
                trying: (attempt.out || attempt.tries > 0).then_some(attempt.tries + 1),
                last: queue.last.clone(),
            },
            None => Status {
                pending: waiting,
                due: (waiting > 0).then_some(queue.open_at),
                trying: None,
                last: queue.last.clone(),
            },
        }
    }

    /// When the country rules' counter is next due to be read.
    pub fn next_fold(&self) -> u64 {
        self.next_fold
    }

    /// Adds what the country rules' counter counted since it was last read
    /// to the day's drops; on the first reading of a new UTC day, raises the
    /// summary of the day before for those `reaches` lets hear of it. A
    /// counter that could not be read adds nothing, and why comes back as
    /// the error once the day's drops are saved.
    pub fn fold(
        &mut self,
        now: u64,
        counter: Counter,
        reaches: &dyn Fn(&str) -> bool,
    ) -> Result<(), String> {
        self.next_fold = (now / HOUR + 1) * HOUR;
        let mut problem = None;
        match counter {
            Counter::Read { packets, bytes } => {
                self.drops.packets = self.drops.packets.saturating_add(packets);
                self.drops.bytes = self.drops.bytes.saturating_add(bytes);
            }
            Counter::Absent => {}
            Counter::Unreadable(error) => {
                problem = Some(format!(
                    "the country rules' drop counter could not be read: {error}"
                ));
            }
        }
        let today = now / DAY;
        if self.drops.day != today {
            if self.drops.packets > 0 {
                let text = drop_summary(&self.drops);
                self.raise(now, Topic::CountryDrops, &text, reaches);
            }
            self.drops = Drops {
                day: today,
                packets: 0,
                bytes: 0,
            };
        }
        let json = serde_json::to_vec(&self.drops)
            .map_err(|error| format!("{}: {error}", self.drops_path.display()))?;
        files::write_private(&self.drops_path, &json)?;
        match problem {
            Some(problem) => Err(problem),
            None => Ok(()),
        }
    }

    /// `admin`'s channel `id`, when they have it.
    pub fn channel(&self, admin: &str, id: u32) -> Option<&Channel> {
        self.file
            .admins
            .get(admin)?
            .channels
            .iter()
            .find(|channel| channel.id == id)
    }
}

/// Checks a file read back: its version, canonical admin names, channel
/// IDs below the next one and used once, at most MAX_CHANNELS each, and
/// targets and a mail server the panel would write.
fn check_file(file: &AlertFile) -> Result<(), String> {
    if file.version != FORMAT_VERSION {
        return Err(format!(
            "format version {} is not the version {FORMAT_VERSION} this panel reads",
            file.version
        ));
    }
    let mut ids = BTreeSet::new();
    for (admin, choice) in &file.admins {
        if store::canonical_name(admin)? != *admin {
            return Err(format!("the admin name '{admin}' is not in lower case"));
        }
        if choice.channels.len() > MAX_CHANNELS {
            return Err(format!("{admin} has more than {MAX_CHANNELS} channels"));
        }
        for channel in &choice.channels {
            if channel.id >= file.next_id || !ids.insert(channel.id) {
                return Err(format!(
                    "the channel ID {} is used twice or is not below the next ID",
                    channel.id
                ));
            }
            check_target(&channel.target)
                .map_err(|error| format!("{admin}'s channel {}: {error}", channel.id))?;
        }
    }
    if let Some(server) = &file.mail {
        check_mail(server).map_err(|error| format!("the mail server: {error}"))?;
    }
    Ok(())
}

/// The summary of a day's drops.
fn drop_summary(drops: &Drops) -> String {
    let day = clock::rfc3339(drops.day * DAY);
    let date = match day.get(..10) {
        Some(date) => date,
        None => day.as_str(),
    };
    let packets = match drops.packets {
        1 => "1 packet".to_owned(),
        packets => format!("{} packets", units::count(packets)),
    };
    format!(
        "The country rules dropped {packets} ({}) on {date} (UTC).",
        units::amount(drops.bytes)
    )
}

/// The hour and minute of `time`, UTC.
fn clock_time(time: u64) -> String {
    let text = clock::rfc3339(time);
    match text.get(11..16) {
        Some(time) => time.to_owned(),
        None => text,
    }
}

/// A message's subject and text: its alerts one to a line, with their UTC
/// times, as many as fit in MAX_TEXT, and how many more there were.
pub fn compose(server: &str, lines: &[Line], overflow: usize) -> (String, String) {
    let total = lines.len() + overflow;
    let subject = match (lines, overflow) {
        ([line], 0) => match line.topic {
            Some(topic) => format!("{server}: {}", topic.heading()),
            None => format!("{server}: test message"),
        },
        _ => format!("{server}: {total} alerts"),
    };
    let room = |shown: usize| match total - shown {
        0 => MAX_TEXT,
        unshown => MAX_TEXT - format!("\nand {unshown} more alerts").len(),
    };
    let mut text = String::new();
    let mut length = 0;
    let mut shown = 0;
    for line in lines {
        let entry = format!("{} UTC  {}", clock_time(line.time), line.text);
        let separator = usize::from(shown > 0);
        let entry_length = entry.chars().count();
        if length + separator + entry_length > room(shown + 1) {
            if shown == 0 {
                let cut: String = entry.chars().take(room(1) - 1).collect();
                text.push_str(&cut);
                text.push('…');
                shown = 1;
            }
            break;
        }
        if separator == 1 {
            text.push('\n');
        }
        text.push_str(&entry);
        length += separator + entry_length;
        shown += 1;
    }
    match total - shown {
        0 => {}
        1 => text.push_str("\nand 1 more alert"),
        unshown => text.push_str(&format!("\nand {unshown} more alerts")),
    }
    (subject, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    const NOW: u64 = 1_795_000_000;

    fn open_at(dir: &TestDir, now: u64) -> Alerts {
        Alerts::open(
            &dir.path().join("alerts.json"),
            &dir.path().join("country-drops.json"),
            None,
            "vpn.example.com".to_owned(),
            None,
            now,
        )
        .unwrap()
    }

    fn open(dir: &TestDir) -> Alerts {
        open_at(dir, NOW)
    }

    fn hook(n: u32) -> Target {
        webhook(&format!(
            "https://hooks.example.com/alerts/{n}-abcdefghijkl"
        ))
        .unwrap()
    }

    fn everyone(_admin: &str) -> bool {
        true
    }

    fn failed(why: &str) -> Tried {
        Tried::Failed(why.to_owned())
    }

    #[test]
    fn choices_survive_a_save_and_a_reload() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::Blocks, Topic::SignIns]))
            .unwrap();
        let id = alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        let topic = ntfy("", "panel-alerts-4f9c2b7a", "tk_abcdefghijklmnop").unwrap();
        alerts.add("alex", topic, NOW).unwrap().unwrap();
        let reloaded = open(&dir);
        let choice = reloaded.choice("alex").unwrap();
        assert_eq!(
            choice.topics,
            BTreeSet::from([Topic::Blocks, Topic::SignIns])
        );
        assert_eq!(choice.channels.len(), 2);
        assert_eq!(choice.channels[0].id, id);
        assert_eq!(
            choice.channels[1].target.label(),
            "ntfy.sh, topic …2b7a, with an access token"
        );
    }

    #[test]
    fn a_file_the_panel_would_not_write_is_refused() {
        let dir = TestDir::new();
        let path = dir.path().join("alerts.json");
        for bad in [
            r#"{"version":2,"next_id":1,"admins":{},"mail":null}"#,
            r#"{"version":1,"next_id":1,"admins":{},"mail":null,"extra":1}"#,
            r#"{"version":1,"next_id":1,"admins":{"Alex":{"topics":[],"channels":[]}},"mail":null}"#,
            r#"{"version":1,"next_id":2,"admins":{"alex":{"topics":[],"channels":[{"id":1,"added":0,"target":{"kind":"email","address":"a@example.com"}},{"id":1,"added":0,"target":{"kind":"email","address":"b@example.com"}}]}},"mail":null}"#,
            r#"{"version":1,"next_id":2,"admins":{"alex":{"topics":[],"channels":[{"id":1,"added":0,"target":{"kind":"webhook","url":"http://203.0.113.5/hook"}}]}},"mail":null}"#,
            "not json",
        ] {
            fs::write(&path, bad).unwrap();
            let opened = Alerts::open(
                &path,
                &dir.path().join("country-drops.json"),
                None,
                "vpn.example.com".to_owned(),
                None,
                NOW,
            );
            assert!(opened.is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn secrets_stay_in_the_root_only_file() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        let key = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
        let bot = telegram(&format!("123456789:{key}"), "-1001234567890").unwrap();
        alerts.add("alex", bot, NOW).unwrap().unwrap();
        let text = fs::read_to_string(dir.path().join("alerts.json")).unwrap();
        assert!(text.contains(key), "{text}");
        let shown = format!("{:?}", alerts.choice("alex").unwrap());
        assert!(!shown.contains(key), "{shown}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("alerts.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn channels_are_capped_and_never_twice() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        for n in 0..10 {
            alerts.add("alex", hook(n), NOW).unwrap().unwrap();
        }
        let refused = alerts.add("alex", hook(10), NOW).unwrap().unwrap_err();
        assert!(refused.contains("10 channels"), "{refused}");
        alerts.add("sam", hook(0), NOW).unwrap().unwrap();
        let again = alerts.add("sam", hook(0), NOW).unwrap().unwrap_err();
        assert!(again.contains("already"), "{again}");
    }

    #[test]
    fn channel_entries_are_checked() {
        assert!(ntfy("", "alerts", "").is_ok());
        assert!(ntfy("https://ntfy.example.com/", "alerts", "").is_ok());
        assert!(ntfy("", "two words", "").is_err());
        assert!(ntfy("", "", "").is_err());
        assert!(ntfy("ftp://ntfy.example.com", "alerts", "").is_err());
        assert!(ntfy("", "alerts", "has space").is_err());
        let token = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
        assert!(telegram(token, "123456789").is_ok());
        assert!(telegram(token, "@panel_alerts").is_ok());
        assert!(telegram(token, "me").is_err());
        assert!(telegram("123456789", "123456789").is_err());
        assert!(telegram("bot:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "1").is_err());
        assert!(email("alex@example.com").is_ok());
        assert!(email("not an address").is_err());
        assert!(email("alex@example.com\r\nBcc: mallory@example.com").is_err());
    }

    #[test]
    fn urls_are_https_or_http_to_private_networks() {
        for good in [
            "https://hooks.example.com/services/T0/B0/x",
            "https://203.0.113.5:8443/hook",
            "http://192.168.1.10:8123/api/webhook/panel",
            "http://10.0.0.2/message?token=abc",
            "http://[fd00::5]:8080/hook",
            "http://homeassistant.lan:8123/api/webhook/panel",
        ] {
            assert!(parse_url(good).is_ok(), "refused {good}");
        }
        for bad in [
            "http://203.0.113.5/hook",
            "http://[2001:db8::1]/hook",
            "http://127.0.0.1/hook",
            "https://user:pass@hooks.example.com/x",
            "https://hooks.example.com/x#part",
            "hooks.example.com/x",
            "https://hooks.example.com:0/x",
            "https://hooks.example.com:99999/x",
            "https://hooks.example.com/a b",
            "https://[fd00::5/hook",
        ] {
            assert!(parse_url(bad).is_err(), "accepted {bad}");
        }
        let url = parse_url("http://192.168.1.10:8123/api").unwrap();
        assert_eq!((url.secure, url.port), (false, 8123));
        assert!(webhook("http://192.168.1.10/x").unwrap().unencrypted());
        assert!(!hook(1).unencrypted());
    }

    #[test]
    fn labels_show_no_secret_in_full() {
        let bot = telegram("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "-100123").unwrap();
        assert_eq!(bot.label(), "chat -100123");
        let discord =
            webhook("https://discord.com/api/webhooks/1234/abcdefghijklmnopXYZ9").unwrap();
        assert_eq!(discord.label(), "discord.com …XYZ9");
        let short = ntfy("http://192.168.1.4", "short", "").unwrap();
        assert_eq!(short.label(), "192.168.1.4, topic …");
    }

    #[test]
    fn the_environments_mail_server_is_read_and_checked() {
        fn get(
            pairs: &'static [(&'static str, &'static str)],
        ) -> impl Fn(&str) -> Option<OsString> {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _value)| *key == name)
                    .map(|(_key, value)| OsString::from(*value))
            }
        }
        assert_eq!(environment_mail(&get(&[])).unwrap(), None);
        let server = environment_mail(&get(&[
            ("PANEL_SMTP_HOST", "smtp.example.com"),
            ("PANEL_SMTP_USER", "alerts@example.com"),
            ("PANEL_SMTP_PASSWORD", "correct horse"),
            ("PANEL_SMTP_FROM", "alerts@example.com"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!((server.port, server.security), (587, Security::Starttls));
        let tls = environment_mail(&get(&[
            ("PANEL_SMTP_HOST", "smtp.example.com"),
            ("PANEL_SMTP_SECURITY", "TLS"),
            ("PANEL_SMTP_FROM", "alerts@example.com"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(tls.port, 465);
        let plain = environment_mail(&get(&[
            ("PANEL_SMTP_HOST", "192.168.1.2"),
            ("PANEL_SMTP_SECURITY", "plain"),
            ("PANEL_SMTP_USER", "alerts"),
            ("PANEL_SMTP_PASSWORD", "hunter2-secret"),
            ("PANEL_SMTP_FROM", "alerts@example.com"),
        ]))
        .unwrap_err();
        assert!(plain.contains("unencrypted"), "{plain}");
        assert!(!plain.contains("hunter2-secret"), "{plain}");
        let lone_from = environment_mail(&get(&[("PANEL_SMTP_FROM", "alerts@example.com")]));
        assert!(lone_from.unwrap_err().contains("without PANEL_SMTP_HOST"));
        let no_from = environment_mail(&get(&[("PANEL_SMTP_HOST", "smtp.example.com")]));
        assert!(no_from.unwrap_err().contains("PANEL_SMTP_FROM"));
        let zero = environment_mail(&get(&[
            ("PANEL_SMTP_HOST", "smtp.example.com"),
            ("PANEL_SMTP_PORT", "0"),
            ("PANEL_SMTP_FROM", "alerts@example.com"),
        ]));
        assert!(zero.unwrap_err().contains("PANEL_SMTP_PORT"));
    }

    #[test]
    fn a_burst_becomes_one_message_a_minute() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::Blocks]))
            .unwrap();
        let id = alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        assert_eq!(alerts.raise(NOW, Topic::Blocks, "first", &everyone), 1);
        let first = alerts.take_due(NOW);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].subject, "vpn.example.com: automatic block");
        assert!(alerts.take_due(NOW).is_empty(), "a message went out twice");
        assert!(alerts.finish(NOW + 1, id, Tried::Sent).is_some());
        for n in 0..3 {
            alerts.raise(NOW + 10 + n, Topic::Blocks, &format!("more {n}"), &everyone);
        }
        assert!(alerts.take_due(NOW + 30).is_empty());
        assert_eq!(alerts.next_due(), Some(NOW + 61));
        let second = alerts.take_due(NOW + 61);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].alerts, 3);
        assert_eq!(second[0].subject, "vpn.example.com: 3 alerts");
        assert!(second[0].text.contains("more 2"), "{}", second[0].text);
        let report = alerts.finish(NOW + 62, id, Tried::Sent);
        assert_eq!(
            report.map(|report| (report.alerts, report.tries, report.error)),
            Some((3, 1, None))
        );
    }

    #[test]
    fn a_failed_message_is_tried_three_times_in_ten_minutes() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::SignIns]))
            .unwrap();
        let id = alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        alerts.raise(NOW, Topic::SignIns, "alex signed in", &everyone);
        alerts.take_due(NOW);
        assert_eq!(alerts.finish(NOW + 30, id, failed("timed out")), None);
        assert_eq!(alerts.status(id).trying, Some(2));
        assert!(alerts.take_due(NOW + 59).is_empty());
        alerts.raise(NOW + 45, Topic::SignIns, "and again", &everyone);
        let second = alerts.take_due(NOW + 60);
        assert_eq!(
            (second.len(), second[0].try_number, second[0].alerts),
            (1, 2, 2)
        );
        assert_eq!(alerts.finish(NOW + 90, id, failed("timed out")), None);
        assert!(alerts.take_due(NOW + 599).is_empty());
        let third = alerts.take_due(NOW + 600);
        assert_eq!(third[0].try_number, 3);
        let report = alerts.finish(NOW + 630, id, failed("status 503"));
        assert_eq!(
            report.map(|report| (report.tries, report.error)),
            Some((3, Some("status 503".to_owned())))
        );
        assert!(matches!(
            alerts.status(id).last,
            Some(Last::Failed { alerts: 2, .. })
        ));
        assert_eq!(alerts.next_due(), None);
    }

    #[test]
    fn alerts_reach_only_those_who_chose_them() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::SignIns]))
            .unwrap();
        alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        alerts.add("sam", hook(2), NOW).unwrap().unwrap();
        assert_eq!(alerts.raise(NOW, Topic::Blocks, "blocked", &everyone), 0);
        let only_sam = |admin: &str| admin == "sam";
        assert_eq!(
            alerts.raise(NOW, Topic::SignIns, "kai signed in", &only_sam),
            0
        );
        assert_eq!(
            alerts.raise(NOW, Topic::SignIns, "alex signed in", &everyone),
            1
        );
    }

    #[test]
    fn a_test_goes_only_to_the_admins_own_channel() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        let id = alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        assert!(!alerts.test("sam", id, NOW));
        assert!(alerts.test("alex", id, NOW));
        let due = alerts.take_due(NOW);
        assert_eq!(due[0].subject, "vpn.example.com: test message");
        assert!(due[0].text.contains("Alerts page"), "{}", due[0].text);
    }

    #[test]
    fn a_removed_channel_takes_its_queue_with_it() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::Blocks]))
            .unwrap();
        let id = alerts.add("alex", hook(1), NOW).unwrap().unwrap();
        alerts.raise(NOW, Topic::Blocks, "blocked", &everyone);
        assert!(alerts.remove("sam", id).unwrap().is_none());
        assert!(alerts.remove("alex", id).unwrap().is_some());
        assert!(alerts.take_due(NOW).is_empty());
        let kept = alerts.add("alex", hook(2), NOW).unwrap().unwrap();
        alerts.raise(NOW, Topic::Blocks, "blocked", &everyone);
        alerts.forget("alex").unwrap();
        assert!(alerts.take_due(NOW).is_empty());
        assert_eq!(alerts.status(kept), Status::default());
        assert!(open(&dir).choice("alex").is_none());
    }

    #[test]
    fn email_carries_the_mail_server_in_force() {
        let dir = TestDir::new();
        let mut alerts = open(&dir);
        let server = MailServer {
            host: "smtp.example.com".to_owned(),
            port: 587,
            security: Security::Starttls,
            user: Some("alerts@example.com".to_owned()),
            password: Some(Secret::new("correct horse".to_owned())),
            from: "alerts@example.com".to_owned(),
        };
        alerts.set_mail(Some(server.clone())).unwrap();
        let address = email("alex@example.com").unwrap();
        let id = alerts.add("alex", address, NOW).unwrap().unwrap();
        alerts.test("alex", id, NOW);
        assert_eq!(alerts.take_due(NOW)[0].mail, Some(server));
        assert_eq!(
            open(&dir).saved_mail().unwrap().label(),
            "smtp.example.com:587 with STARTTLS, signing in as alerts@example.com, from \
             alerts@example.com"
        );
    }

    #[test]
    fn mail_servers_are_checked() {
        let server = MailServer {
            host: "smtp.example.com".to_owned(),
            port: 25,
            security: Security::Plain,
            user: None,
            password: None,
            from: "alerts@example.com".to_owned(),
        };
        assert!(check_mail(&server).is_ok());
        let with_password = MailServer {
            user: Some("alerts".to_owned()),
            password: Some(Secret::new("correct horse".to_owned())),
            ..server.clone()
        };
        assert!(check_mail(&with_password).is_err());
        let tls = MailServer {
            security: Security::Tls,
            ..with_password.clone()
        };
        assert!(check_mail(&tls).is_ok());
        let half = MailServer { user: None, ..tls };
        assert!(check_mail(&half).is_err());
        let nobody = MailServer {
            from: "nobody".to_owned(),
            ..server.clone()
        };
        assert!(check_mail(&nobody).is_err());
        let spaced = MailServer {
            host: "bad host".to_owned(),
            ..server
        };
        assert!(check_mail(&spaced).is_err());
    }

    #[test]
    fn long_messages_are_cut_to_fit() {
        let lines: Vec<Line> = (0..40)
            .map(|n| Line {
                time: NOW,
                topic: Some(Topic::Blocks),
                text: format!("{n}: {}", "x".repeat(90)),
            })
            .collect();
        let (subject, text) = compose("vpn.example.com", &lines, 7);
        assert_eq!(subject, "vpn.example.com: 47 alerts");
        assert!(text.chars().count() <= MAX_TEXT, "{}", text.chars().count());
        assert!(text.ends_with("more alerts"), "{text}");
        let long = [Line {
            time: NOW,
            topic: None,
            text: "y".repeat(5000),
        }];
        let (_subject, text) = compose("vpn.example.com", &long, 0);
        assert_eq!(text.chars().count(), MAX_TEXT);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn the_days_drops_are_summed_and_summed_up_after_midnight() {
        let dir = TestDir::new();
        let day = NOW / DAY * DAY;
        let mut alerts = open_at(&dir, day + 10);
        alerts
            .set_topics("alex", BTreeSet::from([Topic::CountryDrops]))
            .unwrap();
        alerts.add("alex", hook(1), day).unwrap().unwrap();
        assert_eq!(alerts.next_fold(), day + HOUR);
        let read = |packets, bytes| Counter::Read { packets, bytes };
        alerts
            .fold(day + HOUR, read(1200, 64_000), &everyone)
            .unwrap();
        alerts
            .fold(day + 2 * HOUR, Counter::Absent, &everyone)
            .unwrap();
        let unreadable = Counter::Unreadable("nft is missing".to_owned());
        let error = alerts
            .fold(day + 2 * HOUR + 60, unreadable, &everyone)
            .unwrap_err();
        assert!(error.contains("nft is missing"), "{error}");
        assert_eq!(alerts.next_fold(), day + 3 * HOUR);
        alerts
            .fold(day + 3 * HOUR, read(34, 1_000), &everyone)
            .unwrap();
        assert!(alerts.take_due(day + 3 * HOUR).is_empty());
        let mut alerts = open_at(&dir, day + 4 * HOUR);
        alerts.fold(day + DAY + 5, read(6, 500), &everyone).unwrap();
        let due = alerts.take_due(day + DAY + 5);
        assert_eq!(due.len(), 1);
        assert!(
            due[0].text.contains("dropped 1,240 packets (65 kB) on"),
            "{}",
            due[0].text
        );
        assert!(
            alerts
                .finish(day + DAY + 6, due[0].channel, Tried::Sent)
                .is_some()
        );
        alerts
            .fold(day + 2 * DAY + 5, Counter::Absent, &everyone)
            .unwrap();
        assert!(
            alerts.take_due(day + 3 * DAY).is_empty(),
            "a day without drops was summed up"
        );
    }
}
