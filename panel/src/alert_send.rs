//! Sends alert messages: the sender thread's loop, and one message to ntfy,
//! Telegram, a webhook or an email address. A try waits at most
//! `alerts::CONNECT_TIMEOUT` to connect and `alerts::TRY_TIMEOUT` in all;
//! redirects are not followed, so a token never goes on to another host; an
//! http:// URL is used only while its host resolves to private addresses
//! alone; and no error carries a token, password or URL back.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::extension::ClientId;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::alerts::{
    self, CONNECT_TIMEOUT, Counter, Delivery, MailServer, Security, TRY_TIMEOUT, Target, Tried,
};
use crate::clock;
use crate::config::Host;
use crate::service::Service;

/// The longest part of a refusal quoted back, in characters.
const MAX_REASON: usize = 200;

/// The most of a refusal's answer that is read.
const MAX_ANSWER: u64 = 16 * 1024;

/// The longest message Discord takes, in characters.
const DISCORD_MAX: usize = 2000;

/// The sender thread, as the GeoLite2 thread downloads: sends the messages
/// the service has due, one at a time and outside its lock, with `send`;
/// reads the country rules' counter with `counter` on the hour; and waits
/// until the next of those is due, or the service wakes it for an alert. A
/// pass that fails is reported in the container log and tried again a
/// combining minute later.
pub fn keep_sending(
    service: &Mutex<Service>,
    woken: &Receiver<()>,
    counter: &dyn Fn() -> Counter,
    send: &dyn Fn(&Delivery) -> Result<(), String>,
) {
    let mut wait = Duration::ZERO;
    loop {
        match woken.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        wait = Duration::from_secs(alerts::COMBINE_SECONDS);
        match pass(service, counter, send) {
            Ok(next) => wait = next,
            Err(error) => eprintln!("ocpanel helper: alerts: {error}"),
        }
    }
}

/// One pass of the sender: the counter when it is due, then each message
/// due. Each message is finished whatever became of the others, and their
/// problems come back together; otherwise how long until the next pass.
fn pass(
    service: &Mutex<Service>,
    counter: &dyn Fn() -> Counter,
    send: &dyn Fn(&Delivery) -> Result<(), String>,
) -> Result<Duration, String> {
    let now = clock::now()?;
    let mut problems = Vec::new();
    if locked(service, |service| service.drops_due(now))? {
        let read = counter();
        if let Err(error) = locked(service, |service| service.fold_drops(now, read))? {
            problems.push(error);
        }
    }
    let started = Instant::now();
    for delivery in locked(service, |service| service.take_alerts(now))? {
        let tried = match send(&delivery) {
            Ok(()) => Tried::Sent,
            Err(error) => {
                eprintln!(
                    "ocpanel helper: try {} of a message of {} to {}'s {} channel failed: {error}",
                    delivery.try_number,
                    match delivery.alerts {
                        1 => "1 alert".to_owned(),
                        count => format!("{count} alerts"),
                    },
                    delivery.admin,
                    delivery.target.kind()
                );
                Tried::Failed(error)
            }
        };
        let finished = now + started.elapsed().as_secs();
        match locked(service, |service| {
            service.finish_alert(finished, delivery.channel, tried)
        }) {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => problems.push(error),
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let next = locked(service, |service| service.next_alert_wake())?;
    let now = now + started.elapsed().as_secs();
    Ok(Duration::from_secs(next.saturating_sub(now)))
}

/// What `work` gives with the service locked.
fn locked<T>(service: &Mutex<Service>, work: impl FnOnce(&mut Service) -> T) -> Result<T, String> {
    match service.lock() {
        Ok(mut service) => Ok(work(&mut service)),
        Err(poisoned) => Err(format!(
            "the helper's state is unusable after a failure: {poisoned}"
        )),
    }
}

/// Sends `delivery`, giving `hello` as the panel's name to a mail server;
/// why it failed, with no secret in the reason.
pub fn send(delivery: &Delivery, hello: &Host) -> Result<(), String> {
    let secrets = secrets(&delivery.target, delivery.mail.as_ref());
    let sent = match &delivery.target {
        Target::Ntfy {
            server,
            topic,
            token,
        } => ntfy(
            server,
            topic.expose(),
            token.as_ref().map(|token| token.expose()),
            delivery,
        ),
        Target::Telegram { token, chat } => telegram(token.expose(), chat, delivery),
        Target::Webhook { url } => webhook(url.expose(), delivery),
        Target::Email { address } => email(address, delivery, hello),
    };
    sent.map_err(|error| scrub(&error, &secrets))
}

/// The secrets a delivery holds, longest first, so that a URL is taken out
/// of an error before its path is.
fn secrets(target: &Target, mail: Option<&MailServer>) -> Vec<Zeroizing<String>> {
    let mut secrets = Vec::new();
    match target {
        Target::Ntfy { topic, token, .. } => {
            secrets.push(Zeroizing::new(topic.expose().to_owned()));
            if let Some(token) = token {
                secrets.push(Zeroizing::new(token.expose().to_owned()));
            }
        }
        Target::Telegram { token, .. } => secrets.push(Zeroizing::new(token.expose().to_owned())),
        Target::Webhook { url } => {
            secrets.push(Zeroizing::new(url.expose().to_owned()));
            secrets.push(Zeroizing::new(path_of(url.expose()).to_owned()));
        }
        Target::Email { .. } => {}
    }
    if let Some(password) = mail.and_then(|server| server.password.as_ref()) {
        secrets.push(Zeroizing::new(password.expose().to_owned()));
    }
    secrets.retain(|secret| secret.chars().count() >= 4);
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    secrets
}

/// `text` with every secret in it replaced by an ellipsis.
fn scrub(text: &str, secrets: &[Zeroizing<String>]) -> String {
    let mut text = text.to_owned();
    for secret in secrets {
        text = text.replace(secret.as_str(), "…");
    }
    text
}

/// What follows the host in `url`: its path and query.
fn path_of(url: &str) -> &str {
    let after = match url.split_once("://") {
        Some((_scheme, after)) => after,
        None => url,
    };
    match after.find(['/', '?']) {
        Some(start) => &after[start..],
        None => "",
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(TRY_TIMEOUT))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

/// Checks that `url` may be used now: https://, or http:// to a host whose
/// every address is private. A name is resolved here, when the message is
/// sent, so the check sees the addresses the message would go to.
fn reachable(url: &str) -> Result<(), String> {
    let parsed = alerts::parse_url(url)?;
    if parsed.secure {
        return Ok(());
    }
    let addresses: Vec<IpAddr> = match &parsed.host {
        Host::Address(address) => vec![*address],
        Host::Name(name) => (name.as_str(), parsed.port)
            .to_socket_addrs()
            .map_err(|error| format!("{name} cannot be resolved: {error}"))?
            .map(|socket| socket.ip())
            .collect(),
    };
    if addresses.is_empty() {
        return Err(format!(
            "{} resolves to no address",
            parsed.host.authority()
        ));
    }
    for address in addresses {
        if !alerts::is_private(address)? {
            return Err(format!(
                "an http:// URL may only reach private addresses, and {} resolves to {address}; \
                 use an https:// URL",
                parsed.host.authority()
            ));
        }
    }
    Ok(())
}

/// Posts `body` as JSON to `url`, with a bearer token when one is given; why
/// `service` refused it, when it did.
fn post(service: &str, url: &str, body: &Value, bearer: Option<&str>) -> Result<(), String> {
    let mut request = agent().post(url).header("Content-Type", "application/json");
    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let mut response = request
        .send(body.to_string())
        .map_err(|error| format!("{service} cannot be reached: {error}"))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let code = status.as_u16();
    if status.is_redirection() {
        return Err(format!(
            "{service} answered with a redirect ({code}), which is not followed; give the URL it \
             redirects to"
        ));
    }
    let answer = match response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
    {
        Ok(answer) => answer,
        Err(error) => {
            return Err(format!(
                "{service} answered with status {code}, and its answer cannot be read: {error}"
            ));
        }
    };
    Err(match reason(&answer) {
        Some(reason) => format!("{service} answered with status {code}: {reason}"),
        None => format!("{service} answered with status {code}"),
    })
}

/// The reason a refusal gives: Telegram's description, Discord's or
/// Gotify's message, ntfy's error, or the start of a plain-text answer.
fn reason(answer: &str) -> Option<String> {
    let answer = answer.trim();
    if answer.is_empty() {
        return None;
    }
    if !answer.starts_with('{') {
        return Some(cut(answer));
    }
    match serde_json::from_str::<Value>(answer) {
        Ok(value) => ["description", "message", "error"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .map(cut),
        Err(error) => Some(format!("an answer that is not valid JSON: {error}")),
    }
}

/// `text` on one line and at most MAX_REASON characters.
fn cut(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<&str>>().join(" ");
    match line.char_indices().nth(MAX_REASON) {
        Some((end, _character)) => format!("{}…", &line[..end]),
        None => line,
    }
}

fn ntfy(server: &str, topic: &str, token: Option<&str>, delivery: &Delivery) -> Result<(), String> {
    reachable(server)?;
    let body = json!({
        "topic": topic,
        "title": delivery.subject,
        "message": delivery.text,
        "tags": ["warning"],
    });
    post("ntfy", server, &body, token)
}

fn telegram(token: &str, chat: &str, delivery: &Delivery) -> Result<(), String> {
    let body = json!({
        "chat_id": chat,
        "text": format!("{}\n\n{}", delivery.subject, delivery.text),
        "link_preview_options": {"is_disabled": true},
    });
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    post("Telegram", &url, &body, None)
}

/// Whether `host` and `path` are a Discord webhook's.
fn is_discord(host: &str, path: &str) -> bool {
    matches!(
        host,
        "discord.com" | "discordapp.com" | "canary.discord.com" | "ptb.discord.com"
    ) && path.starts_with("/api/webhooks/")
}

/// `text` with Discord's markdown characters escaped.
fn discord_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if matches!(character, '\\' | '*' | '_' | '~' | '`' | '|') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// `text` with the three characters Slack reads as markup escaped.
fn slack_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The body a webhook gets: Discord's and Slack's own shapes for their
/// hosts, else a title, a message and both as one text, which Gotify, Home
/// Assistant, Mattermost and most others read.
fn webhook_body(host: &str, path: &str, delivery: &Delivery) -> Value {
    if is_discord(host, path) {
        let content = format!(
            "**{}**\n{}",
            discord_text(&delivery.subject),
            discord_text(&delivery.text)
        );
        let content = match content.char_indices().nth(DISCORD_MAX - 1) {
            Some((end, _character)) => format!("{}…", &content[..end]),
            None => content,
        };
        return json!({"content": content, "allowed_mentions": {"parse": []}});
    }
    if host == "hooks.slack.com" {
        let text = format!(
            "*{}*\n{}",
            slack_text(&delivery.subject),
            slack_text(&delivery.text)
        );
        return json!({ "text": text });
    }
    json!({
        "title": delivery.subject,
        "message": delivery.text,
        "text": format!("{}\n\n{}", delivery.subject, delivery.text),
    })
}

fn webhook(url: &str, delivery: &Delivery) -> Result<(), String> {
    reachable(url)?;
    let host = alerts::parse_url(url)?.host.authority();
    let body = webhook_body(&host, path_of(url), delivery);
    post("the webhook", url, &body, None)
}

/// The name a mail server is greeted with.
fn client_id(hello: &Host) -> ClientId {
    match hello {
        Host::Name(name) => ClientId::Domain(name.clone()),
        Host::Address(IpAddr::V4(address)) => ClientId::Ipv4(*address),
        Host::Address(IpAddr::V6(address)) => ClientId::Ipv6(*address),
    }
}

fn email(address: &str, delivery: &Delivery, hello: &Host) -> Result<(), String> {
    let Some(server) = &delivery.mail else {
        return Err(
            "no mail server is set for email alerts; an owner sets one on the Alerts page, or the \
             environment does"
                .to_owned(),
        );
    };
    let from: Mailbox = server
        .from
        .parse()
        .map_err(|error| format!("the From address {}: {error}", server.from))?;
    let to: Mailbox = address
        .parse()
        .map_err(|error| format!("the address {address}: {error}"))?;
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(delivery.subject.clone())
        .header(ContentType::TEXT_PLAIN)
        .body(delivery.text.clone())
        .map_err(|error| format!("the message cannot be written: {error}"))?;
    let builder = match server.security {
        Security::Tls => SmtpTransport::relay(&server.host),
        Security::Starttls => SmtpTransport::starttls_relay(&server.host),
        Security::Plain => Ok(SmtpTransport::builder_dangerous(&server.host)),
    }
    .map_err(|error| format!("the mail server {}: {error}", server.host))?;
    let mut builder = builder
        .port(server.port)
        .timeout(Some(CONNECT_TIMEOUT))
        .hello_name(client_id(hello));
    if let (Some(user), Some(password)) = (&server.user, &server.password) {
        builder = builder.credentials(Credentials::new(user.clone(), password.expose().to_owned()));
    }
    let transport = builder.build();
    let (answer, answered) = mpsc::channel();
    thread::Builder::new()
        .name("smtp".to_owned())
        .spawn(move || {
            let result = match transport.send(&message) {
                Ok(_response) => Ok(()),
                Err(error) => Err(error.to_string()),
            };
            if let Err(late) = answer.send(result) {
                eprintln!(
                    "ocpanel helper: a mail server answered after its try had timed out: {late}"
                );
            }
        })
        .map_err(|error| format!("the mail thread could not start: {error}"))?;
    match answered.recv_timeout(TRY_TIMEOUT) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("the mail server {}: {error}", server.host)),
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "the mail server {} did not finish within {} s",
            server.host,
            TRY_TIMEOUT.as_secs()
        )),
        Err(RecvTimeoutError::Disconnected) => {
            Err("the mail thread ended without an answer".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::Secret;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn delivery(target: Target) -> Delivery {
        Delivery {
            channel: 1,
            admin: "alex".to_owned(),
            target,
            mail: None,
            subject: "vpn.example.com: automatic block".to_owned(),
            text: "05:41 UTC  Blocked 198.51.100.9 for 1 day: banned 3 times within 1 day"
                .to_owned(),
            alerts: 1,
            try_number: 1,
        }
    }

    /// Answers one http request on a loopback port with `status` and
    /// `answer`, and hands back the request it read.
    fn http_once(status: &'static str, answer: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/hook/secret-path-1234",
            listener.local_addr().unwrap()
        );
        let (sender, received) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{answer}",
                answer.len()
            )
            .unwrap();
            sender.send(request).unwrap();
        });
        (url, received)
    }

    #[test]
    fn a_post_carries_json_and_the_bearer_token() {
        let (url, received) = http_once("200 OK", "{}");
        let body = json!({"topic": "alerts", "message": "hello"});
        post("ntfy", &url, &body, Some("tk_secret")).unwrap();
        let request = received.recv().unwrap();
        assert!(
            request.starts_with("POST /hook/secret-path-1234 HTTP/1.1\r\n"),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: application/json"),
            "{request}"
        );
        assert!(
            lower.contains("authorization: bearer tk_secret"),
            "{request}"
        );
        assert!(
            request.ends_with(r#"{"message":"hello","topic":"alerts"}"#),
            "{request}"
        );
    }

    #[test]
    fn a_refusal_says_why() {
        let (url, _received) = http_once(
            "401 Unauthorized",
            r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        );
        let error = post("Telegram", &url, &json!({}), None).unwrap_err();
        assert_eq!(error, "Telegram answered with status 401: Unauthorized");
        let (url, _received) = http_once("302 Found", "");
        let error = post("the webhook", &url, &json!({}), None).unwrap_err();
        assert!(error.contains("redirect (302)"), "{error}");
    }

    #[test]
    fn reasons_are_short_and_on_one_line() {
        assert_eq!(reason(""), None);
        assert_eq!(
            reason(r#"{"message": "Unknown Webhook", "code": 10015}"#).as_deref(),
            Some("Unknown Webhook")
        );
        assert_eq!(
            reason(r#"{"code":40101,"http":401,"error":"unauthorized"}"#).as_deref(),
            Some("unauthorized")
        );
        assert_eq!(reason(r#"{"other": 1}"#), None);
        assert!(reason("{broken").unwrap().contains("not valid JSON"));
        let page = format!("<html>\n  <body>{}</body>", "x".repeat(400));
        let short = reason(&page).unwrap();
        assert!(!short.contains('\n'));
        assert_eq!(short.chars().count(), MAX_REASON + 1);
    }

    #[test]
    fn errors_lose_their_secrets() {
        let url = "https://discord.com/api/webhooks/1234/abcdefghijklmnop";
        let target = Target::Webhook {
            url: Secret::new(url.to_owned()),
        };
        let scrubbed = scrub(
            &format!("bad uri {url}; then the path /api/webhooks/1234/abcdefghijklmnop alone"),
            &secrets(&target, None),
        );
        assert_eq!(scrubbed, "bad uri …; then the path … alone");
        let bot = Target::Telegram {
            token: Secret::new("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw".to_owned()),
            chat: "1".to_owned(),
        };
        let shown = scrub(
            "io: https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/x",
            &secrets(&bot, None),
        );
        assert_eq!(shown, "io: https://api.telegram.org/bot…/x");
    }

    #[test]
    fn http_reaches_only_private_addresses_when_sent() {
        assert!(reachable("http://192.168.1.10:8123/x").is_ok());
        assert!(reachable("https://203.0.113.5/x").is_ok());
        let public = reachable("http://203.0.113.5/x").unwrap_err();
        assert!(public.contains("private addresses"), "{public}");
        let loopback = reachable("http://localhost:8080/x").unwrap_err();
        assert!(loopback.contains("resolves to"), "{loopback}");
    }

    #[test]
    fn webhooks_get_the_shape_their_service_reads() {
        let message = delivery(Target::Webhook {
            url: Secret::new("https://example.com/x".to_owned()),
        });
        let discord = webhook_body("discord.com", "/api/webhooks/1/abc", &message);
        assert_eq!(discord["allowed_mentions"]["parse"], json!([]));
        let content = discord["content"].as_str().unwrap();
        assert!(content.starts_with("**vpn.example.com: automatic block**\n"));
        let slack = webhook_body("hooks.slack.com", "/services/T/B/x", &message);
        assert!(
            slack["text"]
                .as_str()
                .unwrap()
                .starts_with("*vpn.example.com")
        );
        let other = webhook_body("192.168.1.10:8123", "/api/webhook/panel", &message);
        assert_eq!(other["title"], "vpn.example.com: automatic block");
        assert!(other["text"].as_str().unwrap().contains("\n\n05:41 UTC"));
        assert_eq!(discord_text("a_b*c"), "a\\_b\\*c");
        assert_eq!(slack_text("<!channel> & co"), "&lt;!channel&gt; &amp; co");
        let long = Delivery {
            text: "z".repeat(3000),
            ..message
        };
        let cut = webhook_body("discord.com", "/api/webhooks/1/abc", &long);
        assert_eq!(
            cut["content"].as_str().unwrap().chars().count(),
            DISCORD_MAX
        );
    }

    /// A mail server on a loopback port that takes one message without
    /// encryption or a password, and hands back what it was given.
    fn smtp_once() -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, received) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer: TcpStream = stream;
            let mut said = String::new();
            writer
                .write_all(b"220 relay.example.com ESMTP\r\n")
                .unwrap();
            let mut data = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                said.push_str(&line);
                if data {
                    if line == ".\r\n" {
                        data = false;
                        writer.write_all(b"250 queued\r\n").unwrap();
                    }
                    continue;
                }
                let verb = line.to_ascii_uppercase();
                let reply: &[u8] = if verb.starts_with("EHLO") {
                    b"250-relay.example.com\r\n250 8BITMIME\r\n"
                } else if verb.starts_with("DATA") {
                    data = true;
                    b"354 go ahead\r\n"
                } else if verb.starts_with("QUIT") {
                    writer.write_all(b"221 bye\r\n").unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                writer.write_all(reply).unwrap();
            }
            sender.send(said).unwrap();
        });
        (port, received)
    }

    #[test]
    fn email_goes_through_the_mail_server() {
        let (port, received) = smtp_once();
        let mut message = delivery(Target::Email {
            address: "alex@example.com".to_owned(),
        });
        message.mail = Some(MailServer {
            host: "127.0.0.1".to_owned(),
            port,
            security: Security::Plain,
            user: None,
            password: None,
            from: "alerts@example.com".to_owned(),
        });
        send(&message, &Host::Name("vpn.example.com".to_owned())).unwrap();
        let said = received.recv().unwrap();
        assert!(said.starts_with("EHLO vpn.example.com\r\n"), "{said}");
        assert!(said.contains("MAIL FROM:<alerts@example.com>"), "{said}");
        assert!(said.contains("RCPT TO:<alex@example.com>"), "{said}");
        assert!(
            said.contains("Subject: vpn.example.com: automatic block"),
            "{said}"
        );
        assert!(said.contains("Blocked 198.51.100.9"), "{said}");
    }

    #[test]
    fn email_without_a_mail_server_says_so() {
        let message = delivery(Target::Email {
            address: "alex@example.com".to_owned(),
        });
        let error = send(&message, &Host::Name("vpn.example.com".to_owned())).unwrap_err();
        assert!(error.contains("no mail server"), "{error}");
    }
}
