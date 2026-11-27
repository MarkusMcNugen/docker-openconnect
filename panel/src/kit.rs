//! The onboarding kit: what a VPN user needs to connect, shown once when a
//! change sets their password or authenticator key. The helper builds it from
//! the server's configuration and certificate; the web process draws it.

use std::fmt;
use std::fs;

use data_encoding::BASE64;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::serverconf::ServerConfig;
use crate::totp;

/// The issuer authenticator apps show beside a VPN user's account.
const ISSUER: &str = "OpenConnect VPN";

/// The DER tag of a SEQUENCE.
const SEQUENCE: u8 = 0x30;

/// The DER tag of a certificate's explicit version, which version 1
/// certificates leave out.
const VERSION: u8 = 0xa0;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kit {
    pub user: String,
    pub groups: Vec<String>,
    /// The server as a client takes it: `host`, or `host:port` when the
    /// port is not 443.
    pub address: String,
    /// The secret a client adds to the address when ocserv hides behind
    /// camouflage.
    pub camouflage: Option<String>,
    /// The pin of the server's key, `pin-sha256:...`, as openconnect's
    /// `--servercert` takes it.
    pub pin: String,
    /// The password the change set, if it set one.
    pub password: Option<String>,
    /// The authenticator key the change made, if it made one.
    pub authenticator: Option<Authenticator>,
    /// Whether the VPN asks for a code from an authenticator app after the
    /// password.
    pub codes: bool,
    /// Whether Cisco Secure Client can connect.
    pub cisco: bool,
}

impl Kit {
    /// The URL a client opens: `https://address/`, with `?secret` added when
    /// ocserv hides behind camouflage.
    pub fn url(&self) -> String {
        match &self.camouflage {
            Some(secret) => format!("https://{}/?{secret}", self.address),
            None => format!("https://{}/", self.address),
        }
    }
}

impl fmt::Debug for Kit {
    /// Leaves out the password, the authenticator key and the camouflage
    /// secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Kit")
            .field("user", &self.user)
            .field("groups", &self.groups)
            .field("address", &self.address)
            .field("pin", &self.pin)
            .field("codes", &self.codes)
            .field("cisco", &self.cisco)
            .finish_non_exhaustive()
    }
}

/// A new authenticator key, as an app takes it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authenticator {
    /// The key as unpadded base32, for typing into an app.
    pub key: String,
    /// The `otpauth://` URI the QR code holds.
    pub uri: String,
}

impl Authenticator {
    /// A new random key for `user` of the VPN at `host`, and the same key in
    /// hex, as liboath's users file holds it.
    pub fn new(user: &str, host: &str) -> Result<(Authenticator, Zeroizing<String>), String> {
        let key = totp::new_secret()?;
        let hex = Zeroizing::new(totp::hex_of(&key)?);
        let uri = totp::uri(&key, &format!("{user}@{host}"), ISSUER);
        Ok((Authenticator { key, uri }, hex))
    }
}

impl fmt::Debug for Authenticator {
    /// Leaves out the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .finish_non_exhaustive()
    }
}

/// What every kit tells about the server. It is read before a change, so
/// that a server that cannot be described is refused before anything
/// changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub address: String,
    pub camouflage: Option<String>,
    pub pin: String,
    pub codes: bool,
    pub cisco: bool,
}

impl Server {
    /// The server the running configuration `config` describes, which
    /// clients reach at `address`, with the pin of the certificate it names.
    pub fn of(config: &ServerConfig, address: &str) -> Result<Server, String> {
        let certificate = config.server_cert().ok_or_else(|| {
            "the VPN server's configuration names no server-cert, so the kit has no key pin"
                .to_owned()
        })?;
        let pem = fs::read_to_string(certificate).map_err(|error| {
            format!(
                "the server certificate {} could not be read: {error}",
                certificate.display()
            )
        })?;
        let pin = key_pin(&pem).map_err(|error| {
            format!("the server certificate {}: {error}", certificate.display())
        })?;
        Ok(Server {
            address: address.to_owned(),
            camouflage: config.camouflage_secret().map(str::to_owned),
            pin,
            codes: config.otp_file().is_some(),
            cisco: config.cisco_compatible(),
        })
    }

    /// The kit for `user` after a change that set `password`, made
    /// `authenticator`, or both.
    pub fn kit(
        &self,
        user: &str,
        groups: &[String],
        password: Option<String>,
        authenticator: Option<Authenticator>,
    ) -> Kit {
        Kit {
            user: user.to_owned(),
            groups: groups.to_vec(),
            address: self.address.clone(),
            camouflage: self.camouflage.clone(),
            pin: self.pin.clone(),
            password,
            authenticator,
            codes: self.codes,
            cisco: self.cisco,
        }
    }
}

/// The pin openconnect's `--servercert` takes for the first certificate in
/// `pem`: `pin-sha256:` and the base64 SHA-256 of its subject public key
/// info, as `certtool --certificate-info` prints it.
pub fn key_pin(pem: &str) -> Result<String, String> {
    let first = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or_else(|| "it holds no PEM certificate".to_owned())?
        .map_err(|error| format!("its first certificate cannot be read: {error}"))?;
    let info = subject_public_key_info(first.as_ref())?;
    Ok(format!(
        "pin-sha256:{}",
        BASE64.encode(&Sha256::digest(info))
    ))
}

/// One DER element at the start of some bytes.
struct Element<'a> {
    tag: u8,
    contents: &'a [u8],
    /// The element with its tag and length.
    whole: &'a [u8],
    /// The bytes after it.
    rest: &'a [u8],
}

fn element(input: &[u8]) -> Result<Element<'_>, String> {
    let malformed = || "the certificate is not well-formed DER".to_owned();
    let (&tag, after_tag) = input.split_first().ok_or_else(malformed)?;
    let (&first, after_first) = after_tag.split_first().ok_or_else(malformed)?;
    let (length, after_length) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || after_first.len() < count {
            return Err(malformed());
        }
        let (bytes, after) = after_first.split_at(count);
        let length = bytes
            .iter()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        (length, after)
    };
    if after_length.len() < length {
        return Err(malformed());
    }
    let header = input.len() - after_length.len();
    let (contents, rest) = after_length.split_at(length);
    Ok(Element {
        tag,
        contents,
        whole: &input[..header + length],
        rest,
    })
}

/// The first element of `input`, which must be a SEQUENCE.
fn sequence<'a>(input: &'a [u8], what: &str) -> Result<Element<'a>, String> {
    let found = element(input).map_err(|error| format!("{what}: {error}"))?;
    if found.tag != SEQUENCE {
        return Err(format!("{what} is not a DER sequence"));
    }
    Ok(found)
}

/// The subject public key info of a DER certificate, with its own tag and
/// length: the field after the subject in the signed part.
fn subject_public_key_info(certificate: &[u8]) -> Result<&[u8], String> {
    let certificate = sequence(certificate, "the certificate")?;
    let signed = sequence(certificate.contents, "its signed part")?;
    let mut rest = signed.contents;
    if rest.first() == Some(&VERSION) {
        rest = element(rest)?.rest;
    }
    for field in [
        "serial number",
        "signature algorithm",
        "issuer",
        "validity",
        "subject",
    ] {
        rest = element(rest)
            .map_err(|error| format!("its {field}: {error}"))?
            .rest;
    }
    Ok(sequence(rest, "its public key info")?.whole)
}

/// What the Certificates page shows of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    /// The subject's common name, else its organization.
    pub subject: String,
    pub issuer: String,
    /// The DNS names and IP addresses it is valid for.
    pub names: Vec<String>,
    /// Unix times it is valid from and until.
    pub not_before: u64,
    pub not_after: u64,
    /// The pin clients check, as `key_pin` gives it.
    pub pin: String,
}

/// The facts of the first certificate in `pem`.
pub fn certificate_facts(pem: &str) -> Result<Facts, String> {
    let first = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or_else(|| "it holds no PEM certificate".to_owned())?
        .map_err(|error| format!("its first certificate cannot be read: {error}"))?;
    let certificate = sequence(first.as_ref(), "the certificate")?;
    let signed = sequence(certificate.contents, "its signed part")?;
    let mut rest = signed.contents;
    if rest.first() == Some(&VERSION) {
        rest = element(rest)?.rest;
    }
    rest = element(rest)?.rest;
    rest = element(rest)?.rest;
    let issuer = sequence(rest, "its issuer")?;
    let validity = sequence(issuer.rest, "its validity")?;
    let not_before = element(validity.contents)?;
    let not_after = element(not_before.rest)?;
    let subject = sequence(validity.rest, "its subject")?;
    let info = sequence(subject.rest, "its public key info")?;
    let mut names = Vec::new();
    let mut tail = info.rest;
    while !tail.is_empty() {
        let field = element(tail)?;
        if field.tag == EXTENSIONS {
            names = alternative_names(sequence(field.contents, "its extensions")?.contents)?;
        }
        tail = field.rest;
    }
    Ok(Facts {
        subject: name_of(issuer_or_subject(subject.contents)?),
        issuer: name_of(issuer_or_subject(issuer.contents)?),
        names,
        not_before: time_of(&not_before)?,
        not_after: time_of(&not_after)?,
        pin: format!("pin-sha256:{}", BASE64.encode(&Sha256::digest(info.whole))),
    })
}

/// The serial number of the first certificate in `pem`, in lowercase
/// hexadecimal without the sign byte DER adds before a high first bit.
pub fn certificate_serial(pem: &str) -> Result<String, String> {
    let first = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or_else(|| "it holds no PEM certificate".to_owned())?
        .map_err(|error| format!("its first certificate cannot be read: {error}"))?;
    let certificate = sequence(first.as_ref(), "the certificate")?;
    let signed = sequence(certificate.contents, "its signed part")?;
    let mut rest = signed.contents;
    if rest.first() == Some(&VERSION) {
        rest = element(rest)?.rest;
    }
    let serial = element(rest)?;
    if serial.tag != INTEGER || serial.contents.is_empty() {
        return Err("its serial number is not a DER integer".to_owned());
    }
    let digits = match serial.contents {
        [0, rest @ ..] if !rest.is_empty() => rest,
        all => all,
    };
    Ok(digits.iter().map(|byte| format!("{byte:02x}")).collect())
}

const INTEGER: u8 = 0x02;

/// The DER tag of the extensions of a certificate's signed part.
const EXTENSIONS: u8 = 0xa3;

/// The common name and organization of a distinguished name.
fn issuer_or_subject(name: &[u8]) -> Result<(Option<String>, Option<String>), String> {
    const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    let (mut common, mut organization) = (None, None);
    let mut sets = name;
    while !sets.is_empty() {
        let set = element(sets)?;
        let mut pairs = set.contents;
        while !pairs.is_empty() {
            let pair = sequence(pairs, "a name attribute")?;
            let oid = element(pair.contents)?;
            let value = element(oid.rest)?;
            let text = String::from_utf8_lossy(value.contents).into_owned();
            if oid.contents == COMMON_NAME {
                common = Some(text);
            } else if oid.contents == ORGANIZATION {
                organization = Some(text);
            }
            pairs = pair.rest;
        }
        sets = set.rest;
    }
    Ok((common, organization))
}

fn name_of((common, organization): (Option<String>, Option<String>)) -> String {
    match (common, organization) {
        (Some(common), _) => common,
        (None, Some(organization)) => organization,
        (None, None) => "no name".to_owned(),
    }
}

/// The DNS names and IP addresses of the subject alternative name
/// extension among `extensions`.
fn alternative_names(extensions: &[u8]) -> Result<Vec<String>, String> {
    const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    let mut names = Vec::new();
    let mut rest = extensions;
    while !rest.is_empty() {
        let extension = sequence(rest, "an extension")?;
        let oid = element(extension.contents)?;
        if oid.contents == SUBJECT_ALT_NAME {
            let mut value = element(oid.rest)?;
            if value.tag == BOOLEAN {
                value = element(value.rest)?;
            }
            let mut general = sequence(value.contents, "its alternative names")?.contents;
            while !general.is_empty() {
                let name = element(general)?;
                match (name.tag, name.contents.len()) {
                    (DNS_NAME, _) => {
                        names.push(String::from_utf8_lossy(name.contents).into_owned())
                    }
                    (IP_ADDRESS, 4) => {
                        let octets: [u8; 4] = name.contents.try_into().map_err(|error| {
                            format!("an IPv4 alternative name is not 4 bytes: {error}")
                        })?;
                        names.push(std::net::Ipv4Addr::from(octets).to_string());
                    }
                    (IP_ADDRESS, 16) => {
                        let octets: [u8; 16] = name.contents.try_into().map_err(|error| {
                            format!("an IPv6 alternative name is not 16 bytes: {error}")
                        })?;
                        names.push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                    (other, _) => names.push(format!("a name of DER tag {other:#04x}")),
                }
                general = name.rest;
            }
        }
        rest = extension.rest;
    }
    Ok(names)
}

const BOOLEAN: u8 = 0x01;
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// A certificate time, UTCTime or GeneralizedTime in UTC, as Unix seconds.
fn time_of(time: &Element<'_>) -> Result<u64, String> {
    let text = std::str::from_utf8(time.contents)
        .map_err(|error| format!("a certificate time is not text: {error}"))?;
    let digits = text
        .strip_suffix('Z')
        .ok_or_else(|| format!("the certificate time '{text}' is not in UTC"))?;
    let (year, rest) = match (time.tag, digits.len()) {
        (UTC_TIME, 12) => {
            let short = number(&digits[..2])?;
            (
                if short < 50 {
                    2000 + short
                } else {
                    1900 + short
                },
                &digits[2..],
            )
        }
        (GENERALIZED_TIME, 14) => (number(&digits[..4])?, &digits[4..]),
        _ => return Err(format!("'{text}' is not a certificate time")),
    };
    let [month, day, hour, minute, second] = [0, 2, 4, 6, 8].map(|at| number(&rest[at..at + 2]));
    Ok(unix_seconds(year, month?, day?)? + hour? * 3600 + minute? * 60 + second?)
}

fn number(digits: &str) -> Result<u64, String> {
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("'{digits}' in a certificate time is not a number"));
    }
    digits
        .parse()
        .map_err(|error| format!("'{digits}' in a certificate time: {error}"))
}

/// Seconds from 1970-01-01 to the start of the day, for days from 1970 on.
fn unix_seconds(year: u64, month: u64, day: u64) -> Result<u64, String> {
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(format!(
            "{year}-{month}-{day} is not a date this panel reads"
        ));
    }
    let (year, month) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = year / 400;
    let of_era = year % 400;
    let of_year = (153 * month + 2) / 5 + day - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    Ok((era * 146_097 + of_era_days - 719_468) * 86_400)
}

/// A made-up P-256 certificate, made with `openssl req -x509 -newkey ec`, for
/// the tests and the development server.
#[cfg(any(test, debug_assertions))]
pub const SAMPLE_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUUtnEOgIDTlOLslD2k9/RAN1QXyYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMB4XDTI2MTEyNjA4MjYzNloXDTM2
MTEyMzA4MjYzNlowGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEIte9LJAu2CCX2Z1umS4netarbjoxHR82inj0IcnY
M/yj6/q5bMBwsSe0RLUzXKa7Y3Crmacr8g2YnsBbIx7w5qNTMFEwHQYDVR0OBBYE
FCn2BdeKBBdDYz6evy5h9YE8Si+MMB8GA1UdIwQYMBaAFCn2BdeKBBdDYz6evy5h
9YE8Si+MMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgczig3FYE
SO4C6AE995D6GmuOFJgA6mdzDfMTPJuwvxICIQDSJAHlBdtZBlylnMkHIDUX9P/D
lkztJL+yFuypRGe7FA==
-----END CERTIFICATE-----
";

/// The pin of `SAMPLE_CERT`, as `openssl x509 -pubkey | openssl pkey -pubin
/// -outform der | openssl dgst -sha256 -binary | base64` gives it.
#[cfg(test)]
pub const SAMPLE_PIN: &str = "pin-sha256:b4W4gGKuXa6gOB3rEP5m0MNF5t5b63qTRnJ+VrcPY/8=";

#[cfg(test)]
mod tests {
    use super::*;

    const EC_CERT: &str = SAMPLE_CERT;
    const EC_PIN: &str = SAMPLE_PIN;

    fn time(tag: u8, text: &'static str) -> Result<u64, String> {
        time_of(&Element {
            tag,
            contents: text.as_bytes(),
            whole: text.as_bytes(),
            rest: &[],
        })
    }

    #[test]
    fn certificate_times_read_as_unix_seconds() {
        assert_eq!(time(UTC_TIME, "250101000000Z").unwrap(), 1_735_689_600);
        assert_eq!(time(UTC_TIME, "240229123456Z").unwrap(), 1_709_210_096);
        assert_eq!(
            time(GENERALIZED_TIME, "20500101000000Z").unwrap(),
            2_524_608_000
        );
        assert!(time(UTC_TIME, "2501010000Z").is_err());
        assert!(time(UTC_TIME, "250101000000+0100").is_err());
        assert!(time(GENERALIZED_TIME, "2050130100000Z").is_err());
    }

    #[test]
    fn the_facts_of_a_certificate_are_read() {
        let facts = certificate_facts(EC_CERT).unwrap();
        assert_eq!(facts.pin, EC_PIN);
        assert!(facts.not_after > facts.not_before, "{facts:?}");
        assert!(!facts.subject.is_empty() && !facts.issuer.is_empty());
        assert!(certificate_facts("no certificate here").is_err());
    }

    #[test]
    fn the_serial_number_reads_as_openssl_prints_it() {
        assert_eq!(
            certificate_serial(EC_CERT).unwrap(),
            "52d9c43a02034e538bb250f693dfd100dd505f26"
        );
        assert_eq!(
            certificate_serial(RSA_CERT).unwrap(),
            "54fb8cc39f78ace228b1a360f236870b6dd3b452"
        );
        assert!(certificate_serial("no certificate here").is_err());
    }

    /// An RSA 2048 certificate, whose lengths take two bytes.
    const RSA_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUVPuMw594rOIosaNg8jaHC23TtFIwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMB4XDTI2MTEyNjA4MjYzNloX
DTM2MTEyMzA4MjYzNlowGjEYMBYGA1UEAwwPdnBuLmV4YW1wbGUuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1barR9U22zbBhuozBqZGfWyOYsgw
QCJwiOI2pLnHuVv8JAPgrRcbM/fPr1TbdpDVdf/MowERS1ZONs4kHyEJLSbt8w+o
93crBDYARn5Z+Ddb1REWVQ6MUSBIZVi2ehj8JvIV/qGsmtl7HH9KoWlqN18M7hOK
JT37xIi3L6GQDVcOd3iQS+R339rYkziCE1xfWmDDZlNNV3QP15zMojB83Zgtxt9N
JzWLK8ZK50aV0k8kzq9O0axRtm4XUVMoVAYS9bjSHdlzsEuEiUnYcCKHMR1zCMtG
lR20TIBhMWoCFkd9x4atTMZFSBbY4GYII2F0EjWolEiy+PccDJCwqI0cnQIDAQAB
o1MwUTAdBgNVHQ4EFgQUaqEMX2EGa+3wkX4yaZixA8l4ON8wHwYDVR0jBBgwFoAU
aqEMX2EGa+3wkX4yaZixA8l4ON8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAuchWJxGymPFNjZAoA26hAno5oZKyjMZfjXD7TT2klTOptioeEZAi
BLPCT8+pX5sdgf/YP6PySTBaqvF/vEcI3Yiqkm9MISvNpM1oSSSBtIrjecLSY4K8
qdPHYByWZv7i09vUJymsJNaon3GCIx72zCVFGxlqgFRYzCb9KfACc49QpKClfzxa
+NLA6PPJ98Pzh2hqj1Bkyc+9XA1FobTImYxlZ0jLOiJVaXGNXchWbdi6EH/KsfiJ
JCUCh7WEA2exQJJhq8nysmDcE/6Cs1sc/ViBBc7kZeQzT1PvjUMqqTjuVyhNCVZm
+DAjvMH/YYe6wyuyReAkt9uJ05Q6rhV5UA==
-----END CERTIFICATE-----
";

    const RSA_PIN: &str = "pin-sha256:NhfUvRBipPxqHLaypf0NP05I2Ci6bu6pW64v7/rbbkk=";

    #[test]
    fn the_pin_is_the_hash_of_the_public_key_info_as_openssl_computes_it() {
        assert_eq!(key_pin(EC_CERT).unwrap(), EC_PIN);
        assert_eq!(key_pin(RSA_CERT).unwrap(), RSA_PIN);
    }

    #[test]
    fn a_chain_is_pinned_by_its_first_certificate() {
        assert_eq!(key_pin(&format!("{EC_CERT}{RSA_CERT}")).unwrap(), EC_PIN);
        assert_eq!(key_pin(&format!("{RSA_CERT}{EC_CERT}")).unwrap(), RSA_PIN);
    }

    #[test]
    fn text_without_a_certificate_has_no_pin() {
        let none = key_pin("not a certificate").unwrap_err();
        assert!(none.contains("no PEM certificate"), "{none}");
        let garbage =
            key_pin("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap_err();
        assert!(garbage.contains("not a DER sequence"), "{garbage}");
        let truncated = key_pin(&EC_CERT.replace("\nlkztJL+yFuypRGe7FA==", "")).unwrap_err();
        assert!(truncated.contains("well-formed"), "{truncated}");
    }

    #[test]
    fn the_url_carries_the_camouflage_secret() {
        let server = Server {
            address: "vpn.example.com:4443".to_owned(),
            camouflage: None,
            pin: EC_PIN.to_owned(),
            codes: false,
            cisco: true,
        };
        let kit = server.kit("casey", &[], None, None);
        assert_eq!(kit.url(), "https://vpn.example.com:4443/");
        let hidden = Server {
            camouflage: Some("hidden-door".to_owned()),
            ..server
        };
        assert_eq!(
            hidden.kit("casey", &[], None, None).url(),
            "https://vpn.example.com:4443/?hidden-door"
        );
    }

    #[test]
    fn debug_output_leaves_the_secrets_out() {
        let (authenticator, hex) = Authenticator::new("casey", "vpn.example.com").unwrap();
        let server = Server {
            address: "vpn.example.com".to_owned(),
            camouflage: Some("hidden-door".to_owned()),
            pin: EC_PIN.to_owned(),
            codes: true,
            cisco: false,
        };
        let kit = server.kit(
            "casey",
            &["staff".to_owned()],
            Some("tuba-lantern-57-orbit-quill-mango".to_owned()),
            Some(authenticator.clone()),
        );
        let shown = format!("{kit:?}");
        for secret in [
            "tuba-lantern",
            authenticator.key.as_str(),
            hex.as_str(),
            "hidden-door",
        ] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("casey"), "{shown}");
    }

    #[test]
    fn a_new_authenticator_key_names_the_user_and_the_server() {
        let (authenticator, hex) = Authenticator::new("casey", "vpn.example.com").unwrap();
        assert_eq!(hex.len(), 40);
        assert_eq!(totp::hex_of(&authenticator.key).unwrap(), *hex);
        assert!(
            authenticator
                .uri
                .starts_with("otpauth://totp/OpenConnect%20VPN:casey%40vpn.example.com?secret="),
            "{}",
            authenticator.uri
        );
    }
}
