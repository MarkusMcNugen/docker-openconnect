//! VPN users' client certificates. The client CA in CONFIG_DIR/certs, which
//! the entrypoint creates and which signs nothing else, issues them through
//! certtool; the helper keeps a record of each one, and revokes one by
//! adding it to the CA's revocation list.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::files;

/// How a certificate's private key came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The helper made the key and handed it out once, in a key file.
    KeyFile,
    /// The user made the key and sent a signing request.
    Request,
}

/// How a key file is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cipher {
    /// AES-256 with a SHA-256 MAC, for current systems.
    Aes256,
    /// 3DES with a SHA-1 MAC, the format macOS 14 and earlier, iOS 17 and
    /// earlier and some Android versions import.
    TripleDes,
}

/// When a certificate was revoked, and by which admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub at: u64,
    pub by: String,
}

/// One certificate the panel issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    /// The serial number in lowercase hexadecimal.
    pub serial: String,
    pub user: String,
    /// The groups it names: the user's when it was issued.
    pub groups: Vec<String>,
    pub method: Method,
    /// How its key file was encrypted, which a renewal repeats; none for a
    /// certificate from a signing request.
    pub cipher: Option<Cipher>,
    /// The admin who issued it, and when.
    pub by: String,
    pub issued: u64,
    pub not_after: u64,
    pub revoked: Option<Revocation>,
    /// The certificate in PEM.
    pub pem: String,
}

impl Issued {
    /// Whether it signs in at `now`: neither revoked nor expired.
    pub fn active(&self, now: u64) -> bool {
        self.revoked.is_none() && now < self.not_after
    }
}

/// The certificates the panel issued, kept in its data directory.
pub struct Records {
    path: PathBuf,
    list: Vec<Issued>,
}

impl Records {
    /// Reads the records at `path`; a missing file holds none.
    pub fn open(path: &Path) -> Result<Records, String> {
        let list = match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        Ok(Records {
            path: path.to_owned(),
            list,
        })
    }

    /// Every record, the newest first.
    pub fn newest_first(&self) -> impl Iterator<Item = &Issued> {
        self.list.iter().rev()
    }

    pub fn find(&self, serial: &str) -> Option<&Issued> {
        self.list.iter().find(|issued| issued.serial == serial)
    }

    /// Adds `issued` and saves the records.
    pub fn add(&mut self, issued: Issued) -> Result<(), String> {
        if self.find(&issued.serial).is_some() {
            return Err(format!(
                "a certificate with the serial number {} is already recorded",
                issued.serial
            ));
        }
        self.list.push(issued);
        self.save()
    }

    /// Marks the certificate `serial` revoked and saves the records.
    pub fn revoke(&mut self, serial: &str, revocation: Revocation) -> Result<(), String> {
        let Some(found) = self.list.iter_mut().find(|issued| issued.serial == serial) else {
            return Err(format!("no certificate has the serial number {serial}"));
        };
        found.revoked = Some(revocation);
        self.save()
    }

    /// The user's certificates that still sign in at `now`.
    pub fn active_of(&self, user: &str, now: u64) -> Vec<Issued> {
        self.list
            .iter()
            .filter(|issued| issued.user == user && issued.active(now))
            .cloned()
            .collect()
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(&self.list)
            .map_err(|error| format!("the certificate records could not be written: {error}"))?;
        files::write_private(&self.path, &text)
    }
}

/// Who a certificate is for: the user it signs in as and the groups it
/// names.
pub struct Subject<'a> {
    pub user: &'a str,
    pub groups: &'a [String],
}

impl Subject<'_> {
    /// The certtool template of a certificate valid for `days` days: the
    /// user as user ID and common name, each group as an organizational
    /// unit, and the TLS client purpose.
    pub fn template(&self, days: u64) -> Result<String, String> {
        for text in std::iter::once(self.user).chain(self.groups.iter().map(String::as_str)) {
            if text.is_empty()
                || text.chars().any(|character| {
                    character == '"' || character == '\\' || character.is_control()
                })
            {
                return Err(format!("'{text}' cannot be written into a certificate"));
            }
        }
        let mut template = format!("uid = \"{0}\"\ncn = \"{0}\"\n", self.user);
        for group in self.groups {
            template.push_str(&format!("unit = \"{group}\"\n"));
        }
        template.push_str(&format!(
            "expiration_days = {days}\nsigning_key\ntls_www_client\n"
        ));
        Ok(template)
    }
}

/// A certificate the client CA signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub pem: String,
    pub serial: String,
    pub not_after: u64,
}

/// A new certificate with the PKCS#12 file that holds it and its key.
pub struct KeyFile {
    pub signed: Signed,
    pub p12: Zeroizing<Vec<u8>>,
}

/// The GnuTLS security levels a signing request's key must reach: RSA 2048
/// is Medium, and P-256 and Ed25519 are High.
const STRONG_ENOUGH: &[&str] = &["Medium", "High", "Ultra", "Future"];

/// The client CA, which signs and revokes VPN users' certificates.
pub trait Authority: Send {
    /// A new private key and a certificate for it, packed into a PKCS#12
    /// file under `passphrase` with `cipher`. The key exists nowhere else
    /// once this returns.
    fn key_file(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        cipher: Cipher,
        passphrase: &str,
    ) -> Result<KeyFile, String>;

    /// A certificate for the key in the PEM signing request `request`, whose
    /// own names are ignored; or, inside, why the request is refused: it is
    /// not one, its signature does not match it, or its key is weaker than
    /// RSA 2048.
    fn sign_request(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        request: &str,
    ) -> Result<Result<Signed, String>, String>;

    /// A new certificate for the key of the PEM certificate `certificate`.
    fn sign_again(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        certificate: &str,
    ) -> Result<Signed, String>;

    /// Adds the PEM certificate `certificate`, whose serial number is
    /// `serial`, to the revoked certificates and writes the revocation list
    /// again.
    fn revoke(&mut self, serial: &str, certificate: &str) -> Result<(), String>;
}

/// The word after "Algorithm Security Level:" in certtool's description of
/// a key, such as "Medium".
fn security_level(description: &str) -> Option<&str> {
    description.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Algorithm Security Level:")
            .and_then(|level| level.split_whitespace().next())
    })
}

/// Why a signing request described by `certtool --crq-info` is refused, if
/// it is.
fn refusal_of(description: &str) -> Option<String> {
    if !description
        .lines()
        .any(|line| line.trim() == "Self signature: verified")
    {
        return Some("the signing request's signature does not match its contents".to_owned());
    }
    match security_level(description) {
        Some(level) if STRONG_ENOUGH.contains(&level) => None,
        Some(level) => Some(format!(
            "the signing request's key is too weak ({level}); use RSA 2048 or stronger, or an \
             elliptic-curve key"
        )),
        None => Some("certtool did not say how strong the signing request's key is".to_owned()),
    }
}

#[cfg(unix)]
pub use system::System;

#[cfg(unix)]
mod system {
    use std::fs;
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use super::{Authority, Cipher, KeyFile, Signed, Subject, refusal_of};
    use crate::config::KeyType;
    use crate::{command, files, kit, secret};

    const CERTTOOL: &str = "certtool";

    /// The entrypoint's writer of the client CA's revocation list.
    const WRITE_REVOCATION_LIST: &str = "/usr/local/libexec/ocserv-docker/client-crl";

    /// The client CA in `dir`, CONFIG_DIR/certs, driven through certtool.
    pub struct System {
        pub dir: PathBuf,
        pub key_type: KeyType,
    }

    /// A private directory for one certificate's files. Dropping it
    /// overwrites every file in it with zeros and removes it, so a key made
    /// for a key file is left nowhere.
    struct Work {
        path: PathBuf,
    }

    impl Work {
        fn new() -> Result<Work, String> {
            let name: String = secret::random_bytes::<8>()?
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let path = std::env::temp_dir().join(format!("ocpanel-certificate-{name}"));
            files::create_private_dir(&path)?;
            Ok(Work { path })
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn text(&self, name: &str) -> Result<String, String> {
            let path = self.file(name);
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
        }
    }

    impl Drop for Work {
        fn drop(&mut self) {
            if let Err(error) = wipe(&self.path) {
                eprintln!(
                    "ocpanel helper: a certificate's working files were not all removed: {error}"
                );
            }
        }
    }

    fn wipe(dir: &Path) -> Result<(), String> {
        let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("an entry of {}: {error}", dir.display()))?
                .path();
            let length = fs::metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?
                .len();
            let zeros = vec![
                0u8;
                usize::try_from(length).map_err(|error| {
                    format!("{} is too large to overwrite: {error}", path.display())
                })?
            ];
            fs::write(&path, zeros).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        fs::remove_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))
    }

    fn text(path: &Path) -> Result<&str, String> {
        path.to_str()
            .ok_or_else(|| format!("{} is not a UTF-8 path", path.display()))
    }

    /// Runs certtool; its standard output when it succeeds.
    fn certtool(args: &[&str]) -> Result<String, String> {
        let ran = command::run(CERTTOOL, args, &[])?;
        if ran.status.success() {
            return Ok(ran.stdout);
        }
        Err(ran.failed("certtool failed"))
    }

    impl System {
        /// Signs a certificate for the key that `key_option` loads from
        /// `key`: --load-privkey for a private key, --load-pubkey for a
        /// public one.
        fn sign(
            &self,
            work: &Work,
            subject: &Subject<'_>,
            days: u64,
            key_option: &str,
            key: &Path,
        ) -> Result<Signed, String> {
            let template = work.file("certificate.tmpl");
            files::write_private(&template, subject.template(days)?.as_bytes())?;
            let certificate = work.file("certificate.pem");
            certtool(&[
                "--generate-certificate",
                key_option,
                text(key)?,
                "--load-ca-certificate",
                text(&self.dir.join("client-ca.pem"))?,
                "--load-ca-privkey",
                text(&self.dir.join("client-ca-key.pem"))?,
                "--template",
                text(&template)?,
                "--outfile",
                text(&certificate)?,
            ])?;
            let pem = work.text("certificate.pem")?;
            Ok(Signed {
                serial: kit::certificate_serial(&pem)?,
                not_after: kit::certificate_facts(&pem)?.not_after,
                pem,
            })
        }
    }

    impl Authority for System {
        fn key_file(
            &mut self,
            subject: &Subject<'_>,
            days: u64,
            cipher: Cipher,
            passphrase: &str,
        ) -> Result<KeyFile, String> {
            if passphrase.contains(['"', '\\', '\n', '\r']) {
                return Err("the passphrase cannot be written into a template".to_owned());
            }
            let work = Work::new()?;
            let key = work.file("key.pem");
            let kind: &[&str] = match self.key_type {
                KeyType::Ecdsa => &["--key-type=ecdsa", "--curve=secp256r1"],
                KeyType::Rsa => &["--key-type=rsa", "--bits=3072"],
            };
            let mut args = vec!["--generate-privkey"];
            args.extend_from_slice(kind);
            args.extend_from_slice(&["--outfile", text(&key)?]);
            certtool(&args)?;
            let signed = self.sign(&work, subject, days, "--load-privkey", &key)?;
            let protection = work.file("p12.tmpl");
            files::write_private(
                &protection,
                Zeroizing::new(format!("password = \"{passphrase}\"\n")).as_bytes(),
            )?;
            let p12 = work.file("key.p12");
            let certificate = work.file("certificate.pem");
            let encryption: &[&str] = match cipher {
                Cipher::Aes256 => &["--pkcs-cipher", "aes-256"],
                Cipher::TripleDes => &["--pkcs-cipher", "3des-pkcs12", "--hash", "SHA1"],
            };
            let mut args = vec![
                "--to-p12",
                "--load-privkey",
                text(&key)?,
                "--load-certificate",
                text(&certificate)?,
                "--p12-name",
                subject.user,
                "--template",
                text(&protection)?,
                "--outder",
                "--outfile",
                text(&p12)?,
            ];
            args.extend_from_slice(encryption);
            certtool(&args)?;
            let p12 = Zeroizing::new(
                fs::read(&p12).map_err(|error| format!("{}: {error}", p12.display()))?,
            );
            Ok(KeyFile { signed, p12 })
        }

        fn sign_request(
            &mut self,
            subject: &Subject<'_>,
            days: u64,
            request: &str,
        ) -> Result<Result<Signed, String>, String> {
            let work = Work::new()?;
            let path = work.file("request.pem");
            files::write_private(&path, request.as_bytes())?;
            let described = command::run(CERTTOOL, &["--crq-info", "--infile", text(&path)?], &[])?;
            if !described.status.success() {
                let reason = described.stderr.lines().next().map_or("", str::trim);
                return Ok(Err(format!(
                    "this is not a certificate signing request: {reason}"
                )));
            }
            if let Some(refusal) = refusal_of(&described.stdout) {
                return Ok(Err(refusal));
            }
            let public = work.file("public.pem");
            certtool(&[
                "--pubkey-info",
                "--load-request",
                text(&path)?,
                "--outfile",
                text(&public)?,
            ])?;
            Ok(Ok(self.sign(
                &work,
                subject,
                days,
                "--load-pubkey",
                &public,
            )?))
        }

        fn sign_again(
            &mut self,
            subject: &Subject<'_>,
            days: u64,
            certificate: &str,
        ) -> Result<Signed, String> {
            let work = Work::new()?;
            let old = work.file("old.pem");
            files::write_private(&old, certificate.as_bytes())?;
            let public = work.file("public.pem");
            certtool(&[
                "--pubkey-info",
                "--load-certificate",
                text(&old)?,
                "--outfile",
                text(&public)?,
            ])?;
            self.sign(&work, subject, days, "--load-pubkey", &public)
        }

        fn revoke(&mut self, serial: &str, certificate: &str) -> Result<(), String> {
            if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("'{serial}' is not a serial number"));
            }
            let revoked = self.dir.join("client-revoked");
            files::create_private_dir(&revoked)?;
            files::write_private(
                &revoked.join(format!("{serial}.pem")),
                certificate.as_bytes(),
            )?;
            let ran = command::run(WRITE_REVOCATION_LIST, &[text(&self.dir)?], &[])?;
            if ran.status.success() {
                return Ok(());
            }
            Err(ran.failed("the revocation list could not be written"))
        }
    }
}

/// A client CA for the tests and the development server: it signs made-up
/// certificates with serial numbers that count up, and records what it
/// revoked.
#[cfg(any(test, debug_assertions))]
pub struct Fake {
    /// The time certificates are valid from.
    pub now: u64,
    pub next_serial: u64,
    pub revoked: Vec<String>,
}

#[cfg(any(test, debug_assertions))]
impl Fake {
    pub fn new(now: u64) -> Fake {
        Fake {
            now,
            next_serial: 1,
            revoked: Vec::new(),
        }
    }

    fn signed(&mut self, subject: &Subject<'_>, days: u64) -> Result<Signed, String> {
        subject.template(days)?;
        let serial = format!("{:08x}{}", self.next_serial, "0".repeat(32));
        self.next_serial += 1;
        Ok(Signed {
            pem: format!(
                "-----BEGIN CERTIFICATE-----\n{serial} {}\n-----END CERTIFICATE-----\n",
                subject.user
            ),
            serial,
            not_after: self.now + days * 86_400,
        })
    }
}

#[cfg(any(test, debug_assertions))]
impl Authority for Fake {
    fn key_file(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        cipher: Cipher,
        passphrase: &str,
    ) -> Result<KeyFile, String> {
        let signed = self.signed(subject, days)?;
        let p12 = Zeroizing::new(format!("{cipher:?} {passphrase} {}", signed.serial).into_bytes());
        Ok(KeyFile { signed, p12 })
    }

    fn sign_request(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        request: &str,
    ) -> Result<Result<Signed, String>, String> {
        if !request.contains("BEGIN CERTIFICATE REQUEST") {
            return Ok(Err(
                "this is not a certificate signing request: no PEM request found".to_owned(),
            ));
        }
        Ok(Ok(self.signed(subject, days)?))
    }

    fn sign_again(
        &mut self,
        subject: &Subject<'_>,
        days: u64,
        _certificate: &str,
    ) -> Result<Signed, String> {
        self.signed(subject, days)
    }

    fn revoke(&mut self, serial: &str, _certificate: &str) -> Result<(), String> {
        self.revoked.push(serial.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn issued(serial: &str, user: &str, not_after: u64) -> Issued {
        Issued {
            serial: serial.to_owned(),
            user: user.to_owned(),
            groups: vec!["staff".to_owned()],
            method: Method::KeyFile,
            cipher: Some(Cipher::Aes256),
            by: "admin".to_owned(),
            issued: 100,
            not_after,
            revoked: None,
            pem: "pem".to_owned(),
        }
    }

    #[test]
    fn records_are_kept_across_opens_and_revocations_stick() {
        let dir = TestDir::new();
        let path = dir.path().join("client-certificates.json");
        let mut records = Records::open(&path).unwrap();
        records.add(issued("0a", "alex", 1_000)).unwrap();
        records.add(issued("0b", "alex", 2_000)).unwrap();
        records.add(issued("0c", "sam", 2_000)).unwrap();
        assert!(records.add(issued("0a", "alex", 1_000)).is_err());
        records
            .revoke(
                "0b",
                Revocation {
                    at: 500,
                    by: "admin".to_owned(),
                },
            )
            .unwrap();
        assert!(
            records
                .revoke(
                    "ff",
                    Revocation {
                        at: 1,
                        by: "a".to_owned()
                    }
                )
                .is_err()
        );
        let records = Records::open(&path).unwrap();
        let serials: Vec<&str> = records
            .newest_first()
            .map(|issued| issued.serial.as_str())
            .collect();
        assert_eq!(serials, ["0c", "0b", "0a"]);
        let active: Vec<String> = records
            .active_of("alex", 999)
            .into_iter()
            .map(|issued| issued.serial)
            .collect();
        assert_eq!(active, ["0a"]);
        assert!(records.active_of("alex", 1_000).is_empty());
    }

    #[test]
    fn the_template_names_the_user_and_each_group() {
        let groups = vec!["staff".to_owned(), "lab".to_owned()];
        let subject = Subject {
            user: "alex",
            groups: &groups,
        };
        assert_eq!(
            subject.template(365).unwrap(),
            "uid = \"alex\"\ncn = \"alex\"\nunit = \"staff\"\nunit = \"lab\"\n\
             expiration_days = 365\nsigning_key\ntls_www_client\n"
        );
        for bad in ["al\"ex", "al\\ex", "al\nex", ""] {
            let subject = Subject {
                user: bad,
                groups: &[],
            };
            assert!(subject.template(1).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_request_must_be_self_signed_with_a_key_of_rsa_2048_or_stronger() {
        let described = |signature: &str, level: &str| {
            format!(
                "\tSubject: UID=root,CN=evil\n\tSubject Public Key Algorithm: RSA\n\t\
                 Algorithm Security Level: {level}\nSelf signature: {signature}\n"
            )
        };
        assert_eq!(
            refusal_of(&described("verified", "Medium (2048 bits)")),
            None
        );
        assert_eq!(refusal_of(&described("verified", "High (256 bits)")), None);
        let weak = refusal_of(&described("verified", "Low (1024 bits)")).unwrap();
        assert!(weak.contains("too weak (Low)"), "{weak}");
        let forged = refusal_of(&described("FAILED", "High (256 bits)")).unwrap();
        assert!(forged.contains("signature does not match"), "{forged}");
        assert!(refusal_of("Self signature: verified\n").is_some());
    }
}
