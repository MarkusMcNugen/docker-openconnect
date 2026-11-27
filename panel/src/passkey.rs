//! Admin passkeys: the WebAuthn relying party they are registered with, the
//! two ceremonies that register one and check one at sign-in, and the names
//! admins give them.

use std::fmt;
use std::time::Duration;

use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::config::Host;
use crate::store::StoredPasskey;

/// The name authenticators show when a passkey is created or used.
const RP_NAME: &str = "OpenConnect admin panel";

/// The most passkeys one admin may register.
pub const MAX_PASSKEYS: usize = 10;

/// The longest passkey name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// The relying party for the panel's origin.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// The relying party ID passkeys are bound to: the panel's host name.
    pub id: String,
    /// The WebAuthn verifier configured for the panel's origin.
    pub webauthn: Webauthn,
}

/// Why the browser's answer to a passkey prompt was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl RelyingParty {
    /// Starts a passkey registration and discards it. This exercises the
    /// random number generator and the challenge encoding that every real
    /// registration and sign-in depends on, on the platform the panel runs on.
    pub fn self_test(&self) -> Result<(), Unavailable> {
        self.webauthn
            .start_passkey_registration(Uuid::new_v4(), "self-test", "self-test", None)
            .map(|(_challenge, _state)| ())
            .map_err(|error| Unavailable::Refused(error.to_string()))
    }

    /// Starts registering a passkey for an admin: `user` is the handle all of
    /// the admin's passkeys carry, and `existing` are their passkeys so far,
    /// which the browser will not register twice. Returns the options for the
    /// browser's passkey prompt, as JSON, and the state the registration
    /// finishes with.
    pub fn begin_registration(
        &self,
        user: Uuid,
        admin: &str,
        existing: &[Passkey],
    ) -> Result<(String, PasskeyRegistration), String> {
        let exclude = existing
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user, admin, admin, Some(exclude))
            .map_err(|error| format!("a passkey registration could not start: {error}"))?;
        let options = serde_json::to_string(&options).map_err(|error| {
            format!("the passkey prompt's options could not be written: {error}")
        })?;
        Ok((options, state))
    }

    /// The passkey the browser registered, from its answer as JSON, checked
    /// against the registration's state.
    pub fn finish_registration(
        &self,
        answer: &str,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, Refused> {
        let credential: RegisterPublicKeyCredential =
            serde_json::from_str(answer).map_err(|error| {
                Refused(format!(
                    "the browser's answer is not a new passkey: {error}"
                ))
            })?;
        self.webauthn
            .finish_passkey_registration(&credential, state)
            .map_err(|error| Refused(format!("the new passkey failed its checks: {error}")))
    }

    /// Starts a sign-in with one of `passkeys`: the options for the browser's
    /// passkey prompt, as JSON, and the state the sign-in finishes with.
    pub fn begin_sign_in(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(String, PasskeyAuthentication), String> {
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|error| format!("a passkey sign-in could not start: {error}"))?;
        let options = serde_json::to_string(&options).map_err(|error| {
            format!("the passkey prompt's options could not be written: {error}")
        })?;
        Ok((options, state))
    }

    /// Checks the browser's answer to a sign-in, as JSON, against the
    /// sign-in's state: which passkey signed, and its new counter.
    pub fn finish_sign_in(
        &self,
        answer: &str,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, Refused> {
        let credential: PublicKeyCredential = serde_json::from_str(answer).map_err(|error| {
            Refused(format!(
                "the browser's answer is not a passkey signature: {error}"
            ))
        })?;
        self.webauthn
            .finish_passkey_authentication(&credential, state)
            .map_err(|error| {
                Refused(format!(
                    "the passkey's signature failed its checks: {error}"
                ))
            })
    }
}

/// The passkey `stored` holds.
pub fn credential_of(stored: &StoredPasskey) -> Result<Passkey, String> {
    serde_json::from_str(&stored.credential).map_err(|error| {
        format!(
            "the stored passkey '{}' cannot be read: {error}",
            stored.name
        )
    })
}

/// `passkey` as admins.json keeps it.
pub fn stored_form(passkey: &Passkey) -> Result<String, String> {
    serde_json::to_string(passkey)
        .map_err(|error| format!("a passkey could not be written: {error}"))
}

/// The rule `name` breaks as a passkey name, or none when it is a valid one:
/// 1 to 64 characters, none of them a control character.
pub fn name_problem(name: &str) -> Option<String> {
    let length = name.chars().count();
    if length == 0 || length > MAX_NAME_CHARS {
        return Some(format!(
            "a name must be 1 to {MAX_NAME_CHARS} characters long"
        ));
    }
    if name.chars().any(char::is_control) {
        return Some("a name cannot hold tabs, line breaks or other control characters".to_owned());
    }
    None
}

/// Whether two passkey names are the same name, letter case aside.
pub fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// Why passkeys cannot be offered at the panel's address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// Browsers bind passkeys to a host name, never to an IP address.
    IpAddress,
    /// The WebAuthn library refused the origin.
    Refused(String),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unavailable::IpAddress => f.write_str(
                "the panel is reached at an IP address, and browsers bind passkeys to a host name",
            ),
            Unavailable::Refused(reason) => write!(f, "the host name was refused: {reason}"),
        }
    }
}

/// Builds the relying party for `https://<host>:<port>`, whose ID is the
/// host name; the browser's passkey prompt waits `timeout` for the admin.
pub fn relying_party(
    host: &Host,
    port: u16,
    timeout: Duration,
) -> Result<RelyingParty, Unavailable> {
    let Host::Name(name) = host else {
        return Err(Unavailable::IpAddress);
    };
    let origin = Url::parse(&format!("https://{name}:{port}"))
        .map_err(|error| Unavailable::Refused(error.to_string()))?;
    let webauthn = WebauthnBuilder::new(name, &origin)
        .and_then(|builder| builder.rp_name(RP_NAME).timeout(timeout).build())
        .map_err(|error| Unavailable::Refused(error.to_string()))?;
    Ok(RelyingParty {
        id: name.clone(),
        webauthn,
    })
}

/// The relying party for the development server's plain HTTP pages at
/// `http://localhost:<port>`, which browsers treat as a secure origin.
#[cfg(debug_assertions)]
pub fn local_relying_party(port: u16, timeout: Duration) -> Result<RelyingParty, Unavailable> {
    let origin = Url::parse(&format!("http://localhost:{port}"))
        .map_err(|error| Unavailable::Refused(error.to_string()))?;
    let webauthn = WebauthnBuilder::new("localhost", &origin)
        .and_then(|builder| builder.rp_name(RP_NAME).timeout(timeout).build())
        .map_err(|error| Unavailable::Refused(error.to_string()))?;
    Ok(RelyingParty {
        id: "localhost".to_owned(),
        webauthn,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config::DEFAULT_PORT;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    /// How long the tests' passkey prompts wait.
    const WINDOW: Duration = Duration::from_secs(300);

    fn party(host: &str, port: u16) -> Result<RelyingParty, Unavailable> {
        relying_party(&Host::parse(host).unwrap(), port, WINDOW)
    }

    /// A browser with a software passkey: it answers the panel's prompts as
    /// a browser at `origin` does, claiming the user verification the panel
    /// requires.
    pub struct Browser {
        origin: Url,
        key: SoftPasskey,
    }

    impl Browser {
        pub fn at(origin: &str) -> Browser {
            Browser {
                origin: Url::parse(origin).unwrap(),
                key: SoftPasskey::new(true),
            }
        }

        /// The browser's answer to a registration prompt, as JSON.
        pub fn register(&mut self, options: &str) -> String {
            let options: CreationChallengeResponse = serde_json::from_str(options).unwrap();
            let answer = self
                .key
                .do_registration(self.origin.clone(), options)
                .unwrap();
            serde_json::to_string(&answer).unwrap()
        }

        /// The browser's answer to a sign-in prompt, as JSON.
        pub fn sign(&mut self, options: &str) -> String {
            let options: RequestChallengeResponse = serde_json::from_str(options).unwrap();
            let answer = self
                .key
                .do_authentication(self.origin.clone(), options)
                .unwrap();
            serde_json::to_string(&answer).unwrap()
        }
    }

    #[test]
    fn host_names_get_a_relying_party() {
        assert_eq!(
            party("vpn.example.com", DEFAULT_PORT).unwrap().id,
            "vpn.example.com"
        );
    }

    #[test]
    fn the_default_https_port_works() {
        assert_eq!(party("vpn.example.com", 443).unwrap().id, "vpn.example.com");
    }

    #[test]
    fn single_label_names_work() {
        assert_eq!(party("vpn", DEFAULT_PORT).unwrap().id, "vpn");
    }

    #[test]
    fn a_registration_can_start() {
        let party = party("vpn.example.com", DEFAULT_PORT).unwrap();
        assert_eq!(party.self_test(), Ok(()));
    }

    #[test]
    fn addresses_get_none() {
        for host in ["192.168.1.20", "fd3e::1"] {
            let reason = party(host, DEFAULT_PORT).unwrap_err();
            assert_eq!(reason, Unavailable::IpAddress, "for {host}");
        }
    }

    #[test]
    fn a_registered_passkey_signs_in_and_survives_storage() {
        let party = party("vpn.example.com", 8443).unwrap();
        let mut browser = Browser::at("https://vpn.example.com:8443");
        let user = Uuid::new_v4();
        let (options, state) = party.begin_registration(user, "alex", &[]).unwrap();
        let passkey = party
            .finish_registration(&browser.register(&options), &state)
            .unwrap();
        let stored = StoredPasskey {
            name: "Work laptop".to_owned(),
            created: 1,
            last_used: None,
            credential: stored_form(&passkey).unwrap(),
        };
        let reloaded = credential_of(&stored).unwrap();
        assert_eq!(reloaded.cred_id(), passkey.cred_id());
        let (options, state) = party.begin_sign_in(&[reloaded]).unwrap();
        let result = party
            .finish_sign_in(&browser.sign(&options), &state)
            .unwrap();
        assert_eq!(result.cred_id(), passkey.cred_id());
        assert!(result.user_verified());
    }

    #[test]
    fn answers_from_another_port_or_to_another_prompt_are_refused() {
        let party = party("vpn.example.com", 8443).unwrap();
        let (options, state) = party
            .begin_registration(Uuid::new_v4(), "alex", &[])
            .unwrap();
        let mut other_port = Browser::at("https://vpn.example.com:9443");
        assert!(
            party
                .finish_registration(&other_port.register(&options), &state)
                .is_err(),
            "a page on another port registered a passkey"
        );
        let mut browser = Browser::at("https://vpn.example.com:8443");
        let passkey = party
            .finish_registration(&browser.register(&options), &state)
            .unwrap();
        let (first, _first_state) = party.begin_sign_in(std::slice::from_ref(&passkey)).unwrap();
        let (_second, second_state) = party.begin_sign_in(&[passkey]).unwrap();
        let refused = party.finish_sign_in(&browser.sign(&first), &second_state);
        assert!(refused.is_err(), "an answer to another prompt signed in");
        assert!(party.finish_sign_in("{}", &second_state).is_err());
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(name_problem("Work laptop"), None);
        assert_eq!(name_problem(&"k".repeat(MAX_NAME_CHARS)), None);
        assert!(name_problem("").is_some());
        assert!(name_problem(&"k".repeat(MAX_NAME_CHARS + 1)).is_some());
        assert!(name_problem("two\nlines").is_some());
        assert!(same_name("YubiKey", "yubikey"));
        assert!(!same_name("YubiKey", "YubiKey 2"));
    }
}
