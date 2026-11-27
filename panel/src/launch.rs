//! The launch message: everything the web process needs to serve, which the
//! helper writes to the web process's standard input and then closes. The
//! web process reads it to the end and opens no files of its own.

use std::io::Read;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The longest launch message accepted, in bytes.
pub const MAX_LAUNCH: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    /// The TCP port to listen on.
    pub port: u16,
    /// The host name or address browsers use, without a port: requests for
    /// any other host are refused.
    pub host: String,
    /// The networks whose addresses may connect, as CIDR text.
    pub allowed: Vec<String>,
    /// The certificate chain in PEM, the panel's own certificate first.
    pub chain_pem: String,
    /// The private key in PEM.
    pub key_pem: String,
    /// The CA in PEM whose client certificates a browser must present, or
    /// none when client certificates are not required.
    pub client_ca_pem: Option<String>,
    /// The ocserv version the image carries, for the sidebar.
    pub ocserv_version: String,
    /// The container's host name, which tells apart several servers behind
    /// one load balancer.
    pub instance: String,
    /// The shortest admin password the helper accepts, for the form's hint.
    pub min_password_length: usize,
    /// The VPN user portal, when it is on.
    pub portal: Option<PortalLaunch>,
}

/// What the web process needs to serve the VPN user portal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalLaunch {
    /// The TCP port to listen on.
    pub port: u16,
    /// The VPN address's host, without a port: the name the portal's pages
    /// show. Requests may name it or the panel's host.
    pub host: String,
    /// The networks whose addresses may connect, as CIDR text; every address
    /// when empty.
    pub allowed: Vec<String>,
    /// The portal's certificate chain and private key in PEM: the panel's
    /// own, or PANEL_PORTAL_CERT and PANEL_PORTAL_KEY.
    pub chain_pem: String,
    pub key_pem: String,
}

impl Drop for PortalLaunch {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

impl Launch {
    /// Reads one launch message to the end of `reader`.
    pub fn read_from(reader: impl Read) -> Result<Launch, String> {
        let mut bytes = Zeroizing::new(Vec::new());
        reader
            .take(MAX_LAUNCH + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("the launch message could not be read: {error}"))?;
        if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_LAUNCH) {
            return Err(format!(
                "the launch message is longer than the {MAX_LAUNCH} bytes accepted"
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("the launch message is not valid: {error}"))
    }

    /// Encodes the message for the web process's standard input.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|error| format!("the launch message could not be encoded: {error}"))
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Launch {
        Launch {
            port: 8443,
            host: "vpn.example.com".to_owned(),
            allowed: vec!["127.0.0.0/8".to_owned()],
            chain_pem: "chain".to_owned(),
            key_pem: "key".to_owned(),
            client_ca_pem: None,
            ocserv_version: "1.6.0".to_owned(),
            instance: "vpn1".to_owned(),
            min_password_length: 12,
            portal: Some(PortalLaunch {
                port: 8444,
                host: "vpn.example.com".to_owned(),
                allowed: Vec::new(),
                chain_pem: "portal chain".to_owned(),
                key_pem: "portal key".to_owned(),
            }),
        }
    }

    #[test]
    fn round_trips() {
        let bytes = sample().encode().unwrap();
        assert_eq!(Launch::read_from(bytes.as_slice()).unwrap(), sample());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let text = r#"{"port":1,"host":"h","allowed":[],"chain_pem":"c","key_pem":"k","client_ca_pem":null,"ocserv_version":"1.6.0","instance":"vpn1","min_password_length":12,"portal":null,"extra":1}"#;
        assert!(Launch::read_from(text.as_bytes()).is_err());
    }

    #[test]
    fn an_overlong_message_is_refused_before_parsing() {
        let long = vec![b' '; usize::try_from(MAX_LAUNCH).unwrap() + 1];
        let error = Launch::read_from(long.as_slice()).unwrap_err();
        assert!(error.contains("longer"), "{error}");
    }
}
