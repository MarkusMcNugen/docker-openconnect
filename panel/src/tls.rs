//! The panel's TLS settings, built from the PEM text in the launch message:
//! TLS 1.3 and 1.2 with rustls's safe defaults and the ring provider, HTTP/1.1
//! only, and client certificates from the image's CA when they are required.

use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Builds the server configuration. `chain_pem` holds the panel's
/// certificate first and the CA after it; `client_ca_pem`, when given, is the
/// CA every browser's certificate must chain to.
pub fn server_config(
    chain_pem: &str,
    key_pem: &str,
    client_ca_pem: Option<&str>,
) -> Result<Arc<ServerConfig>, String> {
    let chain = certificates(chain_pem, "the certificate chain")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|error| format!("the private key is not valid PEM: {error}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS could not be set up: {error}"))?;
    let builder = match client_ca_pem {
        None => builder.with_no_client_auth(),
        Some(pem) => {
            let mut roots = RootCertStore::empty();
            for certificate in certificates(pem, "the client certificate CA")? {
                roots
                    .add(certificate)
                    .map_err(|error| format!("the client certificate CA is not usable: {error}"))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| format!("client certificates could not be set up: {error}"))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder.with_single_cert(chain, key).map_err(|error| {
        format!("the panel's certificate and key do not form a usable pair: {error}")
    })?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Every certificate in a PEM text, in order; none is an error.
fn certificates(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{what} is not valid PEM: {error}"))?;
    if certificates.is_empty() {
        return Err(format!("{what} holds no certificate"));
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_without_a_certificate_is_refused() {
        let error = server_config("not pem", "not pem", None).unwrap_err();
        assert!(error.contains("certificate chain"), "{error}");
    }
}
