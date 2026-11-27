//! The web process's listener. Connections from addresses outside the
//! allowed networks are dropped before any TLS; at most MAX_CONNECTIONS are
//! served at once; the TLS handshake and each request's headers have time
//! limits; everything else is HTTP/1.1 over TLS into the app's router.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio_rustls::TlsAcceptor;

use crate::net::{self, Network};

/// The most connections served at once; more are closed on arrival.
pub const MAX_CONNECTIONS: usize = 256;

/// How long a client has to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client has to send a request's headers.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// The pause after a failed accept, such as when file descriptors run out.
const ACCEPT_PAUSE: Duration = Duration::from_millis(250);

/// The address a request's connection came from, with an IPv4 address
/// mapped into IPv6 written as IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer(pub IpAddr);

/// The address as IPv4 when it is an IPv4 address mapped into IPv6.
pub fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// Binds the port on every IPv6 and IPv4 address, or on every IPv4 address
/// when the container has no IPv6.
pub async fn bind(port: u16) -> Result<TcpListener, String> {
    match TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).await {
        Ok(listener) => Ok(listener),
        Err(v6) => TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .await
            .map_err(|v4| format!("port {port} could not be bound: {v4} (on IPv6: {v6})")),
    }
}

/// Serves connections until the listener fails for good.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    allowed: Vec<Network>,
    app: Router,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, address) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("ocpanel web: a connection could not be accepted: {error}");
                tokio::time::sleep(ACCEPT_PAUSE).await;
                continue;
            }
        };
        let peer = canonical(address.ip());
        if !net::any_contains(&allowed, peer) {
            continue;
        }
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => continue,
            Err(TryAcquireError::Closed) => {
                return Err("the connection limit was closed".to_owned());
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    let service = TowerToHyperService::new(app.layer(Extension(Peer(peer))));
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT);
                    if let Err(error) = builder.serve_connection(TokioIo::new(tls), service).await
                        && !error.is_incomplete_message()
                    {
                        eprintln!("ocpanel web: a connection from {peer} failed: {error}");
                    }
                }
                Ok(Err(error)) => {
                    eprintln!("ocpanel web: a TLS handshake from {peer} failed: {error}");
                }
                Err(elapsed) => {
                    eprintln!("ocpanel web: a TLS handshake from {peer} stopped after {elapsed}");
                }
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv4_is_written_as_ipv4() {
        let mapped: IpAddr = "::ffff:192.168.1.20".parse().unwrap();
        assert_eq!(canonical(mapped), "192.168.1.20".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "fd3e::1".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }
}
