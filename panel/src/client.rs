//! How the web process reaches the helper. Handlers hold the call as a
//! `Helper`, so tests can answer it with the real service in memory; in the
//! container it is one connection to helper.sock, shared by every request and
//! used by one at a time.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::protocol::{Request, Response};

/// The helper's answer to one request, once it arrives.
pub type Reply = Pin<Box<dyn Future<Output = Result<Response, String>> + Send>>;

/// Sends one request to the helper and returns its answer.
#[derive(Clone)]
pub struct Helper(Arc<dyn Fn(Request) -> Reply + Send + Sync>);

impl Helper {
    pub fn new(call: impl Fn(Request) -> Reply + Send + Sync + 'static) -> Helper {
        Helper(Arc::new(call))
    }

    pub async fn call(&self, request: Request) -> Result<Response, String> {
        (self.0)(request).await
    }
}

/// The helper over helper.sock. A failed exchange drops the connection and
/// the next request opens a new one; a request is never sent twice, since a
/// sign-in counted twice would count against the account.
#[cfg(unix)]
pub fn over_socket(path: std::path::PathBuf) -> Helper {
    use tokio::net::UnixStream;
    use tokio::sync::Mutex;
    use zeroize::Zeroizing;

    use crate::protocol;

    let connection = Arc::new(Mutex::new(None::<UnixStream>));
    Helper::new(move |request| -> Reply {
        let path = path.clone();
        let connection = Arc::clone(&connection);
        Box::pin(async move {
            let body = Zeroizing::new(protocol::encode(&request)?);
            drop(request);
            let mut held = connection.lock().await;
            let mut stream = match held.take() {
                Some(stream) => stream,
                None => UnixStream::connect(&path)
                    .await
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            };
            let reply = exchange(&mut stream, &body).await?;
            *held = Some(stream);
            protocol::decode::<Response>(&reply)
        })
    })
}

/// Sends one framed message and reads the framed answer.
#[cfg(unix)]
async fn exchange(
    stream: &mut tokio::net::UnixStream,
    body: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::protocol::MAX_MESSAGE;

    let length = u32::try_from(body.len())
        .map_err(|error| format!("a request is too long to send: {error}"))?;
    if length > MAX_MESSAGE {
        return Err(format!(
            "a request of {length} bytes is longer than the {MAX_MESSAGE} accepted"
        ));
    }
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| format!("a request could not be sent to the helper: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("a request could not be sent to the helper: {error}"))?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("the helper's answer could not be read: {error}"))?;
    let length = u32::from_be_bytes(header);
    if length > MAX_MESSAGE {
        return Err(format!(
            "the helper answered with {length} bytes, more than the {MAX_MESSAGE} accepted"
        ));
    }
    let size = usize::try_from(length)
        .map_err(|error| format!("the helper's answer does not fit in memory: {error}"))?;
    let mut reply = zeroize::Zeroizing::new(vec![0u8; size]);
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| format!("the helper's answer could not be read: {error}"))?;
    Ok(reply)
}
