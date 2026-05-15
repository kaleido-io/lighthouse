//! TLS acceptor for warp HTTP servers using rustls 0.23 (rustls-webpki >= 0.103.13).
//!
//! Adapted from warp 0.3.7's `tls` module (MIT) — kept in-tree so we do not enable warp's
//! `tls` feature, which depends on tokio-rustls 0.25 / rustls 0.22 / rustls-webpki 0.102.x.

use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{future::TryFuture, FutureExt, ready};
use warp::hyper::server::accept::Accept;
use warp::hyper::server::conn::{AddrIncoming, AddrStream};
use warp::hyper::{self, Server};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::Item;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

/// Error loading TLS configuration or binding the listener.
#[derive(Debug)]
pub enum TlsError {
    Io(io::Error),
    CertParse,
    MissingPrivateKey,
    UnknownPrivateKeyFormat,
    EmptyKey,
    InvalidKey(rustls::Error),
    Bind(hyper::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Io(err) => err.fmt(f),
            TlsError::CertParse => write!(f, "certificate parse error"),
            TlsError::MissingPrivateKey => write!(f, "TLS key is missing a private key"),
            TlsError::UnknownPrivateKeyFormat => write!(f, "unknown private key format"),
            TlsError::EmptyKey => write!(f, "TLS key file is empty"),
            TlsError::InvalidKey(err) => write!(f, "invalid TLS key: {err}"),
            TlsError::Bind(err) => write!(f, "error binding HTTP listener: {err}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        TlsError::Io(err)
    }
}

impl From<hyper::Error> for TlsError {
    fn from(err: hyper::Error) -> Self {
        TlsError::Bind(err)
    }
}

/// Load a `rustls` server configuration from PEM certificate and key files.
pub fn load_server_config(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::CertParse)?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut key_bytes = Vec::new();
    key_reader.read_to_end(&mut key_bytes)?;
    if key_bytes.is_empty() {
        return Err(TlsError::EmptyKey);
    }

    let mut key: Option<PrivateKeyDer<'static>> = None;
    let mut key_cur = std::io::Cursor::new(key_bytes);
    for item in rustls_pemfile::read_all(&mut key_cur) {
        match item.map_err(|_| TlsError::UnknownPrivateKeyFormat)? {
            Item::Pkcs1Key(k) => key = Some(k.into()),
            Item::Pkcs8Key(k) => key = Some(k.into()),
            Item::Sec1Key(k) => key = Some(k.into()),
            _ => return Err(TlsError::UnknownPrivateKeyFormat),
        }
    }
    let key = key.ok_or(TlsError::MissingPrivateKey)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(TlsError::InvalidKey)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

enum TlsStreamState {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

/// A TLS connection accepted from an `AddrIncoming` listener.
pub struct TlsStream {
    state: TlsStreamState,
    remote_addr: SocketAddr,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> Self {
        let remote_addr = stream.remote_addr();
        let accept = TokioTlsAcceptor::from(config).accept(stream);
        Self {
            state: TlsStreamState::Handshaking(accept),
            remote_addr,
        }
    }

    /// Remote socket address of the client, if known.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match &mut pin.state {
            TlsStreamState::Handshaking(accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = TlsStreamState::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            TlsStreamState::Streaming(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match &mut pin.state {
            TlsStreamState::Handshaking(accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = TlsStreamState::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            TlsStreamState::Streaming(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            TlsStreamState::Handshaking(_) => Poll::Ready(Ok(())),
            TlsStreamState::Streaming(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            TlsStreamState::Handshaking(_) => Poll::Ready(Ok(())),
            TlsStreamState::Streaming(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Hyper acceptor that performs a TLS handshake for each incoming TCP connection.
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> Self {
        Self { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

/// Bind a TCP listener and return a future that serves `filter` over TLS until `shutdown`.
pub fn try_bind_tls_with_graceful_shutdown<F>(
    filter: F,
    addr: SocketAddr,
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(SocketAddr, Pin<Box<dyn Future<Output = ()> + Send>>), TlsError>
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    <F::Future as TryFuture>::Ok: warp::Reply,
    <F::Future as TryFuture>::Error: warp::reject::IsReject,
{
    use std::convert::Infallible;

    use warp::hyper::service::{make_service_fn, service_fn};

    let tls_config = load_server_config(cert_path, key_path)?;
    let inner = warp::service(filter);

    let make_svc = make_service_fn(move |_conn: &TlsStream| {
        let inner = inner.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let mut inner = inner.clone();
                async move { inner.call(req).await }
            }))
        }
    });

    let mut incoming = AddrIncoming::bind(&addr)?;
    incoming.set_nodelay(true);
    let listen_addr = incoming.local_addr();
    let acceptor = TlsAcceptor::new(tls_config, incoming);

    let server = Server::builder(acceptor)
        .serve(make_svc)
        .with_graceful_shutdown(shutdown)
        .map(|result| {
            if let Err(err) = result {
                tracing::error!(%err, "TLS HTTP server error");
            }
        });

    Ok((listen_addr, Box::pin(server)))
}
