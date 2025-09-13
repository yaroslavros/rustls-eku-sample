use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use gethostname::gethostname;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use anyhow::Result;

async fn pongping(tls: &mut TlsStream<TcpStream>) -> Result<()> {
    let mut plaintext = String::new();
    tls.read_line(&mut plaintext).await?;
    print!("{}", plaintext);
    tls.write_all(b"Hello from the client\n").await?;
    tls.flush().await?;
    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {
    let hostname = gethostname();
    let hostname = hostname.to_string_lossy();
    let cert =
        rcgen::generate_simple_self_signed(vec![hostname.into()]).expect("could not generate cert");

    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.into()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;

    config.extended_key_update = true;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(format!("[::]:{}", 4443)).await?;
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let fut = async move {
            let mut tls = acceptor.accept(tcp_stream).await?;
            for _ in 0..5 { pongping(&mut tls).await? };
            tls.get_mut().1.refresh_traffic_keys()?;
            for _ in 5..19 { pongping(&mut tls).await? };
            Ok(()) as Result<()>
        };
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}
