#![allow(unused_imports)]

use blake2::Blake2b;
use bytes::{Buf, BytesMut};
use chacha20poly1305::XChaCha20Poly1305;
use futures::sink::{self, SinkExt};
use futures::stream::{self, StreamExt};
use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::{
    Certificate, ClientConfig, ConnectionCommon, ServerConfig, ServerName, SideData,
    SignatureScheme,
};
use rustls_pemfile::certs;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::{BufReader, IoSlice, Read, Write};
use std::marker::PhantomData;
use std::marker::Send;
use std::marker::Sync;
use std::marker::Unpin;
use std::mem::size_of;
use std::ops::Deref;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tokio_util::io::SyncIoBridge;

mod crypto;
use crate::crypto::*;

#[derive(Serialize, Deserialize, Debug)]
struct TestMessage {
    msg: String,
}

struct IOPipeline<T> {
    marker: PhantomData<T>,
    crypto: CryptoCtx,
}

impl<T> Encoder<T> for IOPipeline<T>
where
    T: Serialize,
{
    type Error = std::io::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let serialized = serde_json::to_vec(&item).unwrap();
        let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut self.crypto, &serialized);
        dst.extend_from_slice(&ciphertext.len().to_be_bytes());
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }
}

impl<T> Decoder for IOPipeline<T>
where
    T: DeserializeOwned,
{
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const LEN_LEN: usize = size_of::<usize>();

        if src.len() < LEN_LEN {
            return Ok(None);
        }
        let mut length_bytes = [0u8; LEN_LEN];
        length_bytes.copy_from_slice(&src[..LEN_LEN]);
        //TODO: Should check for maximum value for sanity
        let packet_len = usize::from_be_bytes(length_bytes);

        if src.len() < LEN_LEN + packet_len {
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains
        // this frame.
        let data = src[LEN_LEN..LEN_LEN + packet_len].to_vec();
        src.advance(LEN_LEN + packet_len);

        let plaintext = decrypt_message::<XChaCha20Poly1305>(&mut self.crypto, &data);
        let deser = serde_json::from_slice::<T>(&plaintext);
        if let Err(e) = deser {
            if serde_json::Error::is_eof(&e) {
                //Not enough bytes
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Some other kind of error happened",
            ));
        }

        Ok(Some(deser.unwrap()))
    }
}

struct DummyCertVerifier {}

impl ServerCertVerifier for DummyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    //fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    //    Vec::new()
    //}
    fn request_scts(&self) -> bool {
        false
    }
}

//TODO: Tons of code duplication here, and the tx/rx types are wonky
struct AsyncTLSConnection<T> {
    stream: Arc<std::sync::Mutex<rustls::StreamOwned<T, SyncIoBridge<TcpStream>>>>,
    rx_tx:
        Arc<std::sync::Mutex<tokio::sync::mpsc::Sender<(std::io::Result<usize>, Option<Vec<u8>>)>>>,
    rx_rx: Arc<
        std::sync::Mutex<tokio::sync::mpsc::Receiver<(std::io::Result<usize>, Option<Vec<u8>>)>>,
    >,
    tx_tx: Arc<std::sync::Mutex<tokio::sync::mpsc::Sender<std::io::Result<usize>>>>,
    tx_rx: Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<std::io::Result<usize>>>>,
    read_buffer: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl<T, U> AsyncTLSConnection<T>
where
    T: DerefMut + Deref<Target = ConnectionCommon<U>>,
    U: SideData,
{
    fn new(tcp: TcpStream, tls: T) -> Self {
        let (tx_tx, tx_rx) = tokio::sync::mpsc::channel(128);
        let (rx_tx, rx_rx) = tokio::sync::mpsc::channel(128);
        AsyncTLSConnection {
            stream: Arc::new(std::sync::Mutex::new(rustls::StreamOwned::new(
                tls,
                SyncIoBridge::new(tcp),
            ))),
            tx_tx: Arc::new(std::sync::Mutex::new(tx_tx)),
            tx_rx: Arc::new(std::sync::Mutex::new(tx_rx)),
            rx_tx: Arc::new(std::sync::Mutex::new(rx_tx)),
            rx_rx: Arc::new(std::sync::Mutex::new(rx_rx)),
            read_buffer: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl<T, U> AsyncRead for AsyncTLSConnection<T>
where
    T: DerefMut + Deref<Target = ConnectionCommon<U>> + Send + Sync + 'static,
    U: SideData,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let stream = Arc::clone(&self.stream);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.rx_tx);
        let max_to_read = buf.remaining();

        {
            let mut read_buffer = self.read_buffer.lock().unwrap();
            if !read_buffer.is_empty() {
                let min_data: usize;
                if max_to_read <= read_buffer.len() {
                    min_data = max_to_read;
                } else {
                    min_data = read_buffer.len();
                }
                let drained_data: Vec<u8> = read_buffer.drain(..min_data).collect();
                buf.put_slice(&drained_data);
                return Poll::Ready(Ok(()));
            }
        }

        match self.rx_rx.lock().unwrap().try_recv() {
            Ok((res, raw_buf)) => match res {
                Ok(_) => {
                    debug_assert!(raw_buf.is_some());
                    let raw_vec = raw_buf.unwrap();
                    if raw_vec.len() > max_to_read {
                        buf.put_slice(&raw_vec[..max_to_read]);
                        self.read_buffer
                            .lock()
                            .unwrap()
                            .extend_from_slice(&raw_vec[max_to_read..]);
                    } else {
                        buf.put_slice(&raw_vec);
                    }
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => {
                tokio::task::spawn_blocking(move || {
                    {
                        let mut stream = stream.lock().unwrap();
                        let mut raw_buf = [0u8; 4096];

                        match stream.read(&mut raw_buf) {
                            Ok(sz) => {
                                let vec_buf = Vec::from(&raw_buf[..sz]);
                                tx.lock()
                                    .unwrap()
                                    .blocking_send((Ok(vec_buf.len()), Some(vec_buf)))
                                    .unwrap();
                            }
                            Err(e) => {
                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                    tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                                }
                            }
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        }
    }
}

impl<T, U> AsyncWrite for AsyncTLSConnection<T>
where
    T: DerefMut + Deref<Target = ConnectionCommon<U>> + Send + Sync + 'static,
    U: SideData,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let stream = Arc::clone(&self.stream);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx_tx);
        //TODO: Is there any way to avoid copying all this data?
        let saved_data = Vec::from(buf);
        match self.tx_rx.lock().unwrap().try_recv() {
            Ok(res) => match res {
                Ok(sz) => Poll::Ready(Ok(sz)),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => {
                tokio::task::spawn_blocking(move || {
                    {
                        match stream.lock().unwrap().write(&saved_data) {
                            Ok(sz) => tx.lock().unwrap().blocking_send(Ok(sz)).unwrap(),
                            Err(e) => tx.lock().unwrap().blocking_send(Err(e)).unwrap(),
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let stream = Arc::clone(&self.stream);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx_tx);
        match self.tx_rx.lock().unwrap().try_recv() {
            Ok(res) => match res {
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => {
                tokio::task::spawn_blocking(move || {
                    {
                        match stream.lock().unwrap().flush() {
                            Ok(_) => tx.lock().unwrap().blocking_send(Ok(0)).unwrap(),
                            Err(e) => tx.lock().unwrap().blocking_send(Err(e)).unwrap(),
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        }
    }

    //TODO: Is there even a shutdown call available to us for TLS here?
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let stream = Arc::clone(&self.stream);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx_tx);
        //TODO: Is there any way to avoid copying all this data?
        let saved_data: Vec<u8> = bufs
            .iter()
            .flat_map(|slice| slice.iter())
            .map(|byte| byte.to_owned())
            .collect();
        match self.tx_rx.lock().unwrap().try_recv() {
            Ok(res) => match res {
                Ok(sz) => Poll::Ready(Ok(sz)),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => {
                tokio::task::spawn_blocking(move || {
                    {
                        match stream.lock().unwrap().write(&saved_data) {
                            Ok(sz) => tx.lock().unwrap().blocking_send(Ok(sz)).unwrap(),
                            Err(e) => tx.lock().unwrap().blocking_send(Err(e)).unwrap(),
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

async fn run_client() {
    // Connect to a peer
    let stream = TcpStream::connect("127.0.0.1:1337").await.unwrap();

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(DummyCertVerifier {}));

    let rc_config = Arc::new(config);
    let client = rustls::ClientConnection::new(rc_config, "localhost".try_into().unwrap()).unwrap();

    let mut tls_stream = AsyncTLSConnection::new(stream, client);

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    let serialized = serde_json::to_vec(&client_start_handshake(&crypto)).unwrap();
    tls_stream
        .write(&serialized.len().to_be_bytes())
        .await
        .unwrap();
    tls_stream.write(&serialized).await.unwrap();

    let packet_len = tls_stream.read_u64().await.unwrap() as usize;

    while bytes_read < packet_len {
        bytes_read += tls_stream.read_buf(&mut read_buff).await.unwrap();
    }
    //Respond to the handshake
    let response = serde_json::from_slice(&read_buff[..packet_len]).unwrap();
    client_finish_handshake::<Blake2b>(&mut crypto, &response);
    read_buff.drain(..packet_len);

    let pipeline = IOPipeline::<TestMessage> {
        marker: PhantomData,
        crypto: crypto,
    };

    let mut framed = Framed::new(tls_stream, pipeline);

    loop {
        let message = TestMessage {
            msg: format!("Client message {}", message_count),
        };
        framed.send(message).await.unwrap();
        message_count += 1;
        let response = framed.next().await.unwrap().unwrap();
        println!("Client got message: \"{:?}\"", &response);
    }
}

//Ripped straight from the rustls example code
fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

async fn process(stream: TcpStream) {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            load_certs("test_ecc_cert.pem"),
            load_private_key("test_ecc_key.pem"),
        )
        .expect("bad certificate/key");

    let rc_config = Arc::new(config);
    let server = rustls::ServerConnection::new(rc_config).unwrap();

    let mut tls_stream = AsyncTLSConnection::new(stream, server);

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    let packet_len = tls_stream.read_u64().await.unwrap() as usize;
    println!("Incoming client length {packet_len}");
    println!("Counts {bytes_read} {packet_len}");

    read_buff.clear();

    while bytes_read < packet_len {
        bytes_read += tls_stream.read_buf(&mut read_buff).await.unwrap();
    }
    //Respond to the handshake
    let client_handshake = serde_json::from_slice(&read_buff[..packet_len]).unwrap();
    let server_response = server_respond_handshake::<Blake2b>(&mut crypto, &client_handshake);
    let serialized = serde_json::to_vec(&server_response).unwrap();
    tls_stream
        .write(&serialized.len().to_be_bytes())
        .await
        .unwrap();
    tls_stream.write(&serialized).await.unwrap();
    read_buff.drain(..packet_len);
    message_count += 1;

    let pipeline = IOPipeline::<TestMessage> {
        marker: PhantomData,
        crypto: crypto,
    };

    let mut framed = Framed::new(tls_stream, pipeline);

    loop {
        let response = framed.next().await.unwrap().unwrap();
        println!("Server got message: \"{:?}\"", &response);
        let message = TestMessage {
            msg: format!("Server message {}", message_count),
        };
        framed.send(message).await.unwrap();
        message_count += 1;
    }
}

async fn run_server() {
    // Bind the listener to the address
    let listener = TcpListener::bind("127.0.0.1:1337").await.unwrap();

    loop {
        // The second item contains the IP and port of the new connection.
        let (socket, _) = listener.accept().await.unwrap();
        // A new task is spawned for each inbound socket. The socket is
        // moved to the new task and processed there.
        tokio::spawn(async move {
            process(socket).await;
        });
    }
}

#[tokio::main]
async fn main() {
    let mut client = true;

    //I'm not insane enough to start digging into CLI options to begin with
    for arg in env::args().skip(1) {
        if arg == "-s" {
            client = false;
            break;
        }
    }
    println!("Are we a client? {}", client);
    if client {
        run_client().await;
    } else {
        run_server().await;
    }
}
