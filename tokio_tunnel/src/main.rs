#![allow(unused_imports)]

use blake2::Blake2b;
use bytes::{Buf, BytesMut};
use chacha20poly1305::XChaCha20Poly1305;
use futures::sink::{self, SinkExt};
use futures::stream::{self, StreamExt};
use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::{
    Certificate, ClientConfig, ConnectionCommon, ServerConfig, ServerName, SignatureScheme,
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
struct AsyncTLSConnection<T, U>
where
    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync + 'static,
{
    tcp: Arc<std::sync::Mutex<SyncIoBridge<TcpStream>>>,
    tls: Arc<std::sync::Mutex<T>>,
    tx: Arc<std::sync::Mutex<tokio::sync::mpsc::Sender<(std::io::Result<usize>, Option<Vec<u8>>)>>>,
    rx: Arc<
        std::sync::Mutex<tokio::sync::mpsc::Receiver<(std::io::Result<usize>, Option<Vec<u8>>)>>,
    >,
}

impl<T, U> AsyncTLSConnection<T, U>
where
    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync + 'static,
{
    fn new(tcp: TcpStream, tls: T) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        AsyncTLSConnection {
            tcp: Arc::new(std::sync::Mutex::new(SyncIoBridge::new(tcp))),
            tls: Arc::new(std::sync::Mutex::new(tls)),
            tx: Arc::new(std::sync::Mutex::new(tx)),
            rx: Arc::new(std::sync::Mutex::new(rx)),
        }
    }
}

impl<T, U> AsyncRead for AsyncTLSConnection<T, U>
where
    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let tcp = Arc::clone(&self.tcp);
        let tls = Arc::clone(&self.tls);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx);
        eprintln!("Let's call try_recv");
        match self.rx.lock().unwrap().try_recv() {
            Ok((res, raw_buf)) => {
                eprintln!("Try recv is ok");
                match res {
                    Ok(_) => {
                        debug_assert!(raw_buf.is_some());
                        eprintln!("Try recv is ok with ok");
                        eprintln!("What's my stuff {:#?}", &raw_buf.as_ref().unwrap());
                        buf.put_slice(&raw_buf.unwrap());
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => {
                        eprintln!("Try recv is ok with err {}", e.to_string());
                        Poll::Ready(Err(e))
                    }
                }
            }
            Err(TryRecvError::Empty) => {
                eprintln!("Empty?");
                tokio::task::spawn_blocking(move || {
                    {
                        let mut tls = tls.lock().unwrap();
                        let mut tcp = tcp.lock().unwrap();
                        match tls.complete_io(&mut *tcp) {
                            Ok((rd, wr)) => {
                                let mut raw_buf: Vec<u8> = Vec::with_capacity(4096);
                                eprintln!("IO is good, now we read");
                                eprintln!("Data we got {} {}", rd, wr);

                                if tls.wants_read() || tls.wants_write() {
                                    tls.complete_io(&mut *tcp);
                                }


                                let ans = tls.reader().read(&mut raw_buf);
                                eprintln!("Reader answer is {ans:#?}");
                                eprintln!("Buffer contents are {:#?}", &raw_buf);
                                eprintln!("Handshaking? {:?}", tls.is_handshaking());
                                eprintln!("Wants Read: {} Write: {}", tls.wants_read(), tls.wants_write());
                                if tls.wants_read() || tls.wants_write() {
                                    tls.complete_io(&mut *tcp);
                                }

                                //tcp.write(b"FIZZBUZZ");

                                //tls.writer().write(b"ABC");
                                //tls.writer().write(b"DEF");
                                //tls.writer().write(b"GHI");
                                //tls.writer().write(b"JKLM");
                                //tls.writer().flush();

                                //tcp.write(b"BUZZBUZZ");

                                //while tls.wants_read() || tls.wants_write() {
                                //    if tls.wants_read() {
                                //        tls.read_tls(&mut *tcp);
                                //    }
                                //    if tls.wants_write() {
                                //        tls.write_tls(&mut *tcp);
                                //    }
                                //    tls.process_new_packets();
                                //}

                                //let ans = tls.reader().read(&mut raw_buf);
                                //eprintln!("Second try");
                                //eprintln!("Reader answer is {ans:#?}");
                                //eprintln!("Buffer contents are {:#?}", &raw_buf);
                                //eprintln!("Handshaking? {:?}", tls.is_handshaking());
                                //eprintln!("Wants Read: {} Write: {}", tls.wants_read(), tls.wants_write());

                                match tls.reader().read(&mut raw_buf) {
                                    Ok(sz) => {
                                        eprintln!("Reader is ok with sz {:?}", sz);
                                        eprintln!("Sending {:#?}", &raw_buf);
                                        let res = tx.lock().unwrap().blocking_send((Ok(sz), Some(raw_buf)));
                                        match res {
                                            Ok(_) => {
                                                eprintln!("Blocking send is ok");
                                            }
                                            Err(e) => {
                                                eprintln!("Error is {}", e.to_string());
                                            }
                                        }
                                }
                                    Err(e) => {
                                        eprintln!("TLS Error is {}", e.to_string());
                                        //TODO: This is bad, very bad, needs fix
                                        tx.lock()
                                            .unwrap()
                                            .blocking_send((Ok(0), Some(raw_buf)))
                                            .unwrap();
                                }
                                }
                            }
                            Err(e) => {
                                eprintln!("IO is bad, now we read");
                                eprintln!("Error is {}", e.to_string());
                                tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                            }
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(e) => {
                eprintln!("What is my error {}", e.to_string());
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            }
        }
    }
}

impl<T, U> AsyncWrite for AsyncTLSConnection<T, U>
where
    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let tcp = Arc::clone(&self.tcp);
        let tls = Arc::clone(&self.tls);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx);
        //TODO: Is there any way to avoid copying all this data?
        let saved_data = Vec::from(buf);
        match self.rx.lock().unwrap().try_recv() {
            Ok((res, _)) => match res {
                Ok(sz) => Poll::Ready(Ok(sz)),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => {
                tokio::task::spawn_blocking(move || {
                    {
                        let mut tls = tls.lock().unwrap();
                        let mut tcp = tcp.lock().unwrap();
                        match tls.complete_io(&mut *tcp) {
                            Ok((rd, wr)) => {
                                if tls.wants_read() || tls.wants_write() {
                                    tls.complete_io(&mut *tcp);
                                }
                                eprintln!("How much did we read {} and write {}", rd, wr);
                                eprintln!("What are we trying to send {:#?}", &saved_data);
                                match tls.writer().write(&saved_data) {
                                    Ok(sz) => {
                                        if tls.wants_read() || tls.wants_write() {
                                            tls.complete_io(&mut *tcp);
                                        }
                                        eprintln!("Writer is ok with sz {:?}", sz);
                                        //eprintln!("Sending {:#?}", &raw_buf);
                                        let res = tx
                                            .lock()
                                            .unwrap()
                                            //TODO: I don't like this vec::new() call, it's pointless
                                            .blocking_send((Ok(saved_data.len()), Some(Vec::new())));
                                        match res {
                                            Ok(_) => {
                                                eprintln!("Blocking send is ok");
                                            }
                                            Err(e) => {
                                                eprintln!("Error is {}", e.to_string());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("TLS Error is {}", e.to_string());
                                        //TODO: This is bad, very bad, needs fix
                                        tx.lock()
                                            .unwrap()
                                            .blocking_send((Ok(0), Some(Vec::new())))
                                            .unwrap();
                                        }
                                }
                            }
                            Err(e) => {
                                tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                            }
                        }
                    }
                    waker.wake();
                });
                Poll::Pending
            }
            Err(_) => {
                eprintln!("2");
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let tcp = Arc::clone(&self.tcp);
        let tls = Arc::clone(&self.tls);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx);
        tokio::task::spawn_blocking(move || {
            {
                let mut tls = tls.lock().unwrap();
                let mut tcp = tcp.lock().unwrap();
                match tls.complete_io(&mut *tcp) {
                    Ok((_, _)) => {
                        let res = tls.writer().flush();
                        tx.lock()
                            .unwrap()
                            //TODO: I don't like this vec::new() call, it's pointless
                            .blocking_send((Ok(0), Some(Vec::new())))
                            .unwrap();
                    }
                    Err(e) => {
                        tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                    }
                }
            }
            waker.wake();
        });
        match self.rx.lock().unwrap().try_recv() {
            Ok((res, _)) => match res {
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(_) => {
                eprintln!("3");
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            }
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let tcp = Arc::clone(&self.tcp);
        let tls = Arc::clone(&self.tls);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx);
        tokio::task::spawn_blocking(move || {
            {
                let mut tls = tls.lock().unwrap();
                let mut tcp = tcp.lock().unwrap();
                match tls.complete_io(&mut *tcp) {
                    Ok((_, _)) => {
                        let res = tls.send_close_notify();
                        tx.lock()
                            .unwrap()
                            //TODO: I don't like this vec::new() call, it's pointless
                            .blocking_send((Ok(0), Some(Vec::new())))
                            .unwrap();
                    }
                    Err(e) => {
                        tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                    }
                }
            }
            waker.wake();
        });
        match self.rx.lock().unwrap().try_recv() {
            Ok((res, _)) => match res {
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(_) => {
                eprintln!("4");
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let tcp = Arc::clone(&self.tcp);
        let tls = Arc::clone(&self.tls);
        let waker = cx.waker().clone();
        let tx = Arc::clone(&self.tx);
        //TODO: Is there any way to avoid copying all this data?
        let saved_data: Vec<u8> = bufs
            .iter()
            .flat_map(|slice| slice.iter())
            .map(|byte| byte.to_owned())
            .collect();
        tokio::task::spawn_blocking(move || {
            {
                let mut tls = tls.lock().unwrap();
                let mut tcp = tcp.lock().unwrap();
                match tls.complete_io(&mut *tcp) {
                    Ok((_, _)) => {
                        let res = tls.writer().write(&saved_data);
                        tx.lock()
                            .unwrap()
                            //TODO: I don't like this vec::new() call, it's pointless
                            .blocking_send((Ok(saved_data.len()), Some(Vec::new())))
                            .unwrap();
                    }
                    Err(e) => {
                        tx.lock().unwrap().blocking_send((Err(e), None)).unwrap();
                    }
                }
            }
            waker.wake();
        });
        match self.rx.lock().unwrap().try_recv() {
            Ok((res, _)) => match res {
                Ok(sz) => Poll::Ready(Ok(sz)),
                Err(e) => Poll::Ready(Err(e)),
            },
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(_) => {
                eprintln!("5");
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

/*
 * TODO:
 * Here's the plan:
 * Vec<u8> implements write and [u8] implements read
 * We can use this to make a nice and easy synchronous IO interface in an async function
 * This will avoid SyncIoBridge which avoids taking ownership of our async underlying stream
 * Just add some yield calls for good measure, and let it whir away in the background
 */
//fn run_tls_connection<T, U>(conn: T, stream: TcpStream)
//where
//    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync,
//{
//    //let mut bridge = SyncIoBridge::new(stream);
//    //let (tx, rx) = oneshot::channel();
//
//    //tokio::task::spawn(async move || {
//    //    let mut conn: T = rx.blocking_recv().unwrap();
//    //    conn.complete_io(&mut bridge);
//    //});
//    //tx.send(conn);
//}

async fn run_client() {
    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:1337").await.unwrap();

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(DummyCertVerifier {}));

    let rc_config = Arc::new(config);
    let mut client =
        rustls::ClientConnection::new(rc_config, "localhost".try_into().unwrap()).unwrap();

    let mut tls_stream = AsyncTLSConnection::new(stream, client);

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    std::thread::sleep(std::time::Duration::from_secs(3));

    let serialized = serde_json::to_vec(&client_start_handshake(&crypto)).unwrap();
    tls_stream
        .write(&serialized.len().to_be_bytes())
        .await
        .unwrap();
    tls_stream.write(&serialized).await.unwrap();

    println!("Client waiting response");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let packet_len = tls_stream.read_u64().await.unwrap() as usize;

    println!("Client starting loop");

    while bytes_read < packet_len {
        bytes_read += tls_stream.read_buf(&mut read_buff).await.unwrap();
    }
    println!("Client finishing handshake");

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

async fn process(mut stream: TcpStream) {
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            load_certs("test_ecc_cert.pem"),
            load_private_key("test_ecc_key.pem"),
        )
        .expect("bad certificate/key");

    let rc_config = Arc::new(config);
    let mut server = rustls::ServerConnection::new(rc_config).unwrap();

    let mut tls_stream = AsyncTLSConnection::new(stream, server);

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    //let packet_len = tls_stream.read_u64().await.unwrap().try_into().unwrap();
    let packet_len = tls_stream.read_u64().await.unwrap() as usize;
    println!("Incoming client length {packet_len}");
    println!("Counts {bytes_read} {packet_len}");

    read_buff.clear();

    while bytes_read < packet_len {
        bytes_read += tls_stream.read_buf(&mut read_buff).await.unwrap();
    }
    println!("Starting to respond");
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
        let (mut socket, _) = listener.accept().await.unwrap();
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
