#![allow(unused_imports)]

use blake2::Blake2b;
use bytes::{Buf, BytesMut};
use chacha20poly1305::XChaCha20Poly1305;
use futures::sink::{self, SinkExt};
use futures::stream::{self, StreamExt};
use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::{Certificate, ClientConfig, ConnectionCommon, ServerName, SignatureScheme};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::marker::PhantomData;
use std::marker::Send;
use std::marker::Sync;
use std::mem::size_of;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::*;
use std::thread;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
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
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Vec::new()
    }
    fn request_scts(&self) -> bool {
        false
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
fn run_tls_connection<T, U>(conn: T, stream: TcpStream)
where
    T: DerefMut<Target = ConnectionCommon<U>> + Send + Sync,
{
    let mut bridge = SyncIoBridge::new(stream);
    let (tx, rx) = oneshot::channel();

    tokio::task::spawn(async move || {
        let mut conn: T = rx.blocking_recv().unwrap();
        conn.complete_io(&mut bridge);
    });
    tx.send(conn);
}

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
    /*
     * TODO: Next steps:
     *  - Set up a background TLS traffic task (use complete_io with SyncIoBridge on the tokio
     *  TcpStream)
     *  - Implement AsyncRead + AsyncWrite on the connection
     *  - Make sure error handling will not be ignored or randomly panic if we don't want it to
     */
    let mut client =
        rustls::ClientConnection::new(rc_config, "localhost".try_into().unwrap()).unwrap();

    run_tls_connection(client, stream);

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    let serialized = serde_json::to_vec(&client_start_handshake(&crypto)).unwrap();
    stream.write(&serialized.len().to_be_bytes()).await.unwrap();
    stream.write(&serialized).await.unwrap();

    println!("Client waiting response");

    let packet_len = stream.read_u64().await.unwrap().try_into().unwrap();

    println!("Client starting loop");

    while bytes_read < packet_len {
        bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
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

    let mut framed = Framed::new(stream, pipeline);

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

async fn process(stream: &mut TcpStream) {
    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut bytes_read = 0usize;

    let packet_len = stream.read_u64().await.unwrap().try_into().unwrap();
    println!("Incoming client length {packet_len}");
    println!("Counts {bytes_read} {packet_len}");

    read_buff.clear();

    while bytes_read < packet_len {
        bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
    }
    println!("Starting to respond");
    //Respond to the handshake
    let client_handshake = serde_json::from_slice(&read_buff[..packet_len]).unwrap();
    let server_response = server_respond_handshake::<Blake2b>(&mut crypto, &client_handshake);
    let serialized = serde_json::to_vec(&server_response).unwrap();
    stream.write(&serialized.len().to_be_bytes()).await.unwrap();
    stream.write(&serialized).await.unwrap();
    read_buff.drain(..packet_len);
    message_count += 1;

    let pipeline = IOPipeline::<TestMessage> {
        marker: PhantomData,
        crypto: crypto,
    };

    let mut framed = Framed::new(stream, pipeline);

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
            process(&mut socket).await;
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
