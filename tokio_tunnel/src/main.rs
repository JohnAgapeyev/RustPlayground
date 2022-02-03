use tokio::net::*;
use tokio::io::*;
use blake2::Blake2b;
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::io;
use std::io::*;
use std::mem::size_of;
use std::sync::mpsc::channel;
use std::sync::*;
use std::thread;

mod crypto;
use crate::crypto::*;

const LISTENER_MASK: usize = 1 << (usize::BITS - 1);

#[derive(PartialEq)]
enum NetworkRole {
    CLIENT,
    SERVER,
}

#[derive(PartialEq)]
enum HandshakeState {
    //TODO: This really is a mess, but oh well, not worth fixing atm
    INIT,
    INIT_LEN,
    RESPONSE,
    LEN,
    DATA,
}

#[derive(Serialize, Deserialize, Debug)]
struct TestMessage {
    test: bool,
    msg: String,
}

struct Connection {
    stream: TcpStream,
    role: NetworkRole,
    message_count: u64,
    crypto: CryptoCtx,
    read_buff: Vec<u8>,
    write_buff: Vec<u8>,
    handshake_state: HandshakeState,
    packet_len: usize,
    sent_test: bool,
}

struct Network {
    token_count: usize,
    recv_test: bool,
    need_listen: bool,
}

async fn run_client(orig_port: bool) {
    // Connect to a peer
    let mut stream: TcpStream;
    if orig_port == false {
        stream = TcpStream::connect("127.0.0.1:1337").await.unwrap();
    } else {
        stream = TcpStream::connect("127.0.0.1:1234").await.unwrap();
    }

    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut write_buff: Vec<u8> = Vec::new();
    let mut handshake_state = HandshakeState::INIT;
    let mut packet_len = 0usize;
    let mut sent_test = false;
    let mut bytes_read = 0usize;

    let serialized = serde_json::to_vec(&client_start_handshake(&crypto)).unwrap();
    stream.write(&serialized.len().to_be_bytes()).await.unwrap();
    stream.write(&serialized).await.unwrap();
    handshake_state = HandshakeState::INIT_LEN;

    println!("Client waiting response");

    packet_len = stream.read_u64().await.unwrap().try_into().unwrap();

    println!("Client starting loop");

    while bytes_read < packet_len {
        bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
    }
    println!("Client finishing handshake");

    //Respond to the server handshake response
    handshake_state = HandshakeState::RESPONSE;
    //Respond to the handshake
    let response = serde_json::from_slice(&read_buff[..packet_len]).unwrap();
    client_finish_handshake::<Blake2b>(&mut crypto, &response);
    read_buff.drain(..packet_len);
    handshake_state = HandshakeState::LEN;

    let message = TestMessage {
        test: if sent_test == false { true } else { false },
        msg: format!("Client message {}", message_count),
    };
    let plaintext = serde_json::to_vec(&message).unwrap();
    let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut crypto, &plaintext);
    //TODO: Even nagle doesn't save us, this will literally write 8 bytes to the wire, needs buffering
    stream.write(&ciphertext.len().to_be_bytes()).await.unwrap();
    stream.write(&ciphertext).await.unwrap();
    message_count += 1;
    if sent_test == false {
        sent_test = true;
    }

    loop {
        packet_len = stream.read_u64().await.unwrap().try_into().unwrap();

        bytes_read = 0;
        while bytes_read < packet_len {
            bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
        }

        let plaintext = decrypt_message::<XChaCha20Poly1305>(
            &mut crypto,
            &read_buff[..packet_len],
        );
        let response: TestMessage = serde_json::from_slice(&plaintext).unwrap();
        println!("Client got message: \"{:?}\"", &response);
        read_buff.drain(..packet_len);
        handshake_state = HandshakeState::LEN;
        packet_len = 0;

        let message = TestMessage {
            test: if sent_test == false { true } else { false },
            msg: format!("Client message {}", message_count),
        };
        let plaintext = serde_json::to_vec(&message).unwrap();
        let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut crypto, &plaintext);
        //TODO: Even nagle doesn't save us, this will literally write 8 bytes to the wire, needs buffering
        stream.write(&ciphertext.len().to_be_bytes()).await.unwrap();
        stream.write(&ciphertext).await.unwrap();
        message_count += 1;
        if sent_test == false {
            sent_test = true;
        }
    }
}

async fn process(stream: &mut TcpStream) {
    let mut message_count = 0u64;
    let mut crypto = CryptoCtx::default();
    let mut read_buff: Vec<u8> = Vec::new();
    let mut write_buff: Vec<u8> = Vec::new();
    let mut handshake_state = HandshakeState::INIT;
    let mut packet_len = 0usize;
    let mut sent_test = false;
    let mut bytes_read = 0usize;

    packet_len = stream.read_u64().await.unwrap().try_into().unwrap();
    println!("Incoming client length {packet_len}");
    println!("Counts {bytes_read} {packet_len}");

    read_buff.clear();

    while bytes_read < packet_len {
        bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
    }
    println!("Starting to respond");
    //Respond to the handshake
    let client_handshake =
        serde_json::from_slice(&read_buff[..packet_len]).unwrap();
    let server_response =
        server_respond_handshake::<Blake2b>(&mut crypto, &client_handshake);
    let serialized = serde_json::to_vec(&server_response).unwrap();
    stream.write(&serialized.len().to_be_bytes()).await.unwrap();
    stream.write(&serialized).await.unwrap();
    read_buff.drain(..packet_len);
    message_count += 1;
    handshake_state = HandshakeState::LEN;

    loop {
        packet_len = stream.read_u64().await.unwrap().try_into().unwrap();

        bytes_read = 0;
        while bytes_read < packet_len {
            bytes_read += stream.read_buf(&mut read_buff).await.unwrap();
        }

        let plaintext = decrypt_message::<XChaCha20Poly1305>(
            &mut crypto,
            &read_buff[..packet_len],
        );
        let response: TestMessage = serde_json::from_slice(&plaintext).unwrap();
        println!("Server got message: \"{:?}\"", &response);
        read_buff.drain(..packet_len);
        handshake_state = HandshakeState::LEN;
        packet_len = 0;

        //TODO: This runs into weird recursive issues
        //if response.test {
        //    println!("Creating listener");
        //    tokio::spawn(async move {
        //        // Bind the listener to the address
        //        let listener = TcpListener::bind("127.0.0.1:1234").await.unwrap();

        //        loop {
        //            // The second item contains the IP and port of the new connection.
        //            let (mut socket, _) = listener.accept().await.unwrap();
        //            // A new task is spawned for each inbound socket. The socket is
        //            // moved to the new task and processed there.
        //            tokio::spawn(async move {
        //                process(&mut socket).await;
        //            });
        //        }
        //    });
        //}


        let message = TestMessage {
            test: if sent_test == false { true } else { false },
            msg: format!("Server message {}", message_count),
        };
        let plaintext = serde_json::to_vec(&message).unwrap();
        let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut crypto, &plaintext);
        //TODO: Even nagle doesn't save us, this will literally write 8 bytes to the wire, needs buffering
        stream.write(&ciphertext.len().to_be_bytes()).await.unwrap();
        stream.write(&ciphertext).await.unwrap();
        message_count += 1;
        if sent_test == false {
            sent_test = true;
        }
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
    let mut port_choice = false;

    //I'm not insane enough to start digging into CLI options to begin with
    for arg in env::args().skip(1) {
        if arg == "-s" {
            client = false;
            break;
        }
        if arg == "-1" {
            port_choice = false;
            break;
        }
        if arg == "-2" {
            port_choice = true;
            break;
        }
    }
    println!("Are we a client? {}", client);
    if client {
        run_client(port_choice).await;
    } else {
        run_server().await;
    }
}
