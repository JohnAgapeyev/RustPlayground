use std::env;
use std::io;
use std::io::*;
use std::collections::HashMap;
use std::cmp::PartialEq;
use std::convert::TryInto;
use mio::*;
use mio::net::*;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, ReusableSecret, PublicKey};
use blake2::Blake2b;
use blake2::Digest;
use generic_array::GenericArray;
use generic_array::typenum::U32;
use generic_array::typenum::U64;

use crate::Connection;

//Just return the pubkey since I don't need anything more complex at this time
pub fn client_start_handshake(conn: &Connection) -> [u8; 32] {
    *conn.pubkey.as_bytes()
}

pub fn client_finish_handshake(conn: &mut Connection, data: &[u8; 32]) {
    let server_pubkey = PublicKey::from(*data);
    let shared = conn.privkey.diffie_hellman(&server_pubkey);
    let res = Blake2b::digest(&shared.to_bytes());
    //Backwards from the server to ensure equivalent keys
    let (tx, rx) = res.split_at(32);
    conn.rx_key = rx.try_into().unwrap();
    conn.tx_key = tx.try_into().unwrap();
    println!("Client is using keys:\n{:02X?}\n{:02X?}", conn.rx_key, conn.tx_key);
}

pub fn server_respond_handshake(conn: &mut Connection, data: &[u8; 32]) {
    let client_pubkey = PublicKey::from(*data);
    let shared = conn.privkey.diffie_hellman(&client_pubkey);
    let res = Blake2b::digest(&shared.to_bytes());
    let (rx, tx) = res.split_at(32);
    conn.rx_key = rx.try_into().unwrap();
    conn.tx_key = tx.try_into().unwrap();
    conn.stream.write(conn.pubkey.as_bytes());
    println!("Server is using keys:\n{:02X?}\n{:02X?}", conn.rx_key, conn.tx_key);
}

