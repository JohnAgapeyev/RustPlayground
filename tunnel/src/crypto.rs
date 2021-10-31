use blake2::Blake2b;
use digest::Digest;
use digest::FixedOutput;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use generic_array::typenum::U7;
use generic_array::ArrayLength;
use rand::rngs::OsRng;
use std::cmp::Ordering;
use std::convert::TryInto;
use typenum::operator_aliases::Eq;
use typenum::type_operators::Cmp;
use typenum::type_operators::IsEqual;
use typenum::type_operators::IsGreaterOrEqual;
use typenum::True;
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret};

use crate::Connection;

//TODO: Implement various other parts of crypto
//AEAD tunnel, symmetric key ratcheting, signatures, KDF

pub struct CryptoCtx {
    //Could use StaticSecret if we want serialization for super long term stuff
    privkey: ReusableSecret,
    pubkey: PublicKey,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
}

impl Default for CryptoCtx {
    fn default() -> Self {
        let privkey = ReusableSecret::new(OsRng);
        let pubkey = PublicKey::from(&privkey);
        CryptoCtx {
            privkey,
            pubkey,
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
        }
    }
}

//Just return the pubkey since I don't need anything more complex at this time
pub fn client_start_handshake(ctx: &CryptoCtx) -> [u8; 32] {
    *ctx.pubkey.as_bytes()
}

pub fn client_finish_handshake<Hash>(crypto: &mut CryptoCtx, data: &[u8; 32])
where
    Hash: Digest,
    Hash: FixedOutput,
    <Hash as Digest>::OutputSize: IsEqual<U64, Output = True>,
{
    let server_pubkey = PublicKey::from(*data);
    let shared = crypto.privkey.diffie_hellman(&server_pubkey);
    let res = Hash::digest(&shared.to_bytes());
    //Backwards from the server to ensure equivalent keys
    let (tx, rx) = res.split_at(32);
    crypto.rx_key = rx.try_into().unwrap();
    crypto.tx_key = tx.try_into().unwrap();
    println!(
        "Client is using keys:\n{:02X?}\n{:02X?}",
        crypto.rx_key, crypto.tx_key
    );
}

pub fn server_respond_handshake<Hash>(crypto: &mut CryptoCtx, data: &[u8; 32]) -> [u8; 32]
where
    Hash: Digest,
    Hash: FixedOutput,
    <Hash as Digest>::OutputSize: IsEqual<U64, Output = True>,
{
    let client_pubkey = PublicKey::from(*data);
    let shared = crypto.privkey.diffie_hellman(&client_pubkey);
    let res = Hash::digest(&shared.to_bytes());
    let (rx, tx) = res.split_at(32);
    crypto.rx_key = rx.try_into().unwrap();
    crypto.tx_key = tx.try_into().unwrap();
    println!(
        "Server is using keys:\n{:02X?}\n{:02X?}",
        crypto.rx_key, crypto.tx_key
    );
    return *crypto.pubkey.as_bytes();
}
