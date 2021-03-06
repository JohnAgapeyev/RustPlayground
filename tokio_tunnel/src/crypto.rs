use aead::{Aead, Key, NewAead, Nonce};
use digest::Digest;
use generic_array::typenum::U24;
use generic_array::typenum::U32;
use generic_array::typenum::U64;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use typenum::type_operators::IsEqual;
use typenum::True;
use x25519_dalek::{PublicKey, ReusableSecret};

//TODO: Implement various other parts of crypto
//AEAD tunnel, symmetric key ratcheting, signatures, KDF

pub struct CryptoCtx {
    //Could use StaticSecret if we want serialization for super long term stuff
    privkey: ReusableSecret,
    pubkey: PublicKey,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_counter: u64,
    rx_counter: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ClientHandshake {
    pubkey: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct ServerHandshake {
    pubkey: PublicKey,
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
            tx_counter: 0,
            rx_counter: 0,
        }
    }
}

//Just return the pubkey since I don't need anything more complex at this time
pub fn client_start_handshake(ctx: &CryptoCtx) -> ClientHandshake {
    ClientHandshake { pubkey: ctx.pubkey }
}

pub fn client_finish_handshake<Hash>(crypto: &mut CryptoCtx, response: &ServerHandshake)
where
    Hash: Digest,
    Hash::OutputSize: IsEqual<U64, Output = True>,
{
    let shared = crypto.privkey.diffie_hellman(&response.pubkey);
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

pub fn server_respond_handshake<Hash>(
    crypto: &mut CryptoCtx,
    client: &ClientHandshake,
) -> ServerHandshake
where
    Hash: Digest,
    Hash::OutputSize: IsEqual<U64, Output = True>,
{
    let shared = crypto.privkey.diffie_hellman(&client.pubkey);
    let res = Hash::digest(&shared.to_bytes());
    let (rx, tx) = res.split_at(32);
    crypto.rx_key = rx.try_into().unwrap();
    crypto.tx_key = tx.try_into().unwrap();
    println!(
        "Server is using keys:\n{:02X?}\n{:02X?}",
        crypto.rx_key, crypto.tx_key
    );
    return ServerHandshake {
        pubkey: crypto.pubkey,
    };
}

pub fn encrypt_message<Cipher>(crypto: &mut CryptoCtx, data: &[u8]) -> Vec<u8>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let key = Key::<Cipher>::from_slice(&crypto.tx_key);
    let cipher = Cipher::new(key);
    let nonce_contents = format!("Nonce{:0>19}", crypto.tx_counter);
    println!("Encrypting with nonce:\n{:02X?}", nonce_contents);
    let nonce = Nonce::<Cipher>::from_slice(nonce_contents.as_bytes());
    if crypto.tx_counter != u64::MAX {
        crypto.tx_counter += 1;
    } else {
        panic!("Tx counter overflow");
    }
    //TODO: Probably shouldn't panic on failure
    cipher.encrypt(nonce, data).unwrap()
}

pub fn decrypt_message<Cipher>(crypto: &mut CryptoCtx, data: &[u8]) -> Vec<u8>
where
    Cipher: NewAead,
    Cipher: Aead,
    Cipher::KeySize: IsEqual<U32, Output = True>,
    //TODO: Should probably redo nonce generation to be generic enough for things like AES-GCM that use 96 bit nonces
    Cipher::NonceSize: IsEqual<U24, Output = True>,
{
    let key = Key::<Cipher>::from_slice(&crypto.rx_key);
    let cipher = Cipher::new(key);
    let nonce_contents = format!("Nonce{:0>19}", crypto.rx_counter);
    println!("Decrypting with nonce:\n{:02X?}", nonce_contents);
    let nonce = Nonce::<Cipher>::from_slice(nonce_contents.as_bytes());
    if crypto.rx_counter != u64::MAX {
        crypto.rx_counter += 1;
    } else {
        panic!("Tx counter overflow");
    }
    //TODO: Probably shouldn't panic on failure
    cipher.decrypt(nonce, data).unwrap()
}
