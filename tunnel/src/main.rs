//use aes_gcm::Aes128Gcm;
//use aes_gcm::Aes256Gcm;
use blake2::Blake2b;
//use blake2::Blake2s;
//se blake2::VarBlake2b;
use chacha20poly1305::XChaCha20Poly1305;
use mio::event::*;
use mio::net::*;
use mio::*;
use serde::{Deserialize, Serialize};
//use sha2::Sha256;
//use sha2::Sha384;
//use sha2::Sha512;
//use sha2::Sha512Trunc256;
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

fn get_unique_token(token_count: &mut usize, listener: bool) -> Token {
    let val = *token_count + 1 + if listener { LISTENER_MASK } else { 0 };
    let ret = Token(val);
    *token_count += 1;
    return ret;
}

fn client_read(conn: &mut Connection) {
    //TODO: This is a hack for len->data packetization, needs a better solution eventually
    let mut need_processing = true;
    match conn.stream.read_to_end(&mut conn.read_buff) {
        Ok(_) => {}
        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return,
    }
    if conn.read_buff.len() == 0 {
        return;
    }
    while need_processing == true {
        need_processing = false;
        match conn.handshake_state {
            HandshakeState::INIT => panic!("Should never happen"),
            HandshakeState::INIT_LEN => {
                //Respond to the server handshake response
                let size_size = size_of::<usize>();
                conn.packet_len =
                    usize::from_be_bytes(conn.read_buff[..size_size].try_into().unwrap());
                conn.read_buff.drain(..size_size);
                conn.handshake_state = HandshakeState::RESPONSE;
                if conn.read_buff.len() > 0 {
                    need_processing = true;
                }
            }
            HandshakeState::RESPONSE => {
                //Respond to the handshake
                let response = serde_json::from_slice(&conn.read_buff[..conn.packet_len]).unwrap();
                client_finish_handshake::<Blake2b>(&mut conn.crypto, &response);
                conn.read_buff.drain(..conn.packet_len);
                conn.handshake_state = HandshakeState::LEN;
            }
            HandshakeState::LEN => {
                let size_size = size_of::<usize>();
                conn.packet_len =
                    usize::from_be_bytes(conn.read_buff[..size_size].try_into().unwrap());
                conn.read_buff.drain(..size_size);
                conn.handshake_state = HandshakeState::DATA;
                need_processing = true;
            }
            HandshakeState::DATA => {
                if conn.read_buff.len() < conn.packet_len {
                    //Not enough data
                    return;
                }
                let plaintext = decrypt_message::<XChaCha20Poly1305>(
                    &mut conn.crypto,
                    &conn.read_buff[..conn.packet_len],
                );
                let response: TestMessage = serde_json::from_slice(&plaintext).unwrap();
                println!("Client got message: \"{:?}\"", &response);
                conn.read_buff.drain(..conn.packet_len);
                conn.handshake_state = HandshakeState::LEN;
                conn.packet_len = 0;
            }
        }
    }
}

fn client_write(conn: &mut Connection) {
    match conn.handshake_state {
        HandshakeState::INIT => {
            let serialized = serde_json::to_vec(&client_start_handshake(&conn.crypto)).unwrap();
            conn.stream.write(&serialized.len().to_be_bytes()).unwrap();
            conn.stream.write(&serialized).unwrap();
            conn.handshake_state = HandshakeState::INIT_LEN;
        }
        HandshakeState::INIT_LEN => {}
        HandshakeState::RESPONSE => {}
        HandshakeState::LEN | HandshakeState::DATA => {
            let message = TestMessage {
                test: if conn.sent_test == false { true } else { false },
                msg: format!("Client message {}", conn.message_count),
            };
            let plaintext = serde_json::to_vec(&message).unwrap();
            let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut conn.crypto, &plaintext);
            //TODO: Even nagle doesn't save us, this will literally write 8 bytes to the wire, needs buffering
            conn.stream.write(&ciphertext.len().to_be_bytes()).unwrap();
            conn.stream.write(&ciphertext).unwrap();
            conn.message_count += 1;
            if conn.sent_test == false {
                conn.sent_test = true;
            }
        }
    }
    //println!("Client write");
}

fn server_read(conn: &mut Connection, ctx: &mut Network) {
    //TODO: This is a hack for len->data packetization, needs a better solution eventually
    let mut need_processing = true;
    match conn.stream.read_to_end(&mut conn.read_buff) {
        Ok(_) => {}
        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return,
    }
    if conn.read_buff.len() == 0 {
        return;
    }
    while need_processing == true {
        need_processing = false;
        match conn.handshake_state {
            HandshakeState::INIT => {
                //Respond to the server handshake response
                let size_size = size_of::<usize>();
                conn.packet_len =
                    usize::from_be_bytes(conn.read_buff[..size_size].try_into().unwrap());
                conn.read_buff.drain(..size_size);
                conn.handshake_state = HandshakeState::INIT_LEN;
                if conn.read_buff.len() > 0 {
                    need_processing = true;
                }
            }
            HandshakeState::INIT_LEN => {
                //Respond to the handshake
                let client_handshake =
                    serde_json::from_slice(&conn.read_buff[..conn.packet_len]).unwrap();
                let server_response =
                    server_respond_handshake::<Blake2b>(&mut conn.crypto, &client_handshake);
                let serialized = serde_json::to_vec(&server_response).unwrap();
                conn.stream.write(&serialized.len().to_be_bytes()).unwrap();
                conn.stream.write(&serialized).unwrap();
                conn.read_buff.drain(..conn.packet_len);
                conn.message_count += 1;
                conn.handshake_state = HandshakeState::LEN;
            }
            HandshakeState::RESPONSE => panic!("Should never happen"),
            HandshakeState::LEN => {
                let size_size = size_of::<usize>();
                conn.packet_len =
                    usize::from_be_bytes(conn.read_buff[..size_size].try_into().unwrap());
                conn.read_buff.drain(..size_size);
                conn.handshake_state = HandshakeState::DATA;
                need_processing = true;
            }
            HandshakeState::DATA => {
                if conn.read_buff.len() < conn.packet_len {
                    //Not enough data
                    return;
                }
                let plaintext = decrypt_message::<XChaCha20Poly1305>(
                    &mut conn.crypto,
                    &conn.read_buff[..conn.packet_len],
                );
                let response: TestMessage = serde_json::from_slice(&plaintext).unwrap();
                println!("Server got message: \"{:?}\"", &response);
                conn.read_buff.drain(..conn.packet_len);
                conn.handshake_state = HandshakeState::LEN;
                conn.packet_len = 0;
                if response.test == true && ctx.recv_test == false {
                    ctx.recv_test = true;
                    ctx.need_listen = true;
                }
            }
        }
    }
}

fn server_write(conn: &mut Connection) {
    match conn.handshake_state {
        HandshakeState::INIT => {}
        HandshakeState::INIT_LEN => {}
        HandshakeState::RESPONSE => {}
        HandshakeState::LEN | HandshakeState::DATA => {}
    }
    if conn.handshake_state == HandshakeState::LEN {
        //println!("Server write");
        let message = TestMessage {
            test: if conn.sent_test == false { true } else { false },
            msg: format!("Server message {}", conn.message_count),
        };
        let plaintext = serde_json::to_vec(&message).unwrap();
        let ciphertext = encrypt_message::<XChaCha20Poly1305>(&mut conn.crypto, &plaintext);
        //TODO: Even nagle doesn't save us, this will literally write 8 bytes to the wire, needs buffering
        conn.stream.write(&ciphertext.len().to_be_bytes()).unwrap();
        conn.stream.write(&ciphertext).unwrap();
        conn.message_count += 1;
        if conn.sent_test == false {
            conn.sent_test = true;
        }
        //match stream.write(format!("goodbye world {}", msg_count).as_bytes()) {
        //    Ok(_n) => {
        //        msg_count += 1;
        //        println!("Client {} sent msg {}", connection.0, msg_count);
        //        continue;
        //    }
        //    Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {
        //        continue;
        //    }
        //    Err(_e) => {
        //        break;
        //    }
        //}
    }
}

fn process_read_event(conn: &mut Connection, ctx: &mut Network) {
    println!("Process read event");
    match conn.role {
        NetworkRole::CLIENT => client_read(conn),
        NetworkRole::SERVER => server_read(conn, ctx),
    }
}

fn process_write_event(conn: &mut Connection) {
    println!("Process write event");
    match conn.role {
        NetworkRole::CLIENT => client_write(conn),
        NetworkRole::SERVER => server_write(conn),
    }
}

fn run_event_loop(
    poll: Arc<Mutex<Poll>>,
    ctx: Arc<Mutex<Network>>,
    listeners: Arc<Mutex<HashMap<Token, TcpListener>>>,
    connections: Arc<Mutex<HashMap<Token, Connection>>>,
) {
    let mut events = Events::with_capacity(128);

    let (tx, rx) = channel();

    {
        let ctx = Arc::clone(&ctx);
        let listeners = Arc::clone(&listeners);
        let connections = Arc::clone(&connections);
        let registry = poll.lock().unwrap().registry();
        thread::spawn(move || loop {
            let (readable, writable, tok): (bool, bool, Token) = rx.recv().unwrap();
            println!("Got an event in the worker thread");
            let mut conn_lock = connections.lock().unwrap();
            let mut conn = conn_lock.get_mut(&tok).unwrap();
            if readable == true {
                println!("Starting process read");
                let mut ctx_lock = ctx.lock().unwrap();
                println!("Test 4");
                println!("Test 5");
                process_read_event(conn, &mut ctx_lock);
            }
            if writable == true {
                process_write_event(conn);
            }
        });
    }

    loop {
        {
            if let Err(e) = poll.lock().unwrap().poll(&mut events, None) {
                println!("Poll failed with error {}", e);
                break;
            }
        }

        for event in events.iter() {
            match event.token() {
                listener_token
                    if event.is_readable() && (listener_token.0 & LISTENER_MASK != 0) =>
                {
                    println!("Server listener hit");
                    let mut listener_lock = listeners.lock().unwrap();
                    println!("Test 1");
                    let listener = listener_lock.get_mut(&listener_token).unwrap();
                    println!("Test 2");
                    let (mut stream, _) = listener.accept().unwrap();
                    println!("Test 3");
                    let client_token =
                        get_unique_token(&mut ctx.lock().unwrap().token_count, false);
                    println!("Here");
                    poll.lock()
                        .unwrap()
                        .registry()
                        .register(
                            &mut stream,
                            client_token,
                            Interest::READABLE | Interest::WRITABLE,
                        )
                        .unwrap();
                    let conn = Connection {
                        stream,
                        role: NetworkRole::SERVER,
                        message_count: 0,
                        crypto: CryptoCtx::default(),
                        read_buff: Vec::with_capacity(4096),
                        write_buff: Vec::with_capacity(4096),
                        handshake_state: HandshakeState::INIT,
                        packet_len: 0,
                        sent_test: false,
                    };
                    connections.lock().unwrap().insert(client_token, conn);
                    println!("Server listener done work");
                }
                connection_token => {
                    println!("Sending a connection event {:?}", event);
                    tx.send((event.is_readable(), event.is_writable(), connection_token))
                        .unwrap();
                }
            }
        }
        let mut ctx_lock = ctx.lock().unwrap();
        if ctx_lock.need_listen == true {
            let mut listener = TcpListener::bind("127.0.0.1:1234".parse().unwrap()).unwrap();
            let listener_token = get_unique_token(&mut ctx_lock.token_count, true);
            poll.lock()
                .unwrap()
                .registry()
                .register(&mut listener, listener_token, Interest::READABLE)
                .unwrap();
            listeners.lock().unwrap().insert(listener_token, listener);
            ctx_lock.need_listen = false;
        }
    }
    //worker_thread.join().unwrap();
}

fn run_client(orig_port: bool) {
    let mut poll = Arc::new(Mutex::new(Poll::new().unwrap()));
    let ctx = Arc::new(Mutex::new(Network {
        token_count: 0,
        recv_test: false,
        need_listen: false,
    }));
    let listeners = Arc::new(Mutex::new(HashMap::new()));
    let connections = Arc::new(Mutex::new(HashMap::new()));

    // Connect to a peer
    let mut stream: TcpStream;
    if orig_port == false {
        stream = TcpStream::connect("127.0.0.1:1337".parse().unwrap()).unwrap();
    } else {
        stream = TcpStream::connect("127.0.0.1:1234".parse().unwrap()).unwrap();
    }
    let client_token = get_unique_token(&mut ctx.lock().unwrap().token_count, false);
    poll.lock()
        .unwrap()
        .registry()
        .register(
            &mut stream,
            client_token,
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();

    let conn = Connection {
        stream,
        role: NetworkRole::CLIENT,
        message_count: 0,
        crypto: CryptoCtx::default(),
        read_buff: Vec::with_capacity(4096),
        write_buff: Vec::with_capacity(4096),
        handshake_state: HandshakeState::INIT,
        packet_len: 0,
        sent_test: false,
    };

    connections.lock().unwrap().insert(client_token, conn);

    run_event_loop(poll, ctx, listeners, connections);
}

fn run_server() {
    let mut poll = Arc::new(Mutex::new(Poll::new().unwrap()));
    let ctx = Arc::new(Mutex::new(Network {
        token_count: 0,
        recv_test: false,
        need_listen: false,
    }));
    let listeners = Arc::new(Mutex::new(HashMap::new()));
    let connections = Arc::new(Mutex::new(HashMap::new()));

    let mut listener = TcpListener::bind("127.0.0.1:1337".parse().unwrap()).unwrap();
    let listener_token = get_unique_token(&mut ctx.lock().unwrap().token_count, true);
    poll.lock()
        .unwrap()
        .registry()
        .register(&mut listener, listener_token, Interest::READABLE)
        .unwrap();

    listeners.lock().unwrap().insert(listener_token, listener);

    run_event_loop(poll, ctx, listeners, connections);
}

fn main() {
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
        run_client(port_choice);
    } else {
        run_server();
    }
}
