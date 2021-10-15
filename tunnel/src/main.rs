use std::env;
use std::io;
use std::io::*;
use std::prelude::*;
use std::error::Error;
use std::collections::HashMap;
use std::cmp::PartialEq;
use mio::*;
use mio::net::*;

const LISTENER_MASK: usize = 1 << (usize::BITS - 1);

//TODO: Do we want client/server god structs?
//Creating the hashmap to store TCP streams and listeners is a type punning pain
//Probably need to just make a custom enum, or Box everything up, or something
//Point being, handling this in the generic way I _want_ to handle this is not going well
//Maybe I just make all the handling stuff actually generic based on traits
//The Mio TCP/Unix listeners are not distinct from streams based on traits though...
//Probably need some custom wrapping type of something, don't know what yet though

#[derive(PartialEq)]
enum NetworkRole {
    CLIENT,
    SERVER,
}

struct Connection {
    stream: TcpStream,
    role: NetworkRole,
    message_count: u64,
}

struct Network {
    poll: Poll,
    listeners: HashMap<Token, TcpListener>,
    connections: HashMap<Token, Connection>,
    token_count: usize,
}

fn get_unique_token(token_count: &mut usize, listener: bool) -> Token {
    let val = (*token_count + 1 + if listener {LISTENER_MASK} else {0});
    let ret = Token(val);
    *token_count += 1;
    return ret;
}

fn client_read(conn: &mut Connection) {
    let mut buff = Vec::with_capacity(4096);
    match conn.stream.read_to_end(&mut buff) {
        Ok(_) => {}
        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return
    }
    println!("Client got message: \"{}\"", String::from_utf8(buff).unwrap());
}

fn client_write(conn: &mut Connection) {
    conn.stream.write(format!("Client message {}", conn.message_count).as_bytes());
    conn.message_count += 1;
}

fn server_read(conn: &mut Connection) {
    let mut buff = Vec::with_capacity(4096);
    match conn.stream.read_to_end(&mut buff) {
        Ok(_) => {}
        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return
    }
    println!("Server got message: \"{}\"", String::from_utf8(buff).unwrap());
}

fn server_write(conn: &mut Connection) {
    conn.stream.write(format!("Server message {}", conn.message_count).as_bytes());
    conn.message_count += 1;
//    match stream.write(format!("goodbye world {}", msg_count).as_bytes()) {
//        Ok(_n) => {
//            msg_count += 1;
//            println!("Client {} sent msg {}", connection.0, msg_count);
//            continue;
//        }
//        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {
//            continue;
//        }
//        Err(_e) => {
//            break;
//        }
//    }
}

fn process_read_event(conn: &mut Connection) {
    match conn.role {
        NetworkRole::CLIENT => client_read(conn),
        NetworkRole::SERVER => server_read(conn),
    }
}

fn process_write_event(conn: &mut Connection) {
    match conn.role {
        NetworkRole::CLIENT => client_write(conn),
        NetworkRole::SERVER => server_write(conn),
    }
}

fn run_event_loop(ctx: &mut Network) {
    let mut events = Events::with_capacity(128);

    loop {
        if let Err(e) = ctx.poll.poll(&mut events, None) {
            println!("Poll failed with error {}", e);
            return;
        }

        for event in events.iter() {
            match event.token() {
                listener_token if event.is_readable() && (listener_token.0 & LISTENER_MASK != 0) => {
                    let listener = ctx.listeners.get_mut(&listener_token).unwrap();
                    let (mut stream, _) = listener.accept().unwrap();
                    let client_token = get_unique_token(&mut ctx.token_count, false);
                    ctx.poll.registry().register(&mut stream, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();
                    let conn = Connection {
                        stream,
                        role: NetworkRole::SERVER,
                        message_count: 0,
                    };
                    ctx.connections.insert(client_token, conn);
                },
                connection_token => {
                    let mut conn = ctx.connections.get_mut(&connection_token).unwrap();
                    if event.is_readable() {
                        process_read_event(conn);
                    }
                    if event.is_writable() {
                        process_write_event(conn);
                    }
                }
            }
        }
    }
}

fn run_client() {
    let mut ctx = Network {
        poll: Poll::new().unwrap(),
        listeners: HashMap::new(),
        connections: HashMap::new(),
        token_count: 0,
    };

    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:1337".parse().unwrap()).unwrap();
    let client_token = get_unique_token(&mut ctx.token_count, false);
    ctx.poll.registry().register(&mut stream, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();

    let conn = Connection {
        stream,
        role: NetworkRole::CLIENT,
        message_count: 0,
    };

    ctx.connections.insert(client_token, conn);

    run_event_loop(&mut ctx);
}

fn run_server() {
    let mut ctx = Network {
        poll: Poll::new().unwrap(),
        listeners: HashMap::new(),
        connections: HashMap::new(),
        token_count: 0,
    };

    let mut listener = TcpListener::bind("127.0.0.1:1337".parse().unwrap()).unwrap();
    let listener_token = get_unique_token(&mut ctx.token_count, true);
    ctx.poll.registry().register(&mut listener, listener_token, Interest::READABLE).unwrap();
    ctx.listeners.insert(listener_token, listener);

    run_event_loop(&mut ctx);
}

fn main() {
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
        run_client();
    } else {
        run_server();
    }
}

