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

struct Network {
    poll: Poll,
    listeners: HashMap<Token, TcpListener>,
    connections: HashMap<Token, TcpStream>,
    token_count: usize,
    role: NetworkRole,
}

fn get_unique_token(token_count: &mut usize, listener: bool) -> Token {
    let ret = Token(*token_count + 1 + if listener {LISTENER_MASK} else {0});
    *token_count += 1;
    return ret;
}

fn client_read(stream: &mut TcpStream, ctx: &mut Network) {
    //let mut stream = ctx.connections.get_mut(&token).unwrap();
    //stream.write(b"Testing");
}

fn client_write(ctx: &mut Network) {

}

fn server_read(ctx: &mut Network) {

}

fn server_write(ctx: &mut Network) {
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

fn process_read_event(token: Token, ctx: &mut Network) {
    let stream = ctx.connections.get_mut(&token).unwrap();
    client_read(stream, ctx);
}

fn process_write_event(ctx: &mut Network) {

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
                    let (mut socket, _) = listener.accept().unwrap();
                    let client_token = get_unique_token(&mut ctx.token_count, false);
                    ctx.poll.registry().register(&mut socket, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();
                    ctx.connections.insert(client_token, socket);
                },
                connection_token => {
                    //let mut stream = ctx.connections.get_mut(&connection_token).unwrap();
                    if event.is_readable() {
                        process_read_event(connection_token, ctx);
                        if ctx.role == NetworkRole::SERVER {
                            //server_read(ctx);
                        } else {
                            //client_read(connection_token, ctx);
                        }
                    }
                    if event.is_writable() {
                        if ctx.role == NetworkRole::SERVER {
                            server_write(ctx);
                        } else {
                            client_write(ctx);
                        }
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
        role: NetworkRole::CLIENT,
        token_count: 0,
    };

    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:1337".parse().unwrap()).unwrap();
    let client_token = get_unique_token(&mut ctx.token_count, false);
    ctx.poll.registry().register(&mut stream, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();
    ctx.connections.insert(client_token, stream);

    run_event_loop(&mut ctx);
}

fn run_server() {
    let mut ctx = Network {
        poll: Poll::new().unwrap(),
        listeners: HashMap::new(),
        connections: HashMap::new(),
        role: NetworkRole::SERVER,
        token_count: 0,
    };

    let mut listener = TcpListener::bind("127.0.0.1:1337".parse().unwrap()).unwrap();
    let listener_token = get_unique_token(&mut ctx.token_count, false);
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

