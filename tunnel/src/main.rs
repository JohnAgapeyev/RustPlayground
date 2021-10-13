use std::env;
use std::io;
use std::io::*;
use std::prelude::*;
use std::error::Error;
use std::collections::HashMap;
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
struct Client {
    stream: TcpStream,
    //let mut connections = HashMap::<Token, TcpStream>::new(),
}

fn get_unique_token(token_count: &mut usize, listener: bool) -> Token {
    let ret = Token(*token_count + 1 + if listener {LISTENER_MASK} else {0});
    *token_count += 1;
    return ret;
}

fn client_read() {

}

fn client_write() {

}

fn server_read() {

}

fn server_write() {
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

fn run_event_loop(poll: &mut Poll, token_count: &mut usize, stream: Option<&mut TcpStream>, listener: Option<&mut TcpListener>, is_server: bool) {
    let mut events = Events::with_capacity(128);
    let mut connections = HashMap::<Token, TcpStream>::new();

    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            println!("Poll failed with error {}", e);
            return;
        }

        for event in events.iter() {
            match event.token() {
                listener_token if event.is_readable() && (listener_token.0 & LISTENER_MASK != 0) => {
                    //let mut listener = connections.get_mut(&listener).unwrap();
                    let (mut socket, _) = listener.unwrap().accept().unwrap();
                    let client_token = get_unique_token(token_count, false);
                    poll.registry().register(&mut socket, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();
                    connections.insert(client_token, socket);
                },
                connection => {
                    //let stream = connections.get_mut(&connection).unwrap();
                    let stream = stream.unwrap();
                    if event.is_readable() {
                        if is_server {
                            server_read();
                        } else {
                            client_read();
                        }
                    }
                    if event.is_writable() {
                        if is_server {
                            server_write();
                        } else {
                            client_write();
                        }
                    }
                }
            }
        }
    }
}

fn run_client() {
    let mut poll = Poll::new().unwrap();
    let mut token_count: usize = 0;

    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:1337".parse().unwrap()).unwrap();

    let client_token = get_unique_token(&mut token_count, false);

    poll.registry().register(&mut stream, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();

    run_event_loop(&mut poll, &mut token_count, Some(&mut stream), None, false);
}

fn run_server() {
    let mut poll = Poll::new().unwrap();
    let mut token_count: usize = 0;

    let mut listener = TcpListener::bind("127.0.0.1:1337".parse().unwrap()).unwrap();

    let listener_token = get_unique_token(&mut token_count, false);

    poll.registry().register(&mut listener, listener_token, Interest::READABLE).unwrap();

    run_event_loop(&mut poll, &mut token_count, None, Some(&mut listener), true);
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

