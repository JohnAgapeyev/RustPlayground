use std::env;
use std::io;
use std::io::*;
use std::collections::HashMap;
use mio::*;
use mio::net::*;

const CLIENT: Token = Token(0);
const SERVER: Token = Token(1);

fn run_client() {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);
    // Connect to a peer
    let mut stream = TcpStream::connect("127.0.0.1:1337".parse().unwrap()).unwrap();

    poll.registry().register(&mut stream, CLIENT, Interest::READABLE | Interest::WRITABLE).unwrap();

    //let mut interval = time::interval(Duration::from_secs(1));
    let mut msg_count = 0;
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                CLIENT if event.is_writable() => {
                    match stream.write(format!("goodbye world {}", msg_count).as_bytes()) {
                        Ok(_n) => {
                            msg_count += 1;
                            println!("Client sent msg {}", msg_count);
                            continue;
                        }
                        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(_e) => {
                            break;
                        }
                    }
                },
                _ => panic!("What even is this?")
            }
        }

    }
}

fn run_server() {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    let mut listener = TcpListener::bind("127.0.0.1:1337".parse().unwrap()).unwrap();

    poll.registry().register(&mut listener, SERVER, Interest::READABLE).unwrap();

    let mut msg_count = 0;
    let mut client_count = 0;

    let mut connections = HashMap::new();

    loop {
        // The second item contains the IP and port of the new connection.
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                SERVER if event.is_readable() => {
                    let (mut socket, _) = listener.accept().unwrap();
                    let client_token = Token(2 + client_count);
                    poll.registry().register(&mut socket, client_token, Interest::READABLE | Interest::WRITABLE).unwrap();
                    connections.insert(client_token, socket);
                    client_count += 1;
                },
                CLIENT => panic!("Should never happen"),
                token if event.is_writable() => {
                    let stream = connections.get_mut(&token).unwrap();
                    match stream.write(format!("goodbye world {}", msg_count).as_bytes()) {
                        Ok(_n) => {
                            msg_count += 1;
                            println!("Client {} sent msg {}", token.0, msg_count);
                            continue;
                        }
                        Err(ref _e) if _e.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(_e) => {
                            break;
                        }
                    }
                }
                _ => return
            }
        }
    }
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
