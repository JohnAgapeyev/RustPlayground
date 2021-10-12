use std::env;
use std::io;
use tokio::net::*;
use tokio::time;
use tokio::time::*;

async fn run_client() {
    // Connect to a peer
    let stream = TcpStream::connect("127.0.0.1:1337").await.unwrap();

        let mut interval = time::interval(Duration::from_secs(1));
        let mut msg_count = 0;
        loop {
            interval.tick().await;
            stream.writable().await.unwrap();

            // Try to write data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            match stream.try_write(format!("goodbye world {}", msg_count).as_bytes()) {
                Ok(n) => {
                    msg_count += 1;
                    println!("Client sent msg {}", msg_count);
                    continue;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    panic!("Client error I also don't fully understand");
                }
            }
        }
}

async fn run_server() {
    let listener = TcpListener::bind("127.0.0.1:1337").await.unwrap();

    loop {
        // The second item contains the IP and port of the new connection.
        let (socket, _) = listener.accept().await.unwrap();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            let mut msg_count = 0;
            loop {
                interval.tick().await;
                socket.writable().await;
                // Try to write data, this may still fail with `WouldBlock`
                // if the readiness event is a false positive.
                match socket.try_write(format!("hello world {}", msg_count).as_bytes()) {
                    Ok(n) => {
                        msg_count += 1;
                        println!("Server sent msg {}", msg_count);
                        continue;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        panic!("I have no clue how to handle this or the resulting errors");
                    }
                }
            }
        });
    }
}

#[tokio::main]
pub async fn main() {
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
