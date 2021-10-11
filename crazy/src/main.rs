use libc::{sysconf, _SC_PAGESIZE};
use std::convert::TryInto;
use std::io::*;

fn shift_ascii_char(index: usize, c: u8) -> u8 {
    match index % 2 {
        0 if c >= 97 && c <= 122 => c - 32,
        1 if c >= 65 && c <= 90 => c + 32,
        _ => c
    }
}

fn main() {
    let mut buffer: Box<[u8]>;
    let sz: usize;
    unsafe {
        //The try_into().unwrap() combo will still panic if the syscall fails inside an unsafe block which is nice
        sz = sysconf(_SC_PAGESIZE).try_into().unwrap();
    }
    //This can be done simpler if you know the size at compile time
    //Just basically Box::new([0u8; 10]);
    //Because sz is now triggered by a syscall, this means it's dynamic
    //I tried to go the "Box a vector as a slice" rather than the "Box a slice of a vector"
    //approach, but it failed to play nicely, mainly because the slice had an undetermined size at
    //compile time, which it didn't like
    //
    //Not 100% sure, but I'm pretty sure this is also the "nice" way of doing this
    //Trying to read directly into a preallocated vector seemed to not work
    //(kept getting Ok(0) results)
    //Brief googling showed that it might be because vectors require proper calls due to needing to
    //resize capacity and other things, so possibly the read side of the slice operation was a
    //no-op?
    //Not certain, but that's far too deep for my current understanding
    buffer = vec![0u8; sz*16].into_boxed_slice();
    let mut stdin = BufReader::new(stdin());
    let mut stdout = BufWriter::new(stdout());
    while let Ok(size) = stdin.read(&mut *buffer) {
        //While let and if let don't allow match guards, so the check is necessary
        //Didn't want to use a match for something so simple
        if size == 0 {
            break;
        }
        //You can actually do:
        //for i in &mut buffer[..size]
        //And it works just fine
        //Rust is smart, will do a mutable reference for-each
        //The actual iter_mut call here is so I can use enumerate for the index value as well
        for (i, c) in buffer[..size].iter_mut().enumerate() {
            *c = shift_ascii_char(i, *c);
        }
        if let Err(_) = stdout.write(&buffer[..size]) {
            break;
        }
        stdout.flush().unwrap();
    }
}
