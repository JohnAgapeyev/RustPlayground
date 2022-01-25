#[no_mangle]
pub extern "C" fn test() {
    println!("This is a Rust dynamic library call using the C ABI");
}

#[no_mangle]
pub extern "Rust" fn rtest() {
    println!("This is a Rust dynamic library call using the Rust ABI");
}

#[no_mangle]
pub extern "Rust" fn r2test(v: &mut Vec<u8>) {
    println!("This is a Rust dynamic library call using the Rust ABI wItH fAnCy ChAnGeS");
    println!("Wow, this vec has length {}", v.len());
    v[0] = 77u8;
    v.push(69u8);
}
