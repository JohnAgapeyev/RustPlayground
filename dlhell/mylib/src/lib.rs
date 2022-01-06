#[no_mangle]
pub extern "C" fn test() {
    println!("This is a Rust dynamic library call");
}
