fn call_dynamic() {
    unsafe {
        let lib = libloading::Library::new("./target/release/libmylib.so").unwrap();
        let func: libloading::Symbol<unsafe extern "C" fn() -> u32> = lib.get(b"test").unwrap();
        func();
    }
}

fn main() {
    println!("Hello, world!");
    call_dynamic();
}
