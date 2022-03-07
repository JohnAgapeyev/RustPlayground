fn call_dynamic() {
    unsafe {
        let lib = libloading::Library::new("./target/debug/libmylib.so").unwrap();
        let func: libloading::Symbol<unsafe extern "C" fn()> = lib.get(b"test").unwrap();
        func();
        let func: libloading::Symbol<unsafe extern "Rust" fn()> = lib.get(b"rtest").unwrap();
        func();
        let mut v = vec![0u8; 25];
        println!("Passing in a Vec of length {} with first element {} and last element {}", v.len(), v[0], v[v.len() - 1]);
        let func: libloading::Symbol<unsafe extern "Rust" fn(&mut Vec<u8>)> = lib.get(b"r2test").unwrap();
        func(&mut v);
        println!("Current have a Vec of length {} with first element {} and last element {}", v.len(), v[0], v[v.len() - 1]);
    }
}

fn main() {
    println!("Pre hello");
    unsafe {
        std::arch::asm!(
            "",
            out("rax") _,
            //out("rbx") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            clobber_abi("C"),
        );
    }
    let x = false;
    println!("Hello, world!");
    unsafe {
        if std::ptr::read_volatile(std::ptr::addr_of!(x)) {
            std::arch::asm!(
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                "nop",
                clobber_abi("C"),
            );
        }
    }
    unsafe {
        std::arch::asm!(
            "",
            out("rax") _,
            //out("rbx") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            clobber_abi("C"),
        );
    }
    println!("Post hello");
    call_dynamic();
}
