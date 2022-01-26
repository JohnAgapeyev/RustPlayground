#[cfg(debug_assertions)]
include!("main.rs");
#[cfg(not(debug_assertions))]
include!("release_main.rs");
