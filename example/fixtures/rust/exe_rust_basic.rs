// Fixture: standard Rust EXE hello world.
//
// Built with the stable toolchain as a normal std binary. This exercises the
// real Rust runtime path (std initialization, default CRT libraries) and
// depends on static TLS data initialization, which is the core scenario the
// v2 SRDI loader's TLS handling was designed to cover.
//
// Expected marker:
//   [rdi-test] exe_rust_basic hello world

fn main() {
    println!("[rdi-test] exe_rust_basic hello world");
}
