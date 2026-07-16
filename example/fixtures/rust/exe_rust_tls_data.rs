// Fixture: Rust EXE with static TLS data, equivalent to exe_tls_data.c.
//
// Built with the nightly toolchain because `#[thread_local]` on a static
// variable requires `#![feature(thread_local)]`. The default CRT libraries
// are kept so the linker provides `_tls_used`, mirroring the C fixture.
//
// Expected markers (ordered):
//   [rdi-test] exe_rust_tls_data initial ok
//   [rdi-test] exe_rust_tls_data write ok

#![feature(thread_local)]
#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
    fn WriteFile(
        h_file: *mut c_void,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut c_void,
    ) -> i32;
}

const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5u32; // (DWORD)-11

unsafe fn test_write(s: &[u8]) {
    let h = GetStdHandle(STD_OUTPUT_HANDLE);
    if h.is_null() || h as isize == -1 {
        return;
    }
    let mut written: u32 = 0;
    WriteFile(h, s.as_ptr(), s.len() as u32, &mut written, core::ptr::null_mut());
}

#[thread_local]
static G_TLS_COUNTER: UnsafeCell<u32> = UnsafeCell::new(0x12345678);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "system" fn Entry() {
    unsafe {
        let p = G_TLS_COUNTER.get();
        if *p == 0x12345678 {
            test_write(b"[rdi-test] exe_rust_tls_data initial ok\n");
            *p = 0x87654321;
        } else {
            test_write(b"[rdi-test] exe_rust_tls_data initial fail\n");
        }
        if *p == 0x87654321 {
            test_write(b"[rdi-test] exe_rust_tls_data write ok\n");
        } else {
            test_write(b"[rdi-test] exe_rust_tls_data write fail\n");
        }
    }
}
