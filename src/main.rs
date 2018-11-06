extern crate libc;
use libc::{c_int, c_char};

use std::ffi::CString;

#[link(name="crypto", kind = "static")]

#[link(name="gitcrypt")]
extern {
    fn cpp_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn main() {
    let args = std::env::args().map(|arg| CString::new(arg).unwrap() ).collect::<Vec<CString>>();
    let c_args = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<*const c_char>>();
    unsafe {
        let return_code = cpp_main(args.len() as c_int, c_args.as_ptr());
    };
}
