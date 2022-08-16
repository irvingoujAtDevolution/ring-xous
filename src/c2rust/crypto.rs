#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_mut)]
extern crate std;

pub type __uint32_t = std::os::raw::c_uint;
pub type uint32_t = __uint32_t;
#[no_mangle]
pub static mut GFp_ia32cap_P: [uint32_t; 4] = [0 as std::os::raw::c_int as uint32_t, 0, 0, 0];
