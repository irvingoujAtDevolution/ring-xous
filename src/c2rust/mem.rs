#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_mut)]
extern crate std;

pub type size_t = std::os::raw::c_uint;
pub type __uint8_t = std::os::raw::c_uchar;
pub type uint8_t = __uint8_t;
#[no_mangle]
pub unsafe extern "C" fn GFp_memcmp(
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    mut len: size_t,
) -> std::os::raw::c_int {
    let mut x: uint8_t = 0 as std::os::raw::c_int as uint8_t;
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < len {
        x = (x as std::os::raw::c_int
            | *a.offset(i as isize) as std::os::raw::c_int
                ^ *b.offset(i as isize) as std::os::raw::c_int) as uint8_t;
        i = i.wrapping_add(1);
    }
    return x as std::os::raw::c_int;
}
