#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_mut)]
extern crate std;

pub type size_t = std::os::raw::c_uint;
pub type __uint32_t = std::os::raw::c_uint;
pub type uint32_t = __uint32_t;
pub type crypto_word = uint32_t;
pub type BN_ULONG = crypto_word;
pub type Limb = crypto_word;
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut std::os::raw::c_void,
    mut src: *const std::os::raw::c_void,
    mut n: size_t,
) -> *mut std::os::raw::c_void {
    let mut d: *mut std::os::raw::c_uchar = dst as *mut std::os::raw::c_uchar;
    let mut s: *const std::os::raw::c_uchar = src as *const std::os::raw::c_uchar;
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < n {
        *d.offset(i as isize) = *s.offset(i as isize);
        i = i.wrapping_add(1);
    }
    return dst;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut std::os::raw::c_void,
    mut c: std::os::raw::c_int,
    mut n: size_t,
) -> *mut std::os::raw::c_void {
    let mut d: *mut std::os::raw::c_uchar = dst as *mut std::os::raw::c_uchar;
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < n {
        *d.offset(i as isize) = c as std::os::raw::c_uchar;
        i = i.wrapping_add(1);
    }
    return dst;
}
#[no_mangle]
pub unsafe extern "C" fn p256_scalar_mul_mont(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
) {
    static mut N: [BN_ULONG; 8] = [
        0xfc632551 as std::os::raw::c_uint,
        0xf3b9cac2 as std::os::raw::c_uint,
        0xa7179e84 as std::os::raw::c_uint,
        0xbce6faad as std::os::raw::c_uint,
        0xffffffff as std::os::raw::c_uint,
        0xffffffff as std::os::raw::c_uint,
        0 as std::os::raw::c_int as BN_ULONG,
        0xffffffff as std::os::raw::c_uint,
    ];
    static mut N_N0: [BN_ULONG; 2] = [
        0xee00bc4f as std::os::raw::c_uint,
        0xccd1c8aa as std::os::raw::c_uint,
    ];
    bn_mul_mont(
        r,
        a,
        b,
        N.as_ptr(),
        N_N0.as_ptr(),
        256 as std::os::raw::c_int / 32 as std::os::raw::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn p256_scalar_sqr_rep_mont(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut rep: Limb,
) {
    p256_scalar_mul_mont(r, a, a);
    let mut i: Limb = 1 as std::os::raw::c_int as Limb;
    while i < rep {
        p256_scalar_mul_mont(r, r as *const Limb, r as *const Limb);
        i = i.wrapping_add(1);
    }
}
