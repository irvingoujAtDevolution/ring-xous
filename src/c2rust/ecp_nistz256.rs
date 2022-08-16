#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_mut)]
extern crate std;

use std::arch::asm;
extern "C" {
    fn __assert_fail(
        __assertion: *const std::os::raw::c_char,
        __file: *const std::os::raw::c_char,
        __line: std::os::raw::c_uint,
        __function: *const std::os::raw::c_char,
    ) -> !;
    fn LIMBS_are_zero(a: *const Limb, num_limbs: size_t) -> Limb;
    fn LIMBS_equal(a: *const Limb, b: *const Limb, num_limbs: size_t) -> Limb;
    fn LIMBS_sub_mod(
        r: *mut Limb,
        a: *const Limb,
        b: *const Limb,
        m: *const Limb,
        num_limbs: size_t,
    );
    fn LIMBS_shl_mod(r: *mut Limb, a: *const Limb, m: *const Limb, num_limbs: size_t);
    fn GFp_nistz256_select_w5(out: *mut P256_POINT, table: *const P256_POINT, index: crypto_word);
    fn gfp_little_endian_bytes_from_scalar(
        str: *mut uint8_t,
        str_len: size_t,
        scalar: *const Limb,
        num_limbs: size_t,
    );
}
pub type size_t = u64;
pub type __uint8_t = std::os::raw::c_uchar;
pub type __uint32_t = std::os::raw::c_uint;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type crypto_word = uint32_t;
pub type Limb = crypto_word;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct P256_POINT {
    pub X: [Limb; 8],
    pub Y: [Limb; 8],
    pub Z: [Limb; 8],
}
pub type fiat_p256_uint1 = std::os::raw::c_uchar;
pub type fiat_p256_int1 = std::os::raw::c_schar;
pub type BN_ULONG = crypto_word;
pub type fiat_p256_felem = [uint32_t; 8];
pub type fiat_p256_limb_t = uint32_t;
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word) -> crypto_word {
    return (0 as std::os::raw::c_uint).wrapping_sub(
        a >> (std::mem::size_of::<crypto_word>() as u64)
            .wrapping_mul(8 as std::os::raw::c_int as u64)
            .wrapping_sub(1 as std::os::raw::c_int as u64),
    );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word) -> crypto_word {
    return constant_time_msb_w(
        !a & a.wrapping_sub(1 as std::os::raw::c_int as std::os::raw::c_uint),
    );
}
#[inline]
unsafe extern "C" fn constant_time_is_nonzero_w(mut a: crypto_word) -> crypto_word {
    return !constant_time_is_zero_w(a);
}
#[inline]
unsafe extern "C" fn booth_recode(
    mut is_negative: *mut crypto_word,
    mut digit: *mut crypto_word,
    mut in_0: crypto_word,
    mut w: crypto_word,
) {
    if w >= 2 as std::os::raw::c_int as std::os::raw::c_uint {
    } else {
        __assert_fail(
            b"w >= 2\0" as *const u8 as *const std::os::raw::c_char,
            b"crypto/fipsmodule/ec/ecp_nistz.h\0" as *const u8 as *const std::os::raw::c_char,
            251 as std::os::raw::c_int as std::os::raw::c_uint,
            (*std::mem::transmute::<&[u8; 74], &[std::os::raw::c_char; 74]>(
                b"void booth_recode(crypto_word *, crypto_word *, crypto_word, crypto_word)\0",
            ))
            .as_ptr(),
        );
    }
    if w <= 7 as std::os::raw::c_int as std::os::raw::c_uint {
    } else {
        __assert_fail(
            b"w <= 7\0" as *const u8 as *const std::os::raw::c_char,
            b"crypto/fipsmodule/ec/ecp_nistz.h\0" as *const u8 as *const std::os::raw::c_char,
            252 as std::os::raw::c_int as std::os::raw::c_uint,
            (*std::mem::transmute::<&[u8; 74], &[std::os::raw::c_char; 74]>(
                b"void booth_recode(crypto_word *, crypto_word *, crypto_word, crypto_word)\0",
            ))
            .as_ptr(),
        );
    }
    let mut s: crypto_word =
        !(in_0 >> w).wrapping_sub(1 as std::os::raw::c_int as std::os::raw::c_uint);
    let mut d: crypto_word = 0;
    d = ((1 as std::os::raw::c_uint)
        << w.wrapping_add(1 as std::os::raw::c_int as std::os::raw::c_uint))
    .wrapping_sub(in_0)
    .wrapping_sub(1 as std::os::raw::c_int as std::os::raw::c_uint);
    d = d & s | in_0 & !s;
    d = (d >> 1 as std::os::raw::c_int)
        .wrapping_add(d & 1 as std::os::raw::c_int as std::os::raw::c_uint);
    *is_negative = constant_time_is_nonzero_w(s & 1 as std::os::raw::c_int as std::os::raw::c_uint);
    *digit = d;
}
#[inline]
unsafe extern "C" fn limbs_copy(mut r: *mut Limb, mut a: *const Limb, mut num_limbs: size_t) {
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < num_limbs {
        *r.offset(i as isize) = *a.offset(i as isize);
        i = i.wrapping_add(1);
    }
}
#[inline]
unsafe extern "C" fn limbs_zero(mut r: *mut Limb, mut num_limbs: size_t) {
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < num_limbs {
        *r.offset(i as isize) = 0 as std::os::raw::c_int as Limb;
        i = i.wrapping_add(1);
    }
}
static mut ONE: [Limb; 8] = [
    0x1 as std::os::raw::c_int as Limb,
    0 as std::os::raw::c_int as Limb,
    0 as std::os::raw::c_int as Limb,
    0xffffffff as std::os::raw::c_uint,
    0xffffffff as std::os::raw::c_uint,
    0xffffffff as std::os::raw::c_uint,
    0xfffffffe as std::os::raw::c_uint,
    0 as std::os::raw::c_int as Limb,
];
unsafe extern "C" fn copy_conditional(mut dst: *mut Limb, mut src: *const Limb, mut move_0: Limb) {
    let mut mask1: Limb = move_0;
    let mut mask2: Limb = !mask1;
    *dst.offset(0 as std::os::raw::c_int as isize) = *src.offset(0 as std::os::raw::c_int as isize)
        & mask1
        ^ *dst.offset(0 as std::os::raw::c_int as isize) & mask2;
    *dst.offset(1 as std::os::raw::c_int as isize) = *src.offset(1 as std::os::raw::c_int as isize)
        & mask1
        ^ *dst.offset(1 as std::os::raw::c_int as isize) & mask2;
    *dst.offset(2 as std::os::raw::c_int as isize) = *src.offset(2 as std::os::raw::c_int as isize)
        & mask1
        ^ *dst.offset(2 as std::os::raw::c_int as isize) & mask2;
    *dst.offset(3 as std::os::raw::c_int as isize) = *src.offset(3 as std::os::raw::c_int as isize)
        & mask1
        ^ *dst.offset(3 as std::os::raw::c_int as isize) & mask2;
    if (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint)
        == 8 as std::os::raw::c_int as std::os::raw::c_uint
    {
        *dst.offset(4 as std::os::raw::c_int as isize) =
            *src.offset(4 as std::os::raw::c_int as isize) & mask1
                ^ *dst.offset(4 as std::os::raw::c_int as isize) & mask2;
        *dst.offset(5 as std::os::raw::c_int as isize) =
            *src.offset(5 as std::os::raw::c_int as isize) & mask1
                ^ *dst.offset(5 as std::os::raw::c_int as isize) & mask2;
        *dst.offset(6 as std::os::raw::c_int as isize) =
            *src.offset(6 as std::os::raw::c_int as isize) & mask1
                ^ *dst.offset(6 as std::os::raw::c_int as isize) & mask2;
        *dst.offset(7 as std::os::raw::c_int as isize) =
            *src.offset(7 as std::os::raw::c_int as isize) & mask1
                ^ *dst.offset(7 as std::os::raw::c_int as isize) & mask2;
    }
}
static mut Q: [BN_ULONG; 8] = [
    0xffffffff as std::os::raw::c_uint,
    0xffffffff as std::os::raw::c_uint,
    0xffffffff as std::os::raw::c_uint,
    0 as std::os::raw::c_int as BN_ULONG,
    0 as std::os::raw::c_int as BN_ULONG,
    0 as std::os::raw::c_int as BN_ULONG,
    0x1 as std::os::raw::c_int as BN_ULONG,
    0xffffffff as std::os::raw::c_uint,
];
#[inline]
unsafe extern "C" fn is_equal(mut a: *const Limb, mut b: *const Limb) -> Limb {
    return LIMBS_equal(
        a,
        b,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
}
#[inline]
unsafe extern "C" fn is_zero(mut a: *const BN_ULONG) -> Limb {
    return LIMBS_are_zero(
        a,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
}
#[inline]
unsafe extern "C" fn elem_mul_by_2(mut r: *mut Limb, mut a: *const Limb) {
    LIMBS_shl_mod(
        r,
        a,
        Q.as_ptr(),
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
}
#[inline]
unsafe extern "C" fn elem_mul_mont(mut r: *mut Limb, mut a: *const Limb, mut b: *const Limb) {
    GFp_nistz256_mul_mont(r, a, b);
}
#[inline]
unsafe extern "C" fn elem_sqr_mont(mut r: *mut Limb, mut a: *const Limb) {
    GFp_nistz256_sqr_mont(r, a);
}
#[inline]
unsafe extern "C" fn elem_sub(mut r: *mut Limb, mut a: *const Limb, mut b: *const Limb) {
    LIMBS_sub_mod(
        r,
        a,
        b,
        Q.as_ptr(),
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_point_add(
    mut r: *mut P256_POINT,
    mut a: *const P256_POINT,
    mut b: *const P256_POINT,
) {
    let mut U2: [BN_ULONG; 8] = [0; 8];
    let mut S2: [BN_ULONG; 8] = [0; 8];
    let mut U1: [BN_ULONG; 8] = [0; 8];
    let mut S1: [BN_ULONG; 8] = [0; 8];
    let mut Z1sqr: [BN_ULONG; 8] = [0; 8];
    let mut Z2sqr: [BN_ULONG; 8] = [0; 8];
    let mut H: [BN_ULONG; 8] = [0; 8];
    let mut R: [BN_ULONG; 8] = [0; 8];
    let mut Hsqr: [BN_ULONG; 8] = [0; 8];
    let mut Rsqr: [BN_ULONG; 8] = [0; 8];
    let mut Hcub: [BN_ULONG; 8] = [0; 8];
    let mut res_x: [BN_ULONG; 8] = [0; 8];
    let mut res_y: [BN_ULONG; 8] = [0; 8];
    let mut res_z: [BN_ULONG; 8] = [0; 8];
    let mut in1_x: *const BN_ULONG = ((*a).X).as_ptr();
    let mut in1_y: *const BN_ULONG = ((*a).Y).as_ptr();
    let mut in1_z: *const BN_ULONG = ((*a).Z).as_ptr();
    let mut in2_x: *const BN_ULONG = ((*b).X).as_ptr();
    let mut in2_y: *const BN_ULONG = ((*b).Y).as_ptr();
    let mut in2_z: *const BN_ULONG = ((*b).Z).as_ptr();
    let mut in1infty: BN_ULONG = is_zero(((*a).Z).as_ptr());
    let mut in2infty: BN_ULONG = is_zero(((*b).Z).as_ptr());
    elem_sqr_mont(Z2sqr.as_mut_ptr(), in2_z);
    elem_sqr_mont(Z1sqr.as_mut_ptr(), in1_z);
    elem_mul_mont(S1.as_mut_ptr(), Z2sqr.as_mut_ptr() as *const Limb, in2_z);
    elem_mul_mont(S2.as_mut_ptr(), Z1sqr.as_mut_ptr() as *const Limb, in1_z);
    elem_mul_mont(S1.as_mut_ptr(), S1.as_mut_ptr() as *const Limb, in1_y);
    elem_mul_mont(S2.as_mut_ptr(), S2.as_mut_ptr() as *const Limb, in2_y);
    elem_sub(
        R.as_mut_ptr(),
        S2.as_mut_ptr() as *const Limb,
        S1.as_mut_ptr() as *const Limb,
    );
    elem_mul_mont(U1.as_mut_ptr(), in1_x, Z2sqr.as_mut_ptr() as *const Limb);
    elem_mul_mont(U2.as_mut_ptr(), in2_x, Z1sqr.as_mut_ptr() as *const Limb);
    elem_sub(
        H.as_mut_ptr(),
        U2.as_mut_ptr() as *const Limb,
        U1.as_mut_ptr() as *const Limb,
    );
    let mut is_exceptional: BN_ULONG = is_equal(
        U1.as_mut_ptr() as *const Limb,
        U2.as_mut_ptr() as *const Limb,
    ) & !in1infty
        & !in2infty;
    if is_exceptional != 0 {
        if is_equal(
            S1.as_mut_ptr() as *const Limb,
            S2.as_mut_ptr() as *const Limb,
        ) != 0
        {
            GFp_nistz256_point_double(r, a);
        } else {
            limbs_zero(
                ((*r).X).as_mut_ptr(),
                (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
            );
            limbs_zero(
                ((*r).Y).as_mut_ptr(),
                (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
            );
            limbs_zero(
                ((*r).Z).as_mut_ptr(),
                (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
            );
        }
        return;
    }
    elem_sqr_mont(Rsqr.as_mut_ptr(), R.as_mut_ptr() as *const Limb);
    elem_mul_mont(res_z.as_mut_ptr(), H.as_mut_ptr() as *const Limb, in1_z);
    elem_sqr_mont(Hsqr.as_mut_ptr(), H.as_mut_ptr() as *const Limb);
    elem_mul_mont(res_z.as_mut_ptr(), res_z.as_mut_ptr() as *const Limb, in2_z);
    elem_mul_mont(
        Hcub.as_mut_ptr(),
        Hsqr.as_mut_ptr() as *const Limb,
        H.as_mut_ptr() as *const Limb,
    );
    elem_mul_mont(
        U2.as_mut_ptr(),
        U1.as_mut_ptr() as *const Limb,
        Hsqr.as_mut_ptr() as *const Limb,
    );
    elem_mul_by_2(Hsqr.as_mut_ptr(), U2.as_mut_ptr() as *const Limb);
    elem_sub(
        res_x.as_mut_ptr(),
        Rsqr.as_mut_ptr() as *const Limb,
        Hsqr.as_mut_ptr() as *const Limb,
    );
    elem_sub(
        res_x.as_mut_ptr(),
        res_x.as_mut_ptr() as *const Limb,
        Hcub.as_mut_ptr() as *const Limb,
    );
    elem_sub(
        res_y.as_mut_ptr(),
        U2.as_mut_ptr() as *const Limb,
        res_x.as_mut_ptr() as *const Limb,
    );
    elem_mul_mont(
        S2.as_mut_ptr(),
        S1.as_mut_ptr() as *const Limb,
        Hcub.as_mut_ptr() as *const Limb,
    );
    elem_mul_mont(
        res_y.as_mut_ptr(),
        R.as_mut_ptr() as *const Limb,
        res_y.as_mut_ptr() as *const Limb,
    );
    elem_sub(
        res_y.as_mut_ptr(),
        res_y.as_mut_ptr() as *const Limb,
        S2.as_mut_ptr() as *const Limb,
    );
    copy_conditional(res_x.as_mut_ptr(), in2_x, in1infty);
    copy_conditional(res_y.as_mut_ptr(), in2_y, in1infty);
    copy_conditional(res_z.as_mut_ptr(), in2_z, in1infty);
    copy_conditional(res_x.as_mut_ptr(), in1_x, in2infty);
    copy_conditional(res_y.as_mut_ptr(), in1_y, in2infty);
    copy_conditional(res_z.as_mut_ptr(), in1_z, in2infty);
    limbs_copy(
        ((*r).X).as_mut_ptr(),
        res_x.as_mut_ptr() as *const Limb,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    limbs_copy(
        ((*r).Y).as_mut_ptr(),
        res_y.as_mut_ptr() as *const Limb,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    limbs_copy(
        ((*r).Z).as_mut_ptr(),
        res_z.as_mut_ptr() as *const Limb,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_point_mul(
    mut r: *mut P256_POINT,
    mut p_scalar: *const Limb,
    mut p_x: *const Limb,
    mut p_y: *const Limb,
) {
    static mut kWindowSize: size_t = 5 as std::os::raw::c_int as size_t;
    static mut kMask: crypto_word = (((1 as std::os::raw::c_int)
        << 5 as std::os::raw::c_int + 1 as std::os::raw::c_int)
        - 1 as std::os::raw::c_int) as crypto_word;
    let mut p_str: [uint8_t; 33] = [0; 33];
    gfp_little_endian_bytes_from_scalar(
        p_str.as_mut_ptr(),
        (std::mem::size_of::<[uint8_t; 33]>() as u64)
            .wrapping_div(std::mem::size_of::<uint8_t>() as u64),
        p_scalar,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    let mut table: [P256_POINT; 16] = [P256_POINT {
        X: [0; 8],
        Y: [0; 8],
        Z: [0; 8],
    }; 16];
    let mut row: *mut P256_POINT = table.as_mut_ptr();
    limbs_copy(
        ((*row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize)).X)
            .as_mut_ptr(),
        p_x,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    limbs_copy(
        ((*row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize)).Y)
            .as_mut_ptr(),
        p_y,
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    limbs_copy(
        ((*row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize)).Z)
            .as_mut_ptr(),
        ONE.as_ptr(),
        (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
    );
    GFp_nistz256_point_double(
        &mut *row.offset((2 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((3 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((2 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((4 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((2 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((6 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((3 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((8 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((4 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((12 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((6 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((5 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((4 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((7 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((6 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((9 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((8 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((13 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((12 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((14 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((7 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((10 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((5 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((15 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((14 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_add(
        &mut *row.offset((11 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((10 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((1 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    GFp_nistz256_point_double(
        &mut *row.offset((16 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
        &mut *row.offset((8 as std::os::raw::c_int - 1 as std::os::raw::c_int) as isize),
    );
    let mut tmp: [Limb; 8] = [0; 8];
    let mut h: P256_POINT = P256_POINT {
        X: [0; 8],
        Y: [0; 8],
        Z: [0; 8],
    };
    static mut START_INDEX: size_t =
        (256 as std::os::raw::c_int - 1 as std::os::raw::c_int) as size_t;
    let mut index: size_t = START_INDEX;
    let mut raw_wvalue: crypto_word = 0;
    let mut recoded_is_negative: crypto_word = 0;
    let mut recoded: crypto_word = 0;
    raw_wvalue = p_str[index
        .wrapping_sub(1 as std::os::raw::c_int as u64)
        .wrapping_div(8 as std::os::raw::c_int as u64) as usize] as crypto_word;
    raw_wvalue = raw_wvalue
        >> index
            .wrapping_sub(1 as std::os::raw::c_int as u64)
            .wrapping_rem(8 as std::os::raw::c_int as u64)
        & kMask;
    booth_recode(
        &mut recoded_is_negative,
        &mut recoded,
        raw_wvalue,
        kWindowSize as crypto_word,
    );
    GFp_nistz256_select_w5(r, table.as_mut_ptr() as *const P256_POINT, recoded);
    while index >= kWindowSize {
        if index != START_INDEX {
            let mut off: size_t = index
                .wrapping_sub(1 as std::os::raw::c_int as u64)
                .wrapping_div(8 as std::os::raw::c_int as u64);
            raw_wvalue = (p_str[off as usize] as std::os::raw::c_int
                | (p_str[off.wrapping_add(1 as std::os::raw::c_int as u64) as usize]
                    as std::os::raw::c_int)
                    << 8 as std::os::raw::c_int) as crypto_word;
            raw_wvalue = raw_wvalue
                >> index
                    .wrapping_sub(1 as std::os::raw::c_int as u64)
                    .wrapping_rem(8 as std::os::raw::c_int as u64)
                & kMask;
            booth_recode(
                &mut recoded_is_negative,
                &mut recoded,
                raw_wvalue,
                kWindowSize as crypto_word,
            );
            GFp_nistz256_select_w5(&mut h, table.as_mut_ptr() as *const P256_POINT, recoded);
            GFp_nistz256_neg(tmp.as_mut_ptr(), (h.Y).as_mut_ptr() as *const Limb);
            copy_conditional(
                (h.Y).as_mut_ptr(),
                tmp.as_mut_ptr() as *const Limb,
                recoded_is_negative,
            );
            GFp_nistz256_point_add(r, r, &mut h);
        }
        index = (index as u64).wrapping_sub(kWindowSize) as size_t as size_t;
        GFp_nistz256_point_double(r, r);
        GFp_nistz256_point_double(r, r);
        GFp_nistz256_point_double(r, r);
        GFp_nistz256_point_double(r, r);
        GFp_nistz256_point_double(r, r);
    }
    raw_wvalue = p_str[0 as std::os::raw::c_int as usize] as crypto_word;
    raw_wvalue = raw_wvalue << 1 as std::os::raw::c_int & kMask;
    booth_recode(
        &mut recoded_is_negative,
        &mut recoded,
        raw_wvalue,
        kWindowSize as crypto_word,
    );
    GFp_nistz256_select_w5(&mut h, table.as_mut_ptr() as *const P256_POINT, recoded);
    GFp_nistz256_neg(tmp.as_mut_ptr(), (h.Y).as_mut_ptr() as *const Limb);
    copy_conditional(
        (h.Y).as_mut_ptr(),
        tmp.as_mut_ptr() as *const Limb,
        recoded_is_negative,
    );
    GFp_nistz256_point_add(r, r, &mut h);
}
unsafe extern "C" fn fiat_p256_addcarryx_u32(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_p256_uint1,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: uint64_t = (arg1 as u64)
        .wrapping_add(arg2 as uint64_t)
        .wrapping_add(arg3 as u64);
    let mut x2: uint32_t = (x1 & 0xffffffff as std::os::raw::c_uint as u64) as uint32_t;
    let mut x3: fiat_p256_uint1 = (x1 >> 32 as std::os::raw::c_int) as fiat_p256_uint1;
    *out1 = x2;
    *out2 = x3;
}
unsafe extern "C" fn fiat_p256_subborrowx_u32(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_p256_uint1,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: int64_t = arg2 as i64 - arg1 as int64_t - arg3 as i64;
    let mut x2: fiat_p256_int1 = (x1 >> 32 as std::os::raw::c_int) as fiat_p256_int1;
    let mut x3: uint32_t = (x1 & 0xffffffff as std::os::raw::c_uint as i64) as uint32_t;
    *out1 = x3;
    *out2 = (0 as std::os::raw::c_int - x2 as std::os::raw::c_int) as fiat_p256_uint1;
}
unsafe extern "C" fn fiat_p256_mulx_u32(
    mut out1: *mut uint32_t,
    mut out2: *mut uint32_t,
    mut arg1: uint32_t,
    mut arg2: uint32_t,
) {
    let mut x1: uint64_t = (arg1 as uint64_t).wrapping_mul(arg2 as u64);
    let mut x2: uint32_t = (x1 & 0xffffffff as std::os::raw::c_uint as u64) as uint32_t;
    let mut x3: uint32_t = (x1 >> 32 as std::os::raw::c_int) as uint32_t;
    *out1 = x2;
    *out2 = x3;
}
unsafe extern "C" fn fiat_p256_cmovznz_u32(
    mut out1: *mut uint32_t,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: fiat_p256_uint1 = (arg1 != 0) as std::os::raw::c_int as fiat_p256_uint1;
    let mut x2: uint32_t = (0 as std::os::raw::c_int - x1 as std::os::raw::c_int) as fiat_p256_int1
        as std::os::raw::c_uint
        & 0xffffffff as std::os::raw::c_uint;
    let mut x3: uint32_t = value_barrier_u32(x2) & arg3 | value_barrier_u32(!x2) & arg2;
    *out1 = x3;
}
unsafe extern "C" fn fiat_p256_mul(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint32_t = *arg1.offset(1 as std::os::raw::c_int as isize);
    let mut x2: uint32_t = *arg1.offset(2 as std::os::raw::c_int as isize);
    let mut x3: uint32_t = *arg1.offset(3 as std::os::raw::c_int as isize);
    let mut x4: uint32_t = *arg1.offset(4 as std::os::raw::c_int as isize);
    let mut x5: uint32_t = *arg1.offset(5 as std::os::raw::c_int as isize);
    let mut x6: uint32_t = *arg1.offset(6 as std::os::raw::c_int as isize);
    let mut x7: uint32_t = *arg1.offset(7 as std::os::raw::c_int as isize);
    let mut x8: uint32_t = *arg1.offset(0 as std::os::raw::c_int as isize);
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x9,
        &mut x10,
        x8,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x11: uint32_t = 0;
    let mut x12: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x11,
        &mut x12,
        x8,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x13: uint32_t = 0;
    let mut x14: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x13,
        &mut x14,
        x8,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x15: uint32_t = 0;
    let mut x16: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x15,
        &mut x16,
        x8,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x17,
        &mut x18,
        x8,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x19: uint32_t = 0;
    let mut x20: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x19,
        &mut x20,
        x8,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x21: uint32_t = 0;
    let mut x22: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x21,
        &mut x22,
        x8,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x23: uint32_t = 0;
    let mut x24: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x23,
        &mut x24,
        x8,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x25: uint32_t = 0;
    let mut x26: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x25,
        &mut x26,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x24,
        x21,
    );
    let mut x27: uint32_t = 0;
    let mut x28: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x27, &mut x28, x26, x22, x19);
    let mut x29: uint32_t = 0;
    let mut x30: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x29, &mut x30, x28, x20, x17);
    let mut x31: uint32_t = 0;
    let mut x32: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x31, &mut x32, x30, x18, x15);
    let mut x33: uint32_t = 0;
    let mut x34: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x33, &mut x34, x32, x16, x13);
    let mut x35: uint32_t = 0;
    let mut x36: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x35, &mut x36, x34, x14, x11);
    let mut x37: uint32_t = 0;
    let mut x38: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x37, &mut x38, x36, x12, x9);
    let mut x39: uint32_t = (x38 as std::os::raw::c_uint).wrapping_add(x10);
    let mut x40: uint32_t = 0;
    let mut x41: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x40, &mut x41, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x42: uint32_t = 0;
    let mut x43: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x42, &mut x43, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x44: uint32_t = 0;
    let mut x45: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x44, &mut x45, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x46: uint32_t = 0;
    let mut x47: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x46, &mut x47, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x48: uint32_t = 0;
    let mut x49: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x48,
        &mut x49,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x47,
        x44,
    );
    let mut x50: uint32_t = 0;
    let mut x51: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x50, &mut x51, x49, x45, x42);
    let mut x52: uint32_t = (x51 as std::os::raw::c_uint).wrapping_add(x43);
    let mut x53: uint32_t = 0;
    let mut x54: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x53,
        &mut x54,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x23,
        x46,
    );
    let mut x55: uint32_t = 0;
    let mut x56: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x55, &mut x56, x54, x25, x48);
    let mut x57: uint32_t = 0;
    let mut x58: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x57, &mut x58, x56, x27, x50);
    let mut x59: uint32_t = 0;
    let mut x60: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x59, &mut x60, x58, x29, x52);
    let mut x61: uint32_t = 0;
    let mut x62: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x61,
        &mut x62,
        x60,
        x31,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x63: uint32_t = 0;
    let mut x64: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x63,
        &mut x64,
        x62,
        x33,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x65: uint32_t = 0;
    let mut x66: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x65, &mut x66, x64, x35, x23);
    let mut x67: uint32_t = 0;
    let mut x68: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x67, &mut x68, x66, x37, x40);
    let mut x69: uint32_t = 0;
    let mut x70: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x69, &mut x70, x68, x39, x41);
    let mut x71: uint32_t = 0;
    let mut x72: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x71,
        &mut x72,
        x1,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x73: uint32_t = 0;
    let mut x74: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x73,
        &mut x74,
        x1,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x75: uint32_t = 0;
    let mut x76: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x75,
        &mut x76,
        x1,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x77: uint32_t = 0;
    let mut x78: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x77,
        &mut x78,
        x1,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x79: uint32_t = 0;
    let mut x80: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x79,
        &mut x80,
        x1,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x81: uint32_t = 0;
    let mut x82: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x81,
        &mut x82,
        x1,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x83: uint32_t = 0;
    let mut x84: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x83,
        &mut x84,
        x1,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x85: uint32_t = 0;
    let mut x86: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x85,
        &mut x86,
        x1,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x87: uint32_t = 0;
    let mut x88: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x87,
        &mut x88,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x86,
        x83,
    );
    let mut x89: uint32_t = 0;
    let mut x90: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x89, &mut x90, x88, x84, x81);
    let mut x91: uint32_t = 0;
    let mut x92: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x91, &mut x92, x90, x82, x79);
    let mut x93: uint32_t = 0;
    let mut x94: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x93, &mut x94, x92, x80, x77);
    let mut x95: uint32_t = 0;
    let mut x96: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x95, &mut x96, x94, x78, x75);
    let mut x97: uint32_t = 0;
    let mut x98: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x97, &mut x98, x96, x76, x73);
    let mut x99: uint32_t = 0;
    let mut x100: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x99, &mut x100, x98, x74, x71);
    let mut x101: uint32_t = (x100 as std::os::raw::c_uint).wrapping_add(x72);
    let mut x102: uint32_t = 0;
    let mut x103: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x102,
        &mut x103,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x55,
        x85,
    );
    let mut x104: uint32_t = 0;
    let mut x105: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x104, &mut x105, x103, x57, x87);
    let mut x106: uint32_t = 0;
    let mut x107: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x106, &mut x107, x105, x59, x89);
    let mut x108: uint32_t = 0;
    let mut x109: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x108, &mut x109, x107, x61, x91);
    let mut x110: uint32_t = 0;
    let mut x111: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x110, &mut x111, x109, x63, x93);
    let mut x112: uint32_t = 0;
    let mut x113: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x112, &mut x113, x111, x65, x95);
    let mut x114: uint32_t = 0;
    let mut x115: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x114, &mut x115, x113, x67, x97);
    let mut x116: uint32_t = 0;
    let mut x117: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x116, &mut x117, x115, x69, x99);
    let mut x118: uint32_t = 0;
    let mut x119: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x118, &mut x119, x117, x70 as uint32_t, x101);
    let mut x120: uint32_t = 0;
    let mut x121: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x120,
        &mut x121,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x122: uint32_t = 0;
    let mut x123: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x122,
        &mut x123,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x124: uint32_t = 0;
    let mut x125: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x124,
        &mut x125,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x126: uint32_t = 0;
    let mut x127: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x126,
        &mut x127,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x128: uint32_t = 0;
    let mut x129: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x128,
        &mut x129,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x127,
        x124,
    );
    let mut x130: uint32_t = 0;
    let mut x131: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x130, &mut x131, x129, x125, x122);
    let mut x132: uint32_t = (x131 as std::os::raw::c_uint).wrapping_add(x123);
    let mut x133: uint32_t = 0;
    let mut x134: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x133,
        &mut x134,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x102,
        x126,
    );
    let mut x135: uint32_t = 0;
    let mut x136: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x135, &mut x136, x134, x104, x128);
    let mut x137: uint32_t = 0;
    let mut x138: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x137, &mut x138, x136, x106, x130);
    let mut x139: uint32_t = 0;
    let mut x140: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x139, &mut x140, x138, x108, x132);
    let mut x141: uint32_t = 0;
    let mut x142: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x141,
        &mut x142,
        x140,
        x110,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x143: uint32_t = 0;
    let mut x144: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x143,
        &mut x144,
        x142,
        x112,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x145: uint32_t = 0;
    let mut x146: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x145, &mut x146, x144, x114, x102);
    let mut x147: uint32_t = 0;
    let mut x148: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x147, &mut x148, x146, x116, x120);
    let mut x149: uint32_t = 0;
    let mut x150: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x149, &mut x150, x148, x118, x121);
    let mut x151: uint32_t = (x150 as uint32_t).wrapping_add(x119 as std::os::raw::c_uint);
    let mut x152: uint32_t = 0;
    let mut x153: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x152,
        &mut x153,
        x2,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x154: uint32_t = 0;
    let mut x155: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x154,
        &mut x155,
        x2,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x156: uint32_t = 0;
    let mut x157: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x156,
        &mut x157,
        x2,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x158: uint32_t = 0;
    let mut x159: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x158,
        &mut x159,
        x2,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x160: uint32_t = 0;
    let mut x161: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x160,
        &mut x161,
        x2,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x162: uint32_t = 0;
    let mut x163: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x162,
        &mut x163,
        x2,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x164: uint32_t = 0;
    let mut x165: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x164,
        &mut x165,
        x2,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x166: uint32_t = 0;
    let mut x167: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x166,
        &mut x167,
        x2,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x168: uint32_t = 0;
    let mut x169: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x168,
        &mut x169,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x167,
        x164,
    );
    let mut x170: uint32_t = 0;
    let mut x171: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x170, &mut x171, x169, x165, x162);
    let mut x172: uint32_t = 0;
    let mut x173: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x172, &mut x173, x171, x163, x160);
    let mut x174: uint32_t = 0;
    let mut x175: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x174, &mut x175, x173, x161, x158);
    let mut x176: uint32_t = 0;
    let mut x177: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x176, &mut x177, x175, x159, x156);
    let mut x178: uint32_t = 0;
    let mut x179: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x178, &mut x179, x177, x157, x154);
    let mut x180: uint32_t = 0;
    let mut x181: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x180, &mut x181, x179, x155, x152);
    let mut x182: uint32_t = (x181 as std::os::raw::c_uint).wrapping_add(x153);
    let mut x183: uint32_t = 0;
    let mut x184: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x183,
        &mut x184,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x135,
        x166,
    );
    let mut x185: uint32_t = 0;
    let mut x186: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x185, &mut x186, x184, x137, x168);
    let mut x187: uint32_t = 0;
    let mut x188: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x187, &mut x188, x186, x139, x170);
    let mut x189: uint32_t = 0;
    let mut x190: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x189, &mut x190, x188, x141, x172);
    let mut x191: uint32_t = 0;
    let mut x192: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x191, &mut x192, x190, x143, x174);
    let mut x193: uint32_t = 0;
    let mut x194: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x193, &mut x194, x192, x145, x176);
    let mut x195: uint32_t = 0;
    let mut x196: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x195, &mut x196, x194, x147, x178);
    let mut x197: uint32_t = 0;
    let mut x198: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x197, &mut x198, x196, x149, x180);
    let mut x199: uint32_t = 0;
    let mut x200: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x199, &mut x200, x198, x151, x182);
    let mut x201: uint32_t = 0;
    let mut x202: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x201,
        &mut x202,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x203: uint32_t = 0;
    let mut x204: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x203,
        &mut x204,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x205: uint32_t = 0;
    let mut x206: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x205,
        &mut x206,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x207: uint32_t = 0;
    let mut x208: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x207,
        &mut x208,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x209: uint32_t = 0;
    let mut x210: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x209,
        &mut x210,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x208,
        x205,
    );
    let mut x211: uint32_t = 0;
    let mut x212: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x211, &mut x212, x210, x206, x203);
    let mut x213: uint32_t = (x212 as std::os::raw::c_uint).wrapping_add(x204);
    let mut x214: uint32_t = 0;
    let mut x215: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x214,
        &mut x215,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x183,
        x207,
    );
    let mut x216: uint32_t = 0;
    let mut x217: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x216, &mut x217, x215, x185, x209);
    let mut x218: uint32_t = 0;
    let mut x219: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x218, &mut x219, x217, x187, x211);
    let mut x220: uint32_t = 0;
    let mut x221: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x220, &mut x221, x219, x189, x213);
    let mut x222: uint32_t = 0;
    let mut x223: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x222,
        &mut x223,
        x221,
        x191,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x224: uint32_t = 0;
    let mut x225: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x224,
        &mut x225,
        x223,
        x193,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x226: uint32_t = 0;
    let mut x227: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x226, &mut x227, x225, x195, x183);
    let mut x228: uint32_t = 0;
    let mut x229: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x228, &mut x229, x227, x197, x201);
    let mut x230: uint32_t = 0;
    let mut x231: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x230, &mut x231, x229, x199, x202);
    let mut x232: uint32_t = (x231 as uint32_t).wrapping_add(x200 as std::os::raw::c_uint);
    let mut x233: uint32_t = 0;
    let mut x234: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x233,
        &mut x234,
        x3,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x235: uint32_t = 0;
    let mut x236: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x235,
        &mut x236,
        x3,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x237: uint32_t = 0;
    let mut x238: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x237,
        &mut x238,
        x3,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x239: uint32_t = 0;
    let mut x240: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x239,
        &mut x240,
        x3,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x241: uint32_t = 0;
    let mut x242: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x241,
        &mut x242,
        x3,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x243: uint32_t = 0;
    let mut x244: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x243,
        &mut x244,
        x3,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x245: uint32_t = 0;
    let mut x246: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x245,
        &mut x246,
        x3,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x247: uint32_t = 0;
    let mut x248: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x247,
        &mut x248,
        x3,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x249: uint32_t = 0;
    let mut x250: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x249,
        &mut x250,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x248,
        x245,
    );
    let mut x251: uint32_t = 0;
    let mut x252: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x251, &mut x252, x250, x246, x243);
    let mut x253: uint32_t = 0;
    let mut x254: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x253, &mut x254, x252, x244, x241);
    let mut x255: uint32_t = 0;
    let mut x256: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x255, &mut x256, x254, x242, x239);
    let mut x257: uint32_t = 0;
    let mut x258: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x257, &mut x258, x256, x240, x237);
    let mut x259: uint32_t = 0;
    let mut x260: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x259, &mut x260, x258, x238, x235);
    let mut x261: uint32_t = 0;
    let mut x262: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x261, &mut x262, x260, x236, x233);
    let mut x263: uint32_t = (x262 as std::os::raw::c_uint).wrapping_add(x234);
    let mut x264: uint32_t = 0;
    let mut x265: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x264,
        &mut x265,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x216,
        x247,
    );
    let mut x266: uint32_t = 0;
    let mut x267: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x266, &mut x267, x265, x218, x249);
    let mut x268: uint32_t = 0;
    let mut x269: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x268, &mut x269, x267, x220, x251);
    let mut x270: uint32_t = 0;
    let mut x271: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x270, &mut x271, x269, x222, x253);
    let mut x272: uint32_t = 0;
    let mut x273: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x272, &mut x273, x271, x224, x255);
    let mut x274: uint32_t = 0;
    let mut x275: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x274, &mut x275, x273, x226, x257);
    let mut x276: uint32_t = 0;
    let mut x277: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x276, &mut x277, x275, x228, x259);
    let mut x278: uint32_t = 0;
    let mut x279: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x278, &mut x279, x277, x230, x261);
    let mut x280: uint32_t = 0;
    let mut x281: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x280, &mut x281, x279, x232, x263);
    let mut x282: uint32_t = 0;
    let mut x283: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x282,
        &mut x283,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x284: uint32_t = 0;
    let mut x285: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x284,
        &mut x285,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x286: uint32_t = 0;
    let mut x287: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x286,
        &mut x287,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x288: uint32_t = 0;
    let mut x289: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x288,
        &mut x289,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x290: uint32_t = 0;
    let mut x291: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x290,
        &mut x291,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x289,
        x286,
    );
    let mut x292: uint32_t = 0;
    let mut x293: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x292, &mut x293, x291, x287, x284);
    let mut x294: uint32_t = (x293 as std::os::raw::c_uint).wrapping_add(x285);
    let mut x295: uint32_t = 0;
    let mut x296: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x295,
        &mut x296,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x264,
        x288,
    );
    let mut x297: uint32_t = 0;
    let mut x298: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x297, &mut x298, x296, x266, x290);
    let mut x299: uint32_t = 0;
    let mut x300: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x299, &mut x300, x298, x268, x292);
    let mut x301: uint32_t = 0;
    let mut x302: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x301, &mut x302, x300, x270, x294);
    let mut x303: uint32_t = 0;
    let mut x304: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x303,
        &mut x304,
        x302,
        x272,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x305: uint32_t = 0;
    let mut x306: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x305,
        &mut x306,
        x304,
        x274,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x307: uint32_t = 0;
    let mut x308: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x307, &mut x308, x306, x276, x264);
    let mut x309: uint32_t = 0;
    let mut x310: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x309, &mut x310, x308, x278, x282);
    let mut x311: uint32_t = 0;
    let mut x312: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x311, &mut x312, x310, x280, x283);
    let mut x313: uint32_t = (x312 as uint32_t).wrapping_add(x281 as std::os::raw::c_uint);
    let mut x314: uint32_t = 0;
    let mut x315: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x314,
        &mut x315,
        x4,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x316: uint32_t = 0;
    let mut x317: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x316,
        &mut x317,
        x4,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x318: uint32_t = 0;
    let mut x319: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x318,
        &mut x319,
        x4,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x320: uint32_t = 0;
    let mut x321: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x320,
        &mut x321,
        x4,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x322: uint32_t = 0;
    let mut x323: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x322,
        &mut x323,
        x4,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x324: uint32_t = 0;
    let mut x325: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x324,
        &mut x325,
        x4,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x326: uint32_t = 0;
    let mut x327: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x326,
        &mut x327,
        x4,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x328: uint32_t = 0;
    let mut x329: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x328,
        &mut x329,
        x4,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x330: uint32_t = 0;
    let mut x331: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x330,
        &mut x331,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x329,
        x326,
    );
    let mut x332: uint32_t = 0;
    let mut x333: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x332, &mut x333, x331, x327, x324);
    let mut x334: uint32_t = 0;
    let mut x335: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x334, &mut x335, x333, x325, x322);
    let mut x336: uint32_t = 0;
    let mut x337: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x336, &mut x337, x335, x323, x320);
    let mut x338: uint32_t = 0;
    let mut x339: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x338, &mut x339, x337, x321, x318);
    let mut x340: uint32_t = 0;
    let mut x341: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x340, &mut x341, x339, x319, x316);
    let mut x342: uint32_t = 0;
    let mut x343: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x342, &mut x343, x341, x317, x314);
    let mut x344: uint32_t = (x343 as std::os::raw::c_uint).wrapping_add(x315);
    let mut x345: uint32_t = 0;
    let mut x346: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x345,
        &mut x346,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x297,
        x328,
    );
    let mut x347: uint32_t = 0;
    let mut x348: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x347, &mut x348, x346, x299, x330);
    let mut x349: uint32_t = 0;
    let mut x350: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x349, &mut x350, x348, x301, x332);
    let mut x351: uint32_t = 0;
    let mut x352: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x351, &mut x352, x350, x303, x334);
    let mut x353: uint32_t = 0;
    let mut x354: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x353, &mut x354, x352, x305, x336);
    let mut x355: uint32_t = 0;
    let mut x356: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x355, &mut x356, x354, x307, x338);
    let mut x357: uint32_t = 0;
    let mut x358: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x357, &mut x358, x356, x309, x340);
    let mut x359: uint32_t = 0;
    let mut x360: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x359, &mut x360, x358, x311, x342);
    let mut x361: uint32_t = 0;
    let mut x362: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x361, &mut x362, x360, x313, x344);
    let mut x363: uint32_t = 0;
    let mut x364: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x363,
        &mut x364,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x365: uint32_t = 0;
    let mut x366: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x365,
        &mut x366,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x367: uint32_t = 0;
    let mut x368: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x367,
        &mut x368,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x369: uint32_t = 0;
    let mut x370: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x369,
        &mut x370,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x371: uint32_t = 0;
    let mut x372: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x371,
        &mut x372,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x370,
        x367,
    );
    let mut x373: uint32_t = 0;
    let mut x374: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x373, &mut x374, x372, x368, x365);
    let mut x375: uint32_t = (x374 as std::os::raw::c_uint).wrapping_add(x366);
    let mut x376: uint32_t = 0;
    let mut x377: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x376,
        &mut x377,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x345,
        x369,
    );
    let mut x378: uint32_t = 0;
    let mut x379: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x378, &mut x379, x377, x347, x371);
    let mut x380: uint32_t = 0;
    let mut x381: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x380, &mut x381, x379, x349, x373);
    let mut x382: uint32_t = 0;
    let mut x383: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x382, &mut x383, x381, x351, x375);
    let mut x384: uint32_t = 0;
    let mut x385: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x384,
        &mut x385,
        x383,
        x353,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x386: uint32_t = 0;
    let mut x387: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x386,
        &mut x387,
        x385,
        x355,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x388: uint32_t = 0;
    let mut x389: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x388, &mut x389, x387, x357, x345);
    let mut x390: uint32_t = 0;
    let mut x391: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x390, &mut x391, x389, x359, x363);
    let mut x392: uint32_t = 0;
    let mut x393: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x392, &mut x393, x391, x361, x364);
    let mut x394: uint32_t = (x393 as uint32_t).wrapping_add(x362 as std::os::raw::c_uint);
    let mut x395: uint32_t = 0;
    let mut x396: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x395,
        &mut x396,
        x5,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x397: uint32_t = 0;
    let mut x398: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x397,
        &mut x398,
        x5,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x399: uint32_t = 0;
    let mut x400: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x399,
        &mut x400,
        x5,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x401: uint32_t = 0;
    let mut x402: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x401,
        &mut x402,
        x5,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x403: uint32_t = 0;
    let mut x404: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x403,
        &mut x404,
        x5,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x405: uint32_t = 0;
    let mut x406: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x405,
        &mut x406,
        x5,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x407: uint32_t = 0;
    let mut x408: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x407,
        &mut x408,
        x5,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x409: uint32_t = 0;
    let mut x410: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x409,
        &mut x410,
        x5,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x411: uint32_t = 0;
    let mut x412: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x411,
        &mut x412,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x410,
        x407,
    );
    let mut x413: uint32_t = 0;
    let mut x414: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x413, &mut x414, x412, x408, x405);
    let mut x415: uint32_t = 0;
    let mut x416: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x415, &mut x416, x414, x406, x403);
    let mut x417: uint32_t = 0;
    let mut x418: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x417, &mut x418, x416, x404, x401);
    let mut x419: uint32_t = 0;
    let mut x420: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x419, &mut x420, x418, x402, x399);
    let mut x421: uint32_t = 0;
    let mut x422: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x421, &mut x422, x420, x400, x397);
    let mut x423: uint32_t = 0;
    let mut x424: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x423, &mut x424, x422, x398, x395);
    let mut x425: uint32_t = (x424 as std::os::raw::c_uint).wrapping_add(x396);
    let mut x426: uint32_t = 0;
    let mut x427: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x426,
        &mut x427,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x378,
        x409,
    );
    let mut x428: uint32_t = 0;
    let mut x429: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x428, &mut x429, x427, x380, x411);
    let mut x430: uint32_t = 0;
    let mut x431: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x430, &mut x431, x429, x382, x413);
    let mut x432: uint32_t = 0;
    let mut x433: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x432, &mut x433, x431, x384, x415);
    let mut x434: uint32_t = 0;
    let mut x435: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x434, &mut x435, x433, x386, x417);
    let mut x436: uint32_t = 0;
    let mut x437: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x436, &mut x437, x435, x388, x419);
    let mut x438: uint32_t = 0;
    let mut x439: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x438, &mut x439, x437, x390, x421);
    let mut x440: uint32_t = 0;
    let mut x441: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x440, &mut x441, x439, x392, x423);
    let mut x442: uint32_t = 0;
    let mut x443: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x442, &mut x443, x441, x394, x425);
    let mut x444: uint32_t = 0;
    let mut x445: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x444,
        &mut x445,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x446: uint32_t = 0;
    let mut x447: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x446,
        &mut x447,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x448: uint32_t = 0;
    let mut x449: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x448,
        &mut x449,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x450: uint32_t = 0;
    let mut x451: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x450,
        &mut x451,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x452: uint32_t = 0;
    let mut x453: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x452,
        &mut x453,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x451,
        x448,
    );
    let mut x454: uint32_t = 0;
    let mut x455: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x454, &mut x455, x453, x449, x446);
    let mut x456: uint32_t = (x455 as std::os::raw::c_uint).wrapping_add(x447);
    let mut x457: uint32_t = 0;
    let mut x458: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x457,
        &mut x458,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x426,
        x450,
    );
    let mut x459: uint32_t = 0;
    let mut x460: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x459, &mut x460, x458, x428, x452);
    let mut x461: uint32_t = 0;
    let mut x462: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x461, &mut x462, x460, x430, x454);
    let mut x463: uint32_t = 0;
    let mut x464: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x463, &mut x464, x462, x432, x456);
    let mut x465: uint32_t = 0;
    let mut x466: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x465,
        &mut x466,
        x464,
        x434,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x467: uint32_t = 0;
    let mut x468: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x467,
        &mut x468,
        x466,
        x436,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x469: uint32_t = 0;
    let mut x470: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x469, &mut x470, x468, x438, x426);
    let mut x471: uint32_t = 0;
    let mut x472: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x471, &mut x472, x470, x440, x444);
    let mut x473: uint32_t = 0;
    let mut x474: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x473, &mut x474, x472, x442, x445);
    let mut x475: uint32_t = (x474 as uint32_t).wrapping_add(x443 as std::os::raw::c_uint);
    let mut x476: uint32_t = 0;
    let mut x477: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x476,
        &mut x477,
        x6,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x478: uint32_t = 0;
    let mut x479: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x478,
        &mut x479,
        x6,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x480: uint32_t = 0;
    let mut x481: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x480,
        &mut x481,
        x6,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x482: uint32_t = 0;
    let mut x483: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x482,
        &mut x483,
        x6,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x484: uint32_t = 0;
    let mut x485: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x484,
        &mut x485,
        x6,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x486: uint32_t = 0;
    let mut x487: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x486,
        &mut x487,
        x6,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x488: uint32_t = 0;
    let mut x489: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x488,
        &mut x489,
        x6,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x490: uint32_t = 0;
    let mut x491: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x490,
        &mut x491,
        x6,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x492: uint32_t = 0;
    let mut x493: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x492,
        &mut x493,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x491,
        x488,
    );
    let mut x494: uint32_t = 0;
    let mut x495: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x494, &mut x495, x493, x489, x486);
    let mut x496: uint32_t = 0;
    let mut x497: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x496, &mut x497, x495, x487, x484);
    let mut x498: uint32_t = 0;
    let mut x499: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x498, &mut x499, x497, x485, x482);
    let mut x500: uint32_t = 0;
    let mut x501: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x500, &mut x501, x499, x483, x480);
    let mut x502: uint32_t = 0;
    let mut x503: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x502, &mut x503, x501, x481, x478);
    let mut x504: uint32_t = 0;
    let mut x505: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x504, &mut x505, x503, x479, x476);
    let mut x506: uint32_t = (x505 as std::os::raw::c_uint).wrapping_add(x477);
    let mut x507: uint32_t = 0;
    let mut x508: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x507,
        &mut x508,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x459,
        x490,
    );
    let mut x509: uint32_t = 0;
    let mut x510: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x509, &mut x510, x508, x461, x492);
    let mut x511: uint32_t = 0;
    let mut x512: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x511, &mut x512, x510, x463, x494);
    let mut x513: uint32_t = 0;
    let mut x514: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x513, &mut x514, x512, x465, x496);
    let mut x515: uint32_t = 0;
    let mut x516: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x515, &mut x516, x514, x467, x498);
    let mut x517: uint32_t = 0;
    let mut x518: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x517, &mut x518, x516, x469, x500);
    let mut x519: uint32_t = 0;
    let mut x520: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x519, &mut x520, x518, x471, x502);
    let mut x521: uint32_t = 0;
    let mut x522: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x521, &mut x522, x520, x473, x504);
    let mut x523: uint32_t = 0;
    let mut x524: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x523, &mut x524, x522, x475, x506);
    let mut x525: uint32_t = 0;
    let mut x526: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x525,
        &mut x526,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x527: uint32_t = 0;
    let mut x528: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x527,
        &mut x528,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x529: uint32_t = 0;
    let mut x530: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x529,
        &mut x530,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x531: uint32_t = 0;
    let mut x532: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x531,
        &mut x532,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x533: uint32_t = 0;
    let mut x534: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x533,
        &mut x534,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x532,
        x529,
    );
    let mut x535: uint32_t = 0;
    let mut x536: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x535, &mut x536, x534, x530, x527);
    let mut x537: uint32_t = (x536 as std::os::raw::c_uint).wrapping_add(x528);
    let mut x538: uint32_t = 0;
    let mut x539: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x538,
        &mut x539,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x507,
        x531,
    );
    let mut x540: uint32_t = 0;
    let mut x541: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x540, &mut x541, x539, x509, x533);
    let mut x542: uint32_t = 0;
    let mut x543: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x542, &mut x543, x541, x511, x535);
    let mut x544: uint32_t = 0;
    let mut x545: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x544, &mut x545, x543, x513, x537);
    let mut x546: uint32_t = 0;
    let mut x547: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x546,
        &mut x547,
        x545,
        x515,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x548: uint32_t = 0;
    let mut x549: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x548,
        &mut x549,
        x547,
        x517,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x550: uint32_t = 0;
    let mut x551: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x550, &mut x551, x549, x519, x507);
    let mut x552: uint32_t = 0;
    let mut x553: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x552, &mut x553, x551, x521, x525);
    let mut x554: uint32_t = 0;
    let mut x555: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x554, &mut x555, x553, x523, x526);
    let mut x556: uint32_t = (x555 as uint32_t).wrapping_add(x524 as std::os::raw::c_uint);
    let mut x557: uint32_t = 0;
    let mut x558: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x557,
        &mut x558,
        x7,
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x559: uint32_t = 0;
    let mut x560: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x559,
        &mut x560,
        x7,
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x561: uint32_t = 0;
    let mut x562: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x561,
        &mut x562,
        x7,
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x563: uint32_t = 0;
    let mut x564: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x563,
        &mut x564,
        x7,
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x565: uint32_t = 0;
    let mut x566: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x565,
        &mut x566,
        x7,
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x567: uint32_t = 0;
    let mut x568: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x567,
        &mut x568,
        x7,
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x569: uint32_t = 0;
    let mut x570: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x569,
        &mut x570,
        x7,
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x571: uint32_t = 0;
    let mut x572: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x571,
        &mut x572,
        x7,
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x573: uint32_t = 0;
    let mut x574: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x573,
        &mut x574,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x572,
        x569,
    );
    let mut x575: uint32_t = 0;
    let mut x576: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x575, &mut x576, x574, x570, x567);
    let mut x577: uint32_t = 0;
    let mut x578: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x577, &mut x578, x576, x568, x565);
    let mut x579: uint32_t = 0;
    let mut x580: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x579, &mut x580, x578, x566, x563);
    let mut x581: uint32_t = 0;
    let mut x582: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x581, &mut x582, x580, x564, x561);
    let mut x583: uint32_t = 0;
    let mut x584: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x583, &mut x584, x582, x562, x559);
    let mut x585: uint32_t = 0;
    let mut x586: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x585, &mut x586, x584, x560, x557);
    let mut x587: uint32_t = (x586 as std::os::raw::c_uint).wrapping_add(x558);
    let mut x588: uint32_t = 0;
    let mut x589: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x588,
        &mut x589,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x540,
        x571,
    );
    let mut x590: uint32_t = 0;
    let mut x591: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x590, &mut x591, x589, x542, x573);
    let mut x592: uint32_t = 0;
    let mut x593: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x592, &mut x593, x591, x544, x575);
    let mut x594: uint32_t = 0;
    let mut x595: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x594, &mut x595, x593, x546, x577);
    let mut x596: uint32_t = 0;
    let mut x597: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x596, &mut x597, x595, x548, x579);
    let mut x598: uint32_t = 0;
    let mut x599: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x598, &mut x599, x597, x550, x581);
    let mut x600: uint32_t = 0;
    let mut x601: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x600, &mut x601, x599, x552, x583);
    let mut x602: uint32_t = 0;
    let mut x603: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x602, &mut x603, x601, x554, x585);
    let mut x604: uint32_t = 0;
    let mut x605: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x604, &mut x605, x603, x556, x587);
    let mut x606: uint32_t = 0;
    let mut x607: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x606,
        &mut x607,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x608: uint32_t = 0;
    let mut x609: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x608,
        &mut x609,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x610: uint32_t = 0;
    let mut x611: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x610,
        &mut x611,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x612: uint32_t = 0;
    let mut x613: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x612,
        &mut x613,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x614: uint32_t = 0;
    let mut x615: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x614,
        &mut x615,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x613,
        x610,
    );
    let mut x616: uint32_t = 0;
    let mut x617: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x616, &mut x617, x615, x611, x608);
    let mut x618: uint32_t = (x617 as std::os::raw::c_uint).wrapping_add(x609);
    let mut x619: uint32_t = 0;
    let mut x620: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x619,
        &mut x620,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x588,
        x612,
    );
    let mut x621: uint32_t = 0;
    let mut x622: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x621, &mut x622, x620, x590, x614);
    let mut x623: uint32_t = 0;
    let mut x624: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x623, &mut x624, x622, x592, x616);
    let mut x625: uint32_t = 0;
    let mut x626: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x625, &mut x626, x624, x594, x618);
    let mut x627: uint32_t = 0;
    let mut x628: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x627,
        &mut x628,
        x626,
        x596,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x629: uint32_t = 0;
    let mut x630: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x629,
        &mut x630,
        x628,
        x598,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x631: uint32_t = 0;
    let mut x632: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x631, &mut x632, x630, x600, x588);
    let mut x633: uint32_t = 0;
    let mut x634: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x633, &mut x634, x632, x602, x606);
    let mut x635: uint32_t = 0;
    let mut x636: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x635, &mut x636, x634, x604, x607);
    let mut x637: uint32_t = (x636 as uint32_t).wrapping_add(x605 as std::os::raw::c_uint);
    let mut x638: uint32_t = 0;
    let mut x639: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x638,
        &mut x639,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x621,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x640: uint32_t = 0;
    let mut x641: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x640,
        &mut x641,
        x639,
        x623,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x642: uint32_t = 0;
    let mut x643: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x642,
        &mut x643,
        x641,
        x625,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x644: uint32_t = 0;
    let mut x645: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x644,
        &mut x645,
        x643,
        x627,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x646: uint32_t = 0;
    let mut x647: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x646,
        &mut x647,
        x645,
        x629,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x648: uint32_t = 0;
    let mut x649: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x648,
        &mut x649,
        x647,
        x631,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x650: uint32_t = 0;
    let mut x651: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x650,
        &mut x651,
        x649,
        x633,
        0x1 as std::os::raw::c_int as uint32_t,
    );
    let mut x652: uint32_t = 0;
    let mut x653: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x652,
        &mut x653,
        x651,
        x635,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x654: uint32_t = 0;
    let mut x655: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x654,
        &mut x655,
        x653,
        x637,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x656: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x656, x655, x638, x621);
    let mut x657: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x657, x655, x640, x623);
    let mut x658: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x658, x655, x642, x625);
    let mut x659: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x659, x655, x644, x627);
    let mut x660: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x660, x655, x646, x629);
    let mut x661: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x661, x655, x648, x631);
    let mut x662: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x662, x655, x650, x633);
    let mut x663: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x663, x655, x652, x635);
    *out1.offset(0 as std::os::raw::c_int as isize) = x656;
    *out1.offset(1 as std::os::raw::c_int as isize) = x657;
    *out1.offset(2 as std::os::raw::c_int as isize) = x658;
    *out1.offset(3 as std::os::raw::c_int as isize) = x659;
    *out1.offset(4 as std::os::raw::c_int as isize) = x660;
    *out1.offset(5 as std::os::raw::c_int as isize) = x661;
    *out1.offset(6 as std::os::raw::c_int as isize) = x662;
    *out1.offset(7 as std::os::raw::c_int as isize) = x663;
}
unsafe extern "C" fn fiat_p256_square(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = *arg1.offset(1 as std::os::raw::c_int as isize);
    let mut x2: uint32_t = *arg1.offset(2 as std::os::raw::c_int as isize);
    let mut x3: uint32_t = *arg1.offset(3 as std::os::raw::c_int as isize);
    let mut x4: uint32_t = *arg1.offset(4 as std::os::raw::c_int as isize);
    let mut x5: uint32_t = *arg1.offset(5 as std::os::raw::c_int as isize);
    let mut x6: uint32_t = *arg1.offset(6 as std::os::raw::c_int as isize);
    let mut x7: uint32_t = *arg1.offset(7 as std::os::raw::c_int as isize);
    let mut x8: uint32_t = *arg1.offset(0 as std::os::raw::c_int as isize);
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x9,
        &mut x10,
        x8,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x11: uint32_t = 0;
    let mut x12: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x11,
        &mut x12,
        x8,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x13: uint32_t = 0;
    let mut x14: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x13,
        &mut x14,
        x8,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x15: uint32_t = 0;
    let mut x16: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x15,
        &mut x16,
        x8,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x17,
        &mut x18,
        x8,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x19: uint32_t = 0;
    let mut x20: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x19,
        &mut x20,
        x8,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x21: uint32_t = 0;
    let mut x22: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x21,
        &mut x22,
        x8,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x23: uint32_t = 0;
    let mut x24: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x23,
        &mut x24,
        x8,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x25: uint32_t = 0;
    let mut x26: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x25,
        &mut x26,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x24,
        x21,
    );
    let mut x27: uint32_t = 0;
    let mut x28: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x27, &mut x28, x26, x22, x19);
    let mut x29: uint32_t = 0;
    let mut x30: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x29, &mut x30, x28, x20, x17);
    let mut x31: uint32_t = 0;
    let mut x32: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x31, &mut x32, x30, x18, x15);
    let mut x33: uint32_t = 0;
    let mut x34: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x33, &mut x34, x32, x16, x13);
    let mut x35: uint32_t = 0;
    let mut x36: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x35, &mut x36, x34, x14, x11);
    let mut x37: uint32_t = 0;
    let mut x38: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x37, &mut x38, x36, x12, x9);
    let mut x39: uint32_t = (x38 as std::os::raw::c_uint).wrapping_add(x10);
    let mut x40: uint32_t = 0;
    let mut x41: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x40, &mut x41, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x42: uint32_t = 0;
    let mut x43: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x42, &mut x43, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x44: uint32_t = 0;
    let mut x45: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x44, &mut x45, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x46: uint32_t = 0;
    let mut x47: uint32_t = 0;
    fiat_p256_mulx_u32(&mut x46, &mut x47, x23, 0xffffffff as std::os::raw::c_uint);
    let mut x48: uint32_t = 0;
    let mut x49: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x48,
        &mut x49,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x47,
        x44,
    );
    let mut x50: uint32_t = 0;
    let mut x51: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x50, &mut x51, x49, x45, x42);
    let mut x52: uint32_t = (x51 as std::os::raw::c_uint).wrapping_add(x43);
    let mut x53: uint32_t = 0;
    let mut x54: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x53,
        &mut x54,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x23,
        x46,
    );
    let mut x55: uint32_t = 0;
    let mut x56: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x55, &mut x56, x54, x25, x48);
    let mut x57: uint32_t = 0;
    let mut x58: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x57, &mut x58, x56, x27, x50);
    let mut x59: uint32_t = 0;
    let mut x60: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x59, &mut x60, x58, x29, x52);
    let mut x61: uint32_t = 0;
    let mut x62: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x61,
        &mut x62,
        x60,
        x31,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x63: uint32_t = 0;
    let mut x64: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x63,
        &mut x64,
        x62,
        x33,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x65: uint32_t = 0;
    let mut x66: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x65, &mut x66, x64, x35, x23);
    let mut x67: uint32_t = 0;
    let mut x68: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x67, &mut x68, x66, x37, x40);
    let mut x69: uint32_t = 0;
    let mut x70: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x69, &mut x70, x68, x39, x41);
    let mut x71: uint32_t = 0;
    let mut x72: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x71,
        &mut x72,
        x1,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x73: uint32_t = 0;
    let mut x74: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x73,
        &mut x74,
        x1,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x75: uint32_t = 0;
    let mut x76: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x75,
        &mut x76,
        x1,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x77: uint32_t = 0;
    let mut x78: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x77,
        &mut x78,
        x1,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x79: uint32_t = 0;
    let mut x80: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x79,
        &mut x80,
        x1,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x81: uint32_t = 0;
    let mut x82: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x81,
        &mut x82,
        x1,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x83: uint32_t = 0;
    let mut x84: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x83,
        &mut x84,
        x1,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x85: uint32_t = 0;
    let mut x86: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x85,
        &mut x86,
        x1,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x87: uint32_t = 0;
    let mut x88: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x87,
        &mut x88,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x86,
        x83,
    );
    let mut x89: uint32_t = 0;
    let mut x90: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x89, &mut x90, x88, x84, x81);
    let mut x91: uint32_t = 0;
    let mut x92: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x91, &mut x92, x90, x82, x79);
    let mut x93: uint32_t = 0;
    let mut x94: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x93, &mut x94, x92, x80, x77);
    let mut x95: uint32_t = 0;
    let mut x96: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x95, &mut x96, x94, x78, x75);
    let mut x97: uint32_t = 0;
    let mut x98: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x97, &mut x98, x96, x76, x73);
    let mut x99: uint32_t = 0;
    let mut x100: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x99, &mut x100, x98, x74, x71);
    let mut x101: uint32_t = (x100 as std::os::raw::c_uint).wrapping_add(x72);
    let mut x102: uint32_t = 0;
    let mut x103: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x102,
        &mut x103,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x55,
        x85,
    );
    let mut x104: uint32_t = 0;
    let mut x105: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x104, &mut x105, x103, x57, x87);
    let mut x106: uint32_t = 0;
    let mut x107: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x106, &mut x107, x105, x59, x89);
    let mut x108: uint32_t = 0;
    let mut x109: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x108, &mut x109, x107, x61, x91);
    let mut x110: uint32_t = 0;
    let mut x111: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x110, &mut x111, x109, x63, x93);
    let mut x112: uint32_t = 0;
    let mut x113: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x112, &mut x113, x111, x65, x95);
    let mut x114: uint32_t = 0;
    let mut x115: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x114, &mut x115, x113, x67, x97);
    let mut x116: uint32_t = 0;
    let mut x117: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x116, &mut x117, x115, x69, x99);
    let mut x118: uint32_t = 0;
    let mut x119: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x118, &mut x119, x117, x70 as uint32_t, x101);
    let mut x120: uint32_t = 0;
    let mut x121: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x120,
        &mut x121,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x122: uint32_t = 0;
    let mut x123: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x122,
        &mut x123,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x124: uint32_t = 0;
    let mut x125: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x124,
        &mut x125,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x126: uint32_t = 0;
    let mut x127: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x126,
        &mut x127,
        x102,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x128: uint32_t = 0;
    let mut x129: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x128,
        &mut x129,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x127,
        x124,
    );
    let mut x130: uint32_t = 0;
    let mut x131: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x130, &mut x131, x129, x125, x122);
    let mut x132: uint32_t = (x131 as std::os::raw::c_uint).wrapping_add(x123);
    let mut x133: uint32_t = 0;
    let mut x134: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x133,
        &mut x134,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x102,
        x126,
    );
    let mut x135: uint32_t = 0;
    let mut x136: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x135, &mut x136, x134, x104, x128);
    let mut x137: uint32_t = 0;
    let mut x138: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x137, &mut x138, x136, x106, x130);
    let mut x139: uint32_t = 0;
    let mut x140: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x139, &mut x140, x138, x108, x132);
    let mut x141: uint32_t = 0;
    let mut x142: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x141,
        &mut x142,
        x140,
        x110,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x143: uint32_t = 0;
    let mut x144: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x143,
        &mut x144,
        x142,
        x112,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x145: uint32_t = 0;
    let mut x146: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x145, &mut x146, x144, x114, x102);
    let mut x147: uint32_t = 0;
    let mut x148: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x147, &mut x148, x146, x116, x120);
    let mut x149: uint32_t = 0;
    let mut x150: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x149, &mut x150, x148, x118, x121);
    let mut x151: uint32_t = (x150 as uint32_t).wrapping_add(x119 as std::os::raw::c_uint);
    let mut x152: uint32_t = 0;
    let mut x153: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x152,
        &mut x153,
        x2,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x154: uint32_t = 0;
    let mut x155: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x154,
        &mut x155,
        x2,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x156: uint32_t = 0;
    let mut x157: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x156,
        &mut x157,
        x2,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x158: uint32_t = 0;
    let mut x159: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x158,
        &mut x159,
        x2,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x160: uint32_t = 0;
    let mut x161: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x160,
        &mut x161,
        x2,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x162: uint32_t = 0;
    let mut x163: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x162,
        &mut x163,
        x2,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x164: uint32_t = 0;
    let mut x165: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x164,
        &mut x165,
        x2,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x166: uint32_t = 0;
    let mut x167: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x166,
        &mut x167,
        x2,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x168: uint32_t = 0;
    let mut x169: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x168,
        &mut x169,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x167,
        x164,
    );
    let mut x170: uint32_t = 0;
    let mut x171: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x170, &mut x171, x169, x165, x162);
    let mut x172: uint32_t = 0;
    let mut x173: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x172, &mut x173, x171, x163, x160);
    let mut x174: uint32_t = 0;
    let mut x175: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x174, &mut x175, x173, x161, x158);
    let mut x176: uint32_t = 0;
    let mut x177: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x176, &mut x177, x175, x159, x156);
    let mut x178: uint32_t = 0;
    let mut x179: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x178, &mut x179, x177, x157, x154);
    let mut x180: uint32_t = 0;
    let mut x181: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x180, &mut x181, x179, x155, x152);
    let mut x182: uint32_t = (x181 as std::os::raw::c_uint).wrapping_add(x153);
    let mut x183: uint32_t = 0;
    let mut x184: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x183,
        &mut x184,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x135,
        x166,
    );
    let mut x185: uint32_t = 0;
    let mut x186: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x185, &mut x186, x184, x137, x168);
    let mut x187: uint32_t = 0;
    let mut x188: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x187, &mut x188, x186, x139, x170);
    let mut x189: uint32_t = 0;
    let mut x190: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x189, &mut x190, x188, x141, x172);
    let mut x191: uint32_t = 0;
    let mut x192: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x191, &mut x192, x190, x143, x174);
    let mut x193: uint32_t = 0;
    let mut x194: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x193, &mut x194, x192, x145, x176);
    let mut x195: uint32_t = 0;
    let mut x196: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x195, &mut x196, x194, x147, x178);
    let mut x197: uint32_t = 0;
    let mut x198: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x197, &mut x198, x196, x149, x180);
    let mut x199: uint32_t = 0;
    let mut x200: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x199, &mut x200, x198, x151, x182);
    let mut x201: uint32_t = 0;
    let mut x202: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x201,
        &mut x202,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x203: uint32_t = 0;
    let mut x204: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x203,
        &mut x204,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x205: uint32_t = 0;
    let mut x206: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x205,
        &mut x206,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x207: uint32_t = 0;
    let mut x208: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x207,
        &mut x208,
        x183,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x209: uint32_t = 0;
    let mut x210: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x209,
        &mut x210,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x208,
        x205,
    );
    let mut x211: uint32_t = 0;
    let mut x212: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x211, &mut x212, x210, x206, x203);
    let mut x213: uint32_t = (x212 as std::os::raw::c_uint).wrapping_add(x204);
    let mut x214: uint32_t = 0;
    let mut x215: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x214,
        &mut x215,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x183,
        x207,
    );
    let mut x216: uint32_t = 0;
    let mut x217: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x216, &mut x217, x215, x185, x209);
    let mut x218: uint32_t = 0;
    let mut x219: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x218, &mut x219, x217, x187, x211);
    let mut x220: uint32_t = 0;
    let mut x221: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x220, &mut x221, x219, x189, x213);
    let mut x222: uint32_t = 0;
    let mut x223: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x222,
        &mut x223,
        x221,
        x191,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x224: uint32_t = 0;
    let mut x225: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x224,
        &mut x225,
        x223,
        x193,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x226: uint32_t = 0;
    let mut x227: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x226, &mut x227, x225, x195, x183);
    let mut x228: uint32_t = 0;
    let mut x229: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x228, &mut x229, x227, x197, x201);
    let mut x230: uint32_t = 0;
    let mut x231: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x230, &mut x231, x229, x199, x202);
    let mut x232: uint32_t = (x231 as uint32_t).wrapping_add(x200 as std::os::raw::c_uint);
    let mut x233: uint32_t = 0;
    let mut x234: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x233,
        &mut x234,
        x3,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x235: uint32_t = 0;
    let mut x236: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x235,
        &mut x236,
        x3,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x237: uint32_t = 0;
    let mut x238: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x237,
        &mut x238,
        x3,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x239: uint32_t = 0;
    let mut x240: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x239,
        &mut x240,
        x3,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x241: uint32_t = 0;
    let mut x242: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x241,
        &mut x242,
        x3,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x243: uint32_t = 0;
    let mut x244: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x243,
        &mut x244,
        x3,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x245: uint32_t = 0;
    let mut x246: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x245,
        &mut x246,
        x3,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x247: uint32_t = 0;
    let mut x248: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x247,
        &mut x248,
        x3,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x249: uint32_t = 0;
    let mut x250: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x249,
        &mut x250,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x248,
        x245,
    );
    let mut x251: uint32_t = 0;
    let mut x252: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x251, &mut x252, x250, x246, x243);
    let mut x253: uint32_t = 0;
    let mut x254: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x253, &mut x254, x252, x244, x241);
    let mut x255: uint32_t = 0;
    let mut x256: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x255, &mut x256, x254, x242, x239);
    let mut x257: uint32_t = 0;
    let mut x258: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x257, &mut x258, x256, x240, x237);
    let mut x259: uint32_t = 0;
    let mut x260: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x259, &mut x260, x258, x238, x235);
    let mut x261: uint32_t = 0;
    let mut x262: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x261, &mut x262, x260, x236, x233);
    let mut x263: uint32_t = (x262 as std::os::raw::c_uint).wrapping_add(x234);
    let mut x264: uint32_t = 0;
    let mut x265: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x264,
        &mut x265,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x216,
        x247,
    );
    let mut x266: uint32_t = 0;
    let mut x267: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x266, &mut x267, x265, x218, x249);
    let mut x268: uint32_t = 0;
    let mut x269: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x268, &mut x269, x267, x220, x251);
    let mut x270: uint32_t = 0;
    let mut x271: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x270, &mut x271, x269, x222, x253);
    let mut x272: uint32_t = 0;
    let mut x273: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x272, &mut x273, x271, x224, x255);
    let mut x274: uint32_t = 0;
    let mut x275: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x274, &mut x275, x273, x226, x257);
    let mut x276: uint32_t = 0;
    let mut x277: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x276, &mut x277, x275, x228, x259);
    let mut x278: uint32_t = 0;
    let mut x279: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x278, &mut x279, x277, x230, x261);
    let mut x280: uint32_t = 0;
    let mut x281: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x280, &mut x281, x279, x232, x263);
    let mut x282: uint32_t = 0;
    let mut x283: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x282,
        &mut x283,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x284: uint32_t = 0;
    let mut x285: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x284,
        &mut x285,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x286: uint32_t = 0;
    let mut x287: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x286,
        &mut x287,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x288: uint32_t = 0;
    let mut x289: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x288,
        &mut x289,
        x264,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x290: uint32_t = 0;
    let mut x291: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x290,
        &mut x291,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x289,
        x286,
    );
    let mut x292: uint32_t = 0;
    let mut x293: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x292, &mut x293, x291, x287, x284);
    let mut x294: uint32_t = (x293 as std::os::raw::c_uint).wrapping_add(x285);
    let mut x295: uint32_t = 0;
    let mut x296: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x295,
        &mut x296,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x264,
        x288,
    );
    let mut x297: uint32_t = 0;
    let mut x298: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x297, &mut x298, x296, x266, x290);
    let mut x299: uint32_t = 0;
    let mut x300: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x299, &mut x300, x298, x268, x292);
    let mut x301: uint32_t = 0;
    let mut x302: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x301, &mut x302, x300, x270, x294);
    let mut x303: uint32_t = 0;
    let mut x304: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x303,
        &mut x304,
        x302,
        x272,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x305: uint32_t = 0;
    let mut x306: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x305,
        &mut x306,
        x304,
        x274,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x307: uint32_t = 0;
    let mut x308: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x307, &mut x308, x306, x276, x264);
    let mut x309: uint32_t = 0;
    let mut x310: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x309, &mut x310, x308, x278, x282);
    let mut x311: uint32_t = 0;
    let mut x312: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x311, &mut x312, x310, x280, x283);
    let mut x313: uint32_t = (x312 as uint32_t).wrapping_add(x281 as std::os::raw::c_uint);
    let mut x314: uint32_t = 0;
    let mut x315: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x314,
        &mut x315,
        x4,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x316: uint32_t = 0;
    let mut x317: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x316,
        &mut x317,
        x4,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x318: uint32_t = 0;
    let mut x319: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x318,
        &mut x319,
        x4,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x320: uint32_t = 0;
    let mut x321: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x320,
        &mut x321,
        x4,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x322: uint32_t = 0;
    let mut x323: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x322,
        &mut x323,
        x4,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x324: uint32_t = 0;
    let mut x325: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x324,
        &mut x325,
        x4,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x326: uint32_t = 0;
    let mut x327: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x326,
        &mut x327,
        x4,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x328: uint32_t = 0;
    let mut x329: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x328,
        &mut x329,
        x4,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x330: uint32_t = 0;
    let mut x331: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x330,
        &mut x331,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x329,
        x326,
    );
    let mut x332: uint32_t = 0;
    let mut x333: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x332, &mut x333, x331, x327, x324);
    let mut x334: uint32_t = 0;
    let mut x335: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x334, &mut x335, x333, x325, x322);
    let mut x336: uint32_t = 0;
    let mut x337: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x336, &mut x337, x335, x323, x320);
    let mut x338: uint32_t = 0;
    let mut x339: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x338, &mut x339, x337, x321, x318);
    let mut x340: uint32_t = 0;
    let mut x341: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x340, &mut x341, x339, x319, x316);
    let mut x342: uint32_t = 0;
    let mut x343: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x342, &mut x343, x341, x317, x314);
    let mut x344: uint32_t = (x343 as std::os::raw::c_uint).wrapping_add(x315);
    let mut x345: uint32_t = 0;
    let mut x346: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x345,
        &mut x346,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x297,
        x328,
    );
    let mut x347: uint32_t = 0;
    let mut x348: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x347, &mut x348, x346, x299, x330);
    let mut x349: uint32_t = 0;
    let mut x350: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x349, &mut x350, x348, x301, x332);
    let mut x351: uint32_t = 0;
    let mut x352: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x351, &mut x352, x350, x303, x334);
    let mut x353: uint32_t = 0;
    let mut x354: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x353, &mut x354, x352, x305, x336);
    let mut x355: uint32_t = 0;
    let mut x356: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x355, &mut x356, x354, x307, x338);
    let mut x357: uint32_t = 0;
    let mut x358: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x357, &mut x358, x356, x309, x340);
    let mut x359: uint32_t = 0;
    let mut x360: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x359, &mut x360, x358, x311, x342);
    let mut x361: uint32_t = 0;
    let mut x362: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x361, &mut x362, x360, x313, x344);
    let mut x363: uint32_t = 0;
    let mut x364: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x363,
        &mut x364,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x365: uint32_t = 0;
    let mut x366: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x365,
        &mut x366,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x367: uint32_t = 0;
    let mut x368: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x367,
        &mut x368,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x369: uint32_t = 0;
    let mut x370: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x369,
        &mut x370,
        x345,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x371: uint32_t = 0;
    let mut x372: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x371,
        &mut x372,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x370,
        x367,
    );
    let mut x373: uint32_t = 0;
    let mut x374: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x373, &mut x374, x372, x368, x365);
    let mut x375: uint32_t = (x374 as std::os::raw::c_uint).wrapping_add(x366);
    let mut x376: uint32_t = 0;
    let mut x377: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x376,
        &mut x377,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x345,
        x369,
    );
    let mut x378: uint32_t = 0;
    let mut x379: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x378, &mut x379, x377, x347, x371);
    let mut x380: uint32_t = 0;
    let mut x381: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x380, &mut x381, x379, x349, x373);
    let mut x382: uint32_t = 0;
    let mut x383: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x382, &mut x383, x381, x351, x375);
    let mut x384: uint32_t = 0;
    let mut x385: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x384,
        &mut x385,
        x383,
        x353,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x386: uint32_t = 0;
    let mut x387: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x386,
        &mut x387,
        x385,
        x355,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x388: uint32_t = 0;
    let mut x389: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x388, &mut x389, x387, x357, x345);
    let mut x390: uint32_t = 0;
    let mut x391: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x390, &mut x391, x389, x359, x363);
    let mut x392: uint32_t = 0;
    let mut x393: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x392, &mut x393, x391, x361, x364);
    let mut x394: uint32_t = (x393 as uint32_t).wrapping_add(x362 as std::os::raw::c_uint);
    let mut x395: uint32_t = 0;
    let mut x396: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x395,
        &mut x396,
        x5,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x397: uint32_t = 0;
    let mut x398: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x397,
        &mut x398,
        x5,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x399: uint32_t = 0;
    let mut x400: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x399,
        &mut x400,
        x5,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x401: uint32_t = 0;
    let mut x402: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x401,
        &mut x402,
        x5,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x403: uint32_t = 0;
    let mut x404: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x403,
        &mut x404,
        x5,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x405: uint32_t = 0;
    let mut x406: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x405,
        &mut x406,
        x5,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x407: uint32_t = 0;
    let mut x408: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x407,
        &mut x408,
        x5,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x409: uint32_t = 0;
    let mut x410: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x409,
        &mut x410,
        x5,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x411: uint32_t = 0;
    let mut x412: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x411,
        &mut x412,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x410,
        x407,
    );
    let mut x413: uint32_t = 0;
    let mut x414: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x413, &mut x414, x412, x408, x405);
    let mut x415: uint32_t = 0;
    let mut x416: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x415, &mut x416, x414, x406, x403);
    let mut x417: uint32_t = 0;
    let mut x418: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x417, &mut x418, x416, x404, x401);
    let mut x419: uint32_t = 0;
    let mut x420: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x419, &mut x420, x418, x402, x399);
    let mut x421: uint32_t = 0;
    let mut x422: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x421, &mut x422, x420, x400, x397);
    let mut x423: uint32_t = 0;
    let mut x424: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x423, &mut x424, x422, x398, x395);
    let mut x425: uint32_t = (x424 as std::os::raw::c_uint).wrapping_add(x396);
    let mut x426: uint32_t = 0;
    let mut x427: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x426,
        &mut x427,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x378,
        x409,
    );
    let mut x428: uint32_t = 0;
    let mut x429: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x428, &mut x429, x427, x380, x411);
    let mut x430: uint32_t = 0;
    let mut x431: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x430, &mut x431, x429, x382, x413);
    let mut x432: uint32_t = 0;
    let mut x433: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x432, &mut x433, x431, x384, x415);
    let mut x434: uint32_t = 0;
    let mut x435: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x434, &mut x435, x433, x386, x417);
    let mut x436: uint32_t = 0;
    let mut x437: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x436, &mut x437, x435, x388, x419);
    let mut x438: uint32_t = 0;
    let mut x439: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x438, &mut x439, x437, x390, x421);
    let mut x440: uint32_t = 0;
    let mut x441: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x440, &mut x441, x439, x392, x423);
    let mut x442: uint32_t = 0;
    let mut x443: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x442, &mut x443, x441, x394, x425);
    let mut x444: uint32_t = 0;
    let mut x445: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x444,
        &mut x445,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x446: uint32_t = 0;
    let mut x447: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x446,
        &mut x447,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x448: uint32_t = 0;
    let mut x449: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x448,
        &mut x449,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x450: uint32_t = 0;
    let mut x451: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x450,
        &mut x451,
        x426,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x452: uint32_t = 0;
    let mut x453: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x452,
        &mut x453,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x451,
        x448,
    );
    let mut x454: uint32_t = 0;
    let mut x455: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x454, &mut x455, x453, x449, x446);
    let mut x456: uint32_t = (x455 as std::os::raw::c_uint).wrapping_add(x447);
    let mut x457: uint32_t = 0;
    let mut x458: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x457,
        &mut x458,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x426,
        x450,
    );
    let mut x459: uint32_t = 0;
    let mut x460: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x459, &mut x460, x458, x428, x452);
    let mut x461: uint32_t = 0;
    let mut x462: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x461, &mut x462, x460, x430, x454);
    let mut x463: uint32_t = 0;
    let mut x464: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x463, &mut x464, x462, x432, x456);
    let mut x465: uint32_t = 0;
    let mut x466: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x465,
        &mut x466,
        x464,
        x434,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x467: uint32_t = 0;
    let mut x468: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x467,
        &mut x468,
        x466,
        x436,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x469: uint32_t = 0;
    let mut x470: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x469, &mut x470, x468, x438, x426);
    let mut x471: uint32_t = 0;
    let mut x472: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x471, &mut x472, x470, x440, x444);
    let mut x473: uint32_t = 0;
    let mut x474: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x473, &mut x474, x472, x442, x445);
    let mut x475: uint32_t = (x474 as uint32_t).wrapping_add(x443 as std::os::raw::c_uint);
    let mut x476: uint32_t = 0;
    let mut x477: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x476,
        &mut x477,
        x6,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x478: uint32_t = 0;
    let mut x479: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x478,
        &mut x479,
        x6,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x480: uint32_t = 0;
    let mut x481: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x480,
        &mut x481,
        x6,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x482: uint32_t = 0;
    let mut x483: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x482,
        &mut x483,
        x6,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x484: uint32_t = 0;
    let mut x485: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x484,
        &mut x485,
        x6,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x486: uint32_t = 0;
    let mut x487: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x486,
        &mut x487,
        x6,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x488: uint32_t = 0;
    let mut x489: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x488,
        &mut x489,
        x6,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x490: uint32_t = 0;
    let mut x491: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x490,
        &mut x491,
        x6,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x492: uint32_t = 0;
    let mut x493: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x492,
        &mut x493,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x491,
        x488,
    );
    let mut x494: uint32_t = 0;
    let mut x495: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x494, &mut x495, x493, x489, x486);
    let mut x496: uint32_t = 0;
    let mut x497: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x496, &mut x497, x495, x487, x484);
    let mut x498: uint32_t = 0;
    let mut x499: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x498, &mut x499, x497, x485, x482);
    let mut x500: uint32_t = 0;
    let mut x501: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x500, &mut x501, x499, x483, x480);
    let mut x502: uint32_t = 0;
    let mut x503: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x502, &mut x503, x501, x481, x478);
    let mut x504: uint32_t = 0;
    let mut x505: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x504, &mut x505, x503, x479, x476);
    let mut x506: uint32_t = (x505 as std::os::raw::c_uint).wrapping_add(x477);
    let mut x507: uint32_t = 0;
    let mut x508: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x507,
        &mut x508,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x459,
        x490,
    );
    let mut x509: uint32_t = 0;
    let mut x510: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x509, &mut x510, x508, x461, x492);
    let mut x511: uint32_t = 0;
    let mut x512: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x511, &mut x512, x510, x463, x494);
    let mut x513: uint32_t = 0;
    let mut x514: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x513, &mut x514, x512, x465, x496);
    let mut x515: uint32_t = 0;
    let mut x516: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x515, &mut x516, x514, x467, x498);
    let mut x517: uint32_t = 0;
    let mut x518: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x517, &mut x518, x516, x469, x500);
    let mut x519: uint32_t = 0;
    let mut x520: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x519, &mut x520, x518, x471, x502);
    let mut x521: uint32_t = 0;
    let mut x522: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x521, &mut x522, x520, x473, x504);
    let mut x523: uint32_t = 0;
    let mut x524: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x523, &mut x524, x522, x475, x506);
    let mut x525: uint32_t = 0;
    let mut x526: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x525,
        &mut x526,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x527: uint32_t = 0;
    let mut x528: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x527,
        &mut x528,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x529: uint32_t = 0;
    let mut x530: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x529,
        &mut x530,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x531: uint32_t = 0;
    let mut x532: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x531,
        &mut x532,
        x507,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x533: uint32_t = 0;
    let mut x534: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x533,
        &mut x534,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x532,
        x529,
    );
    let mut x535: uint32_t = 0;
    let mut x536: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x535, &mut x536, x534, x530, x527);
    let mut x537: uint32_t = (x536 as std::os::raw::c_uint).wrapping_add(x528);
    let mut x538: uint32_t = 0;
    let mut x539: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x538,
        &mut x539,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x507,
        x531,
    );
    let mut x540: uint32_t = 0;
    let mut x541: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x540, &mut x541, x539, x509, x533);
    let mut x542: uint32_t = 0;
    let mut x543: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x542, &mut x543, x541, x511, x535);
    let mut x544: uint32_t = 0;
    let mut x545: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x544, &mut x545, x543, x513, x537);
    let mut x546: uint32_t = 0;
    let mut x547: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x546,
        &mut x547,
        x545,
        x515,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x548: uint32_t = 0;
    let mut x549: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x548,
        &mut x549,
        x547,
        x517,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x550: uint32_t = 0;
    let mut x551: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x550, &mut x551, x549, x519, x507);
    let mut x552: uint32_t = 0;
    let mut x553: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x552, &mut x553, x551, x521, x525);
    let mut x554: uint32_t = 0;
    let mut x555: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x554, &mut x555, x553, x523, x526);
    let mut x556: uint32_t = (x555 as uint32_t).wrapping_add(x524 as std::os::raw::c_uint);
    let mut x557: uint32_t = 0;
    let mut x558: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x557,
        &mut x558,
        x7,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x559: uint32_t = 0;
    let mut x560: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x559,
        &mut x560,
        x7,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x561: uint32_t = 0;
    let mut x562: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x561,
        &mut x562,
        x7,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x563: uint32_t = 0;
    let mut x564: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x563,
        &mut x564,
        x7,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x565: uint32_t = 0;
    let mut x566: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x565,
        &mut x566,
        x7,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x567: uint32_t = 0;
    let mut x568: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x567,
        &mut x568,
        x7,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x569: uint32_t = 0;
    let mut x570: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x569,
        &mut x570,
        x7,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x571: uint32_t = 0;
    let mut x572: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x571,
        &mut x572,
        x7,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x573: uint32_t = 0;
    let mut x574: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x573,
        &mut x574,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x572,
        x569,
    );
    let mut x575: uint32_t = 0;
    let mut x576: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x575, &mut x576, x574, x570, x567);
    let mut x577: uint32_t = 0;
    let mut x578: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x577, &mut x578, x576, x568, x565);
    let mut x579: uint32_t = 0;
    let mut x580: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x579, &mut x580, x578, x566, x563);
    let mut x581: uint32_t = 0;
    let mut x582: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x581, &mut x582, x580, x564, x561);
    let mut x583: uint32_t = 0;
    let mut x584: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x583, &mut x584, x582, x562, x559);
    let mut x585: uint32_t = 0;
    let mut x586: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x585, &mut x586, x584, x560, x557);
    let mut x587: uint32_t = (x586 as std::os::raw::c_uint).wrapping_add(x558);
    let mut x588: uint32_t = 0;
    let mut x589: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x588,
        &mut x589,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x540,
        x571,
    );
    let mut x590: uint32_t = 0;
    let mut x591: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x590, &mut x591, x589, x542, x573);
    let mut x592: uint32_t = 0;
    let mut x593: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x592, &mut x593, x591, x544, x575);
    let mut x594: uint32_t = 0;
    let mut x595: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x594, &mut x595, x593, x546, x577);
    let mut x596: uint32_t = 0;
    let mut x597: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x596, &mut x597, x595, x548, x579);
    let mut x598: uint32_t = 0;
    let mut x599: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x598, &mut x599, x597, x550, x581);
    let mut x600: uint32_t = 0;
    let mut x601: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x600, &mut x601, x599, x552, x583);
    let mut x602: uint32_t = 0;
    let mut x603: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x602, &mut x603, x601, x554, x585);
    let mut x604: uint32_t = 0;
    let mut x605: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x604, &mut x605, x603, x556, x587);
    let mut x606: uint32_t = 0;
    let mut x607: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x606,
        &mut x607,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x608: uint32_t = 0;
    let mut x609: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x608,
        &mut x609,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x610: uint32_t = 0;
    let mut x611: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x610,
        &mut x611,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x612: uint32_t = 0;
    let mut x613: uint32_t = 0;
    fiat_p256_mulx_u32(
        &mut x612,
        &mut x613,
        x588,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x614: uint32_t = 0;
    let mut x615: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x614,
        &mut x615,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x613,
        x610,
    );
    let mut x616: uint32_t = 0;
    let mut x617: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x616, &mut x617, x615, x611, x608);
    let mut x618: uint32_t = (x617 as std::os::raw::c_uint).wrapping_add(x609);
    let mut x619: uint32_t = 0;
    let mut x620: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x619,
        &mut x620,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x588,
        x612,
    );
    let mut x621: uint32_t = 0;
    let mut x622: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x621, &mut x622, x620, x590, x614);
    let mut x623: uint32_t = 0;
    let mut x624: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x623, &mut x624, x622, x592, x616);
    let mut x625: uint32_t = 0;
    let mut x626: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x625, &mut x626, x624, x594, x618);
    let mut x627: uint32_t = 0;
    let mut x628: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x627,
        &mut x628,
        x626,
        x596,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x629: uint32_t = 0;
    let mut x630: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x629,
        &mut x630,
        x628,
        x598,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x631: uint32_t = 0;
    let mut x632: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x631, &mut x632, x630, x600, x588);
    let mut x633: uint32_t = 0;
    let mut x634: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x633, &mut x634, x632, x602, x606);
    let mut x635: uint32_t = 0;
    let mut x636: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(&mut x635, &mut x636, x634, x604, x607);
    let mut x637: uint32_t = (x636 as uint32_t).wrapping_add(x605 as std::os::raw::c_uint);
    let mut x638: uint32_t = 0;
    let mut x639: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x638,
        &mut x639,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x621,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x640: uint32_t = 0;
    let mut x641: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x640,
        &mut x641,
        x639,
        x623,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x642: uint32_t = 0;
    let mut x643: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x642,
        &mut x643,
        x641,
        x625,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x644: uint32_t = 0;
    let mut x645: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x644,
        &mut x645,
        x643,
        x627,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x646: uint32_t = 0;
    let mut x647: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x646,
        &mut x647,
        x645,
        x629,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x648: uint32_t = 0;
    let mut x649: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x648,
        &mut x649,
        x647,
        x631,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x650: uint32_t = 0;
    let mut x651: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x650,
        &mut x651,
        x649,
        x633,
        0x1 as std::os::raw::c_int as uint32_t,
    );
    let mut x652: uint32_t = 0;
    let mut x653: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x652,
        &mut x653,
        x651,
        x635,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x654: uint32_t = 0;
    let mut x655: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x654,
        &mut x655,
        x653,
        x637,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x656: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x656, x655, x638, x621);
    let mut x657: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x657, x655, x640, x623);
    let mut x658: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x658, x655, x642, x625);
    let mut x659: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x659, x655, x644, x627);
    let mut x660: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x660, x655, x646, x629);
    let mut x661: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x661, x655, x648, x631);
    let mut x662: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x662, x655, x650, x633);
    let mut x663: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x663, x655, x652, x635);
    *out1.offset(0 as std::os::raw::c_int as isize) = x656;
    *out1.offset(1 as std::os::raw::c_int as isize) = x657;
    *out1.offset(2 as std::os::raw::c_int as isize) = x658;
    *out1.offset(3 as std::os::raw::c_int as isize) = x659;
    *out1.offset(4 as std::os::raw::c_int as isize) = x660;
    *out1.offset(5 as std::os::raw::c_int as isize) = x661;
    *out1.offset(6 as std::os::raw::c_int as isize) = x662;
    *out1.offset(7 as std::os::raw::c_int as isize) = x663;
}
unsafe extern "C" fn fiat_p256_add(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x1,
        &mut x2,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        *arg1.offset(0 as std::os::raw::c_int as isize),
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x3: uint32_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as std::os::raw::c_int as isize),
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x5: uint32_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as std::os::raw::c_int as isize),
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x7: uint32_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as std::os::raw::c_int as isize),
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x9: uint32_t = 0;
    let mut x10: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x9,
        &mut x10,
        x8,
        *arg1.offset(4 as std::os::raw::c_int as isize),
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x11: uint32_t = 0;
    let mut x12: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x11,
        &mut x12,
        x10,
        *arg1.offset(5 as std::os::raw::c_int as isize),
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x13: uint32_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x13,
        &mut x14,
        x12,
        *arg1.offset(6 as std::os::raw::c_int as isize),
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x15: uint32_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x15,
        &mut x16,
        x14,
        *arg1.offset(7 as std::os::raw::c_int as isize),
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x17: uint32_t = 0;
    let mut x18: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x17,
        &mut x18,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x1,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x19: uint32_t = 0;
    let mut x20: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x19,
        &mut x20,
        x18,
        x3,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x21: uint32_t = 0;
    let mut x22: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x21,
        &mut x22,
        x20,
        x5,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x23: uint32_t = 0;
    let mut x24: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x23,
        &mut x24,
        x22,
        x7,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x25: uint32_t = 0;
    let mut x26: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x25,
        &mut x26,
        x24,
        x9,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x27: uint32_t = 0;
    let mut x28: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x27,
        &mut x28,
        x26,
        x11,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x29: uint32_t = 0;
    let mut x30: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x29,
        &mut x30,
        x28,
        x13,
        0x1 as std::os::raw::c_int as uint32_t,
    );
    let mut x31: uint32_t = 0;
    let mut x32: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x31,
        &mut x32,
        x30,
        x15,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x33: uint32_t = 0;
    let mut x34: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x33,
        &mut x34,
        x32,
        x16 as uint32_t,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x35: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x35, x34, x17, x1);
    let mut x36: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x36, x34, x19, x3);
    let mut x37: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x37, x34, x21, x5);
    let mut x38: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x38, x34, x23, x7);
    let mut x39: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x39, x34, x25, x9);
    let mut x40: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x40, x34, x27, x11);
    let mut x41: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x41, x34, x29, x13);
    let mut x42: uint32_t = 0;
    fiat_p256_cmovznz_u32(&mut x42, x34, x31, x15);
    *out1.offset(0 as std::os::raw::c_int as isize) = x35;
    *out1.offset(1 as std::os::raw::c_int as isize) = x36;
    *out1.offset(2 as std::os::raw::c_int as isize) = x37;
    *out1.offset(3 as std::os::raw::c_int as isize) = x38;
    *out1.offset(4 as std::os::raw::c_int as isize) = x39;
    *out1.offset(5 as std::os::raw::c_int as isize) = x40;
    *out1.offset(6 as std::os::raw::c_int as isize) = x41;
    *out1.offset(7 as std::os::raw::c_int as isize) = x42;
}
unsafe extern "C" fn fiat_p256_sub(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x1,
        &mut x2,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        *arg1.offset(0 as std::os::raw::c_int as isize),
        *arg2.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x3: uint32_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as std::os::raw::c_int as isize),
        *arg2.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x5: uint32_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as std::os::raw::c_int as isize),
        *arg2.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x7: uint32_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as std::os::raw::c_int as isize),
        *arg2.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x9: uint32_t = 0;
    let mut x10: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x9,
        &mut x10,
        x8,
        *arg1.offset(4 as std::os::raw::c_int as isize),
        *arg2.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x11: uint32_t = 0;
    let mut x12: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x11,
        &mut x12,
        x10,
        *arg1.offset(5 as std::os::raw::c_int as isize),
        *arg2.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x13: uint32_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x13,
        &mut x14,
        x12,
        *arg1.offset(6 as std::os::raw::c_int as isize),
        *arg2.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x15: uint32_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x15,
        &mut x16,
        x14,
        *arg1.offset(7 as std::os::raw::c_int as isize),
        *arg2.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x17: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x17,
        x16,
        0 as std::os::raw::c_int as uint32_t,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x18: uint32_t = 0;
    let mut x19: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x18,
        &mut x19,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x1,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x20: uint32_t = 0;
    let mut x21: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x20,
        &mut x21,
        x19,
        x3,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x22: uint32_t = 0;
    let mut x23: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x22,
        &mut x23,
        x21,
        x5,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x24: uint32_t = 0;
    let mut x25: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x24,
        &mut x25,
        x23,
        x7,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x26: uint32_t = 0;
    let mut x27: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x26,
        &mut x27,
        x25,
        x9,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x28: uint32_t = 0;
    let mut x29: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x28,
        &mut x29,
        x27,
        x11,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x30: uint32_t = 0;
    let mut x31: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x30,
        &mut x31,
        x29,
        x13,
        (x17 & 0x1 as std::os::raw::c_int as std::os::raw::c_uint) as fiat_p256_uint1 as uint32_t,
    );
    let mut x32: uint32_t = 0;
    let mut x33: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x32,
        &mut x33,
        x31,
        x15,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    *out1.offset(0 as std::os::raw::c_int as isize) = x18;
    *out1.offset(1 as std::os::raw::c_int as isize) = x20;
    *out1.offset(2 as std::os::raw::c_int as isize) = x22;
    *out1.offset(3 as std::os::raw::c_int as isize) = x24;
    *out1.offset(4 as std::os::raw::c_int as isize) = x26;
    *out1.offset(5 as std::os::raw::c_int as isize) = x28;
    *out1.offset(6 as std::os::raw::c_int as isize) = x30;
    *out1.offset(7 as std::os::raw::c_int as isize) = x32;
}
unsafe extern "C" fn fiat_p256_opp(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x1,
        &mut x2,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x3: uint32_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x3,
        &mut x4,
        x2,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x5: uint32_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x5,
        &mut x6,
        x4,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x7: uint32_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x7,
        &mut x8,
        x6,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x9: uint32_t = 0;
    let mut x10: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x9,
        &mut x10,
        x8,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x11: uint32_t = 0;
    let mut x12: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x11,
        &mut x12,
        x10,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x13: uint32_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x13,
        &mut x14,
        x12,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x15: uint32_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u32(
        &mut x15,
        &mut x16,
        x14,
        0 as std::os::raw::c_int as uint32_t,
        *arg1.offset(7 as std::os::raw::c_int as isize),
    );
    let mut x17: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x17,
        x16,
        0 as std::os::raw::c_int as uint32_t,
        0xffffffff as std::os::raw::c_uint,
    );
    let mut x18: uint32_t = 0;
    let mut x19: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x18,
        &mut x19,
        0 as std::os::raw::c_int as fiat_p256_uint1,
        x1,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x20: uint32_t = 0;
    let mut x21: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x20,
        &mut x21,
        x19,
        x3,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x22: uint32_t = 0;
    let mut x23: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x22,
        &mut x23,
        x21,
        x5,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    let mut x24: uint32_t = 0;
    let mut x25: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x24,
        &mut x25,
        x23,
        x7,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x26: uint32_t = 0;
    let mut x27: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x26,
        &mut x27,
        x25,
        x9,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x28: uint32_t = 0;
    let mut x29: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x28,
        &mut x29,
        x27,
        x11,
        0 as std::os::raw::c_int as uint32_t,
    );
    let mut x30: uint32_t = 0;
    let mut x31: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x30,
        &mut x31,
        x29,
        x13,
        (x17 & 0x1 as std::os::raw::c_int as std::os::raw::c_uint) as fiat_p256_uint1 as uint32_t,
    );
    let mut x32: uint32_t = 0;
    let mut x33: fiat_p256_uint1 = 0;
    fiat_p256_addcarryx_u32(
        &mut x32,
        &mut x33,
        x31,
        x15,
        x17 & 0xffffffff as std::os::raw::c_uint,
    );
    *out1.offset(0 as std::os::raw::c_int as isize) = x18;
    *out1.offset(1 as std::os::raw::c_int as isize) = x20;
    *out1.offset(2 as std::os::raw::c_int as isize) = x22;
    *out1.offset(3 as std::os::raw::c_int as isize) = x24;
    *out1.offset(4 as std::os::raw::c_int as isize) = x26;
    *out1.offset(5 as std::os::raw::c_int as isize) = x28;
    *out1.offset(6 as std::os::raw::c_int as isize) = x30;
    *out1.offset(7 as std::os::raw::c_int as isize) = x32;
}
unsafe extern "C" fn fiat_p256_nonzero(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = *arg1.offset(0 as std::os::raw::c_int as isize)
        | (*arg1.offset(1 as std::os::raw::c_int as isize)
            | (*arg1.offset(2 as std::os::raw::c_int as isize)
                | (*arg1.offset(3 as std::os::raw::c_int as isize)
                    | (*arg1.offset(4 as std::os::raw::c_int as isize)
                        | (*arg1.offset(5 as std::os::raw::c_int as isize)
                            | (*arg1.offset(6 as std::os::raw::c_int as isize)
                                | (*arg1.offset(7 as std::os::raw::c_int as isize)
                                    | 0 as std::os::raw::c_int as uint32_t)))))));
    *out1 = x1;
}
unsafe extern "C" fn fiat_p256_selectznz(
    mut out1: *mut uint32_t,
    mut arg1: fiat_p256_uint1,
    mut arg2: *const uint32_t,
    mut arg3: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x1,
        arg1,
        *arg2.offset(0 as std::os::raw::c_int as isize),
        *arg3.offset(0 as std::os::raw::c_int as isize),
    );
    let mut x2: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x2,
        arg1,
        *arg2.offset(1 as std::os::raw::c_int as isize),
        *arg3.offset(1 as std::os::raw::c_int as isize),
    );
    let mut x3: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x3,
        arg1,
        *arg2.offset(2 as std::os::raw::c_int as isize),
        *arg3.offset(2 as std::os::raw::c_int as isize),
    );
    let mut x4: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x4,
        arg1,
        *arg2.offset(3 as std::os::raw::c_int as isize),
        *arg3.offset(3 as std::os::raw::c_int as isize),
    );
    let mut x5: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x5,
        arg1,
        *arg2.offset(4 as std::os::raw::c_int as isize),
        *arg3.offset(4 as std::os::raw::c_int as isize),
    );
    let mut x6: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x6,
        arg1,
        *arg2.offset(5 as std::os::raw::c_int as isize),
        *arg3.offset(5 as std::os::raw::c_int as isize),
    );
    let mut x7: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x7,
        arg1,
        *arg2.offset(6 as std::os::raw::c_int as isize),
        *arg3.offset(6 as std::os::raw::c_int as isize),
    );
    let mut x8: uint32_t = 0;
    fiat_p256_cmovznz_u32(
        &mut x8,
        arg1,
        *arg2.offset(7 as std::os::raw::c_int as isize),
        *arg3.offset(7 as std::os::raw::c_int as isize),
    );
    *out1.offset(0 as std::os::raw::c_int as isize) = x1;
    *out1.offset(1 as std::os::raw::c_int as isize) = x2;
    *out1.offset(2 as std::os::raw::c_int as isize) = x3;
    *out1.offset(3 as std::os::raw::c_int as isize) = x4;
    *out1.offset(4 as std::os::raw::c_int as isize) = x5;
    *out1.offset(5 as std::os::raw::c_int as isize) = x6;
    *out1.offset(6 as std::os::raw::c_int as isize) = x7;
    *out1.offset(7 as std::os::raw::c_int as isize) = x8;
}
unsafe extern "C" fn fiat_p256_nz(mut in1: *const fiat_p256_limb_t) -> fiat_p256_limb_t {
    let mut ret: fiat_p256_limb_t = 0;
    fiat_p256_nonzero(&mut ret, in1);
    return ret;
}
unsafe extern "C" fn fiat_p256_copy(
    mut out: *mut fiat_p256_limb_t,
    mut in1: *const fiat_p256_limb_t,
) {
    let mut i: size_t = 0 as std::os::raw::c_int as size_t;
    while i < 8 as std::os::raw::c_int as u64 {
        *out.offset(i as isize) = *in1.offset(i as isize);
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn fiat_p256_cmovznz(
    mut out: *mut fiat_p256_limb_t,
    mut t: fiat_p256_limb_t,
    mut z: *const fiat_p256_limb_t,
    mut nz: *const fiat_p256_limb_t,
) {
    fiat_p256_selectznz(
        out,
        (t != 0) as std::os::raw::c_int as fiat_p256_uint1,
        z,
        nz,
    );
}
#[no_mangle]
pub unsafe extern "C" fn fiat_p256_point_double(
    mut x_out: *mut uint32_t,
    mut y_out: *mut uint32_t,
    mut z_out: *mut uint32_t,
    mut x_in: *const uint32_t,
    mut y_in: *const uint32_t,
    mut z_in: *const uint32_t,
) {
    let mut delta: fiat_p256_felem = [0; 8];
    let mut gamma: fiat_p256_felem = [0; 8];
    let mut beta: fiat_p256_felem = [0; 8];
    let mut ftmp: fiat_p256_felem = [0; 8];
    let mut ftmp2: fiat_p256_felem = [0; 8];
    let mut tmptmp: fiat_p256_felem = [0; 8];
    let mut alpha: fiat_p256_felem = [0; 8];
    let mut fourbeta: fiat_p256_felem = [0; 8];
    fiat_p256_square(delta.as_mut_ptr(), z_in);
    fiat_p256_square(gamma.as_mut_ptr(), y_in);
    fiat_p256_mul(
        beta.as_mut_ptr(),
        x_in,
        gamma.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        ftmp.as_mut_ptr(),
        x_in,
        delta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        ftmp2.as_mut_ptr(),
        x_in,
        delta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        tmptmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const uint32_t,
        ftmp2.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        ftmp2.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const uint32_t,
        tmptmp.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_mul(
        alpha.as_mut_ptr(),
        ftmp.as_mut_ptr() as *const uint32_t,
        ftmp2.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_square(x_out, alpha.as_mut_ptr() as *const uint32_t);
    fiat_p256_add(
        fourbeta.as_mut_ptr(),
        beta.as_mut_ptr() as *const uint32_t,
        beta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        fourbeta.as_mut_ptr(),
        fourbeta.as_mut_ptr() as *const uint32_t,
        fourbeta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        tmptmp.as_mut_ptr(),
        fourbeta.as_mut_ptr() as *const uint32_t,
        fourbeta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        x_out,
        x_out as *const uint32_t,
        tmptmp.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        delta.as_mut_ptr(),
        gamma.as_mut_ptr() as *const uint32_t,
        delta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(ftmp.as_mut_ptr(), y_in, z_in);
    fiat_p256_square(z_out, ftmp.as_mut_ptr() as *const uint32_t);
    fiat_p256_sub(
        z_out,
        z_out as *const uint32_t,
        delta.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        y_out,
        fourbeta.as_mut_ptr() as *const uint32_t,
        x_out as *const uint32_t,
    );
    fiat_p256_add(
        gamma.as_mut_ptr(),
        gamma.as_mut_ptr() as *const uint32_t,
        gamma.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_square(gamma.as_mut_ptr(), gamma.as_mut_ptr() as *const uint32_t);
    fiat_p256_mul(
        y_out,
        alpha.as_mut_ptr() as *const uint32_t,
        y_out as *const uint32_t,
    );
    fiat_p256_add(
        gamma.as_mut_ptr(),
        gamma.as_mut_ptr() as *const uint32_t,
        gamma.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        y_out,
        y_out as *const uint32_t,
        gamma.as_mut_ptr() as *const uint32_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn fiat_p256_point_add(
    mut x3: *mut uint32_t,
    mut y3: *mut uint32_t,
    mut z3: *mut uint32_t,
    mut x1: *const uint32_t,
    mut y1: *const uint32_t,
    mut z1: *const uint32_t,
    mixed: std::os::raw::c_int,
    mut x2: *const uint32_t,
    mut y2: *const uint32_t,
    mut z2: *const uint32_t,
) {
    let mut x_out: fiat_p256_felem = [0; 8];
    let mut y_out: fiat_p256_felem = [0; 8];
    let mut z_out: fiat_p256_felem = [0; 8];
    let mut z1nz: fiat_p256_limb_t = fiat_p256_nz(z1);
    let mut z2nz: fiat_p256_limb_t = fiat_p256_nz(z2);
    let mut z1z1: fiat_p256_felem = [0; 8];
    fiat_p256_square(z1z1.as_mut_ptr(), z1);
    let mut u1: fiat_p256_felem = [0; 8];
    let mut s1: fiat_p256_felem = [0; 8];
    let mut two_z1z2: fiat_p256_felem = [0; 8];
    if mixed == 0 {
        let mut z2z2: fiat_p256_felem = [0; 8];
        fiat_p256_square(z2z2.as_mut_ptr(), z2);
        fiat_p256_mul(u1.as_mut_ptr(), x1, z2z2.as_mut_ptr() as *const uint32_t);
        fiat_p256_add(two_z1z2.as_mut_ptr(), z1, z2);
        fiat_p256_square(
            two_z1z2.as_mut_ptr(),
            two_z1z2.as_mut_ptr() as *const uint32_t,
        );
        fiat_p256_sub(
            two_z1z2.as_mut_ptr(),
            two_z1z2.as_mut_ptr() as *const uint32_t,
            z1z1.as_mut_ptr() as *const uint32_t,
        );
        fiat_p256_sub(
            two_z1z2.as_mut_ptr(),
            two_z1z2.as_mut_ptr() as *const uint32_t,
            z2z2.as_mut_ptr() as *const uint32_t,
        );
        fiat_p256_mul(s1.as_mut_ptr(), z2, z2z2.as_mut_ptr() as *const uint32_t);
        fiat_p256_mul(s1.as_mut_ptr(), s1.as_mut_ptr() as *const uint32_t, y1);
    } else {
        fiat_p256_copy(u1.as_mut_ptr(), x1);
        fiat_p256_add(two_z1z2.as_mut_ptr(), z1, z1);
        fiat_p256_copy(s1.as_mut_ptr(), y1);
    }
    let mut u2: fiat_p256_felem = [0; 8];
    fiat_p256_mul(u2.as_mut_ptr(), x2, z1z1.as_mut_ptr() as *const uint32_t);
    let mut h: fiat_p256_felem = [0; 8];
    fiat_p256_sub(
        h.as_mut_ptr(),
        u2.as_mut_ptr() as *const uint32_t,
        u1.as_mut_ptr() as *const uint32_t,
    );
    let mut xneq: fiat_p256_limb_t = fiat_p256_nz(h.as_mut_ptr() as *const fiat_p256_limb_t);
    fiat_p256_mul(
        z_out.as_mut_ptr(),
        h.as_mut_ptr() as *const uint32_t,
        two_z1z2.as_mut_ptr() as *const uint32_t,
    );
    let mut z1z1z1: fiat_p256_felem = [0; 8];
    fiat_p256_mul(
        z1z1z1.as_mut_ptr(),
        z1,
        z1z1.as_mut_ptr() as *const uint32_t,
    );
    let mut s2: fiat_p256_felem = [0; 8];
    fiat_p256_mul(s2.as_mut_ptr(), y2, z1z1z1.as_mut_ptr() as *const uint32_t);
    let mut r: fiat_p256_felem = [0; 8];
    fiat_p256_sub(
        r.as_mut_ptr(),
        s2.as_mut_ptr() as *const uint32_t,
        s1.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_add(
        r.as_mut_ptr(),
        r.as_mut_ptr() as *const uint32_t,
        r.as_mut_ptr() as *const uint32_t,
    );
    let mut yneq: fiat_p256_limb_t = fiat_p256_nz(r.as_mut_ptr() as *const fiat_p256_limb_t);
    let mut is_nontrivial_double: fiat_p256_limb_t = constant_time_is_zero_w(xneq | yneq)
        & !constant_time_is_zero_w(z1nz)
        & !constant_time_is_zero_w(z2nz);
    if is_nontrivial_double != 0 {
        fiat_p256_point_double(x3, y3, z3, x1, y1, z1);
        return;
    }
    let mut i: fiat_p256_felem = [0; 8];
    fiat_p256_add(
        i.as_mut_ptr(),
        h.as_mut_ptr() as *const uint32_t,
        h.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_square(i.as_mut_ptr(), i.as_mut_ptr() as *const uint32_t);
    let mut j: fiat_p256_felem = [0; 8];
    fiat_p256_mul(
        j.as_mut_ptr(),
        h.as_mut_ptr() as *const uint32_t,
        i.as_mut_ptr() as *const uint32_t,
    );
    let mut v: fiat_p256_felem = [0; 8];
    fiat_p256_mul(
        v.as_mut_ptr(),
        u1.as_mut_ptr() as *const uint32_t,
        i.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_square(x_out.as_mut_ptr(), r.as_mut_ptr() as *const uint32_t);
    fiat_p256_sub(
        x_out.as_mut_ptr(),
        x_out.as_mut_ptr() as *const uint32_t,
        j.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        x_out.as_mut_ptr(),
        x_out.as_mut_ptr() as *const uint32_t,
        v.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        x_out.as_mut_ptr(),
        x_out.as_mut_ptr() as *const uint32_t,
        v.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        y_out.as_mut_ptr(),
        v.as_mut_ptr() as *const uint32_t,
        x_out.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_mul(
        y_out.as_mut_ptr(),
        y_out.as_mut_ptr() as *const uint32_t,
        r.as_mut_ptr() as *const uint32_t,
    );
    let mut s1j: fiat_p256_felem = [0; 8];
    fiat_p256_mul(
        s1j.as_mut_ptr(),
        s1.as_mut_ptr() as *const uint32_t,
        j.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        y_out.as_mut_ptr(),
        y_out.as_mut_ptr() as *const uint32_t,
        s1j.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_sub(
        y_out.as_mut_ptr(),
        y_out.as_mut_ptr() as *const uint32_t,
        s1j.as_mut_ptr() as *const uint32_t,
    );
    fiat_p256_cmovznz(
        x_out.as_mut_ptr(),
        z1nz,
        x2,
        x_out.as_mut_ptr() as *const fiat_p256_limb_t,
    );
    fiat_p256_cmovznz(x3, z2nz, x1, x_out.as_mut_ptr() as *const fiat_p256_limb_t);
    fiat_p256_cmovznz(
        y_out.as_mut_ptr(),
        z1nz,
        y2,
        y_out.as_mut_ptr() as *const fiat_p256_limb_t,
    );
    fiat_p256_cmovznz(y3, z2nz, y1, y_out.as_mut_ptr() as *const fiat_p256_limb_t);
    fiat_p256_cmovznz(
        z_out.as_mut_ptr(),
        z1nz,
        z2,
        z_out.as_mut_ptr() as *const fiat_p256_limb_t,
    );
    fiat_p256_cmovznz(z3, z2nz, z1, z_out.as_mut_ptr() as *const fiat_p256_limb_t);
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_add(
    mut r: *mut P256_POINT,
    mut a: *const P256_POINT,
    mut b: *const P256_POINT,
) {
    fiat_p256_point_add(
        ((*r).X).as_mut_ptr(),
        ((*r).Y).as_mut_ptr(),
        ((*r).Z).as_mut_ptr(),
        ((*a).X).as_ptr(),
        ((*a).Y).as_ptr(),
        ((*a).Z).as_ptr(),
        0 as std::os::raw::c_int,
        ((*b).X).as_ptr(),
        ((*b).Y).as_ptr(),
        ((*b).Z).as_ptr(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_mul_mont(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
) {
    fiat_p256_mul(r, a, b);
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_sqr_mont(mut r: *mut Limb, mut a: *const Limb) {
    fiat_p256_square(r, a);
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_point_double(
    mut r: *mut P256_POINT,
    mut a: *const P256_POINT,
) {
    fiat_p256_point_double(
        ((*r).X).as_mut_ptr(),
        ((*r).Y).as_mut_ptr(),
        ((*r).Z).as_mut_ptr(),
        ((*a).X).as_ptr(),
        ((*a).Y).as_ptr(),
        ((*a).Z).as_ptr(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_neg(mut res: *mut Limb, mut a: *const Limb) {
    fiat_p256_opp(res, a);
}
