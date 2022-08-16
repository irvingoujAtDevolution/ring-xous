#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_mut)]
extern crate std;



use std::arch::asm;
extern "C" {
fn GFp_bn_mul_mont(
rp: *mut BN_ULONG,
ap: *const BN_ULONG,
bp: *const BN_ULONG,
np: *const BN_ULONG,
n0: *const BN_ULONG,
num: size_t,
);
}
pub type size_t = u64;
pub type __uint32_t = std::os::raw::c_uint;
pub type uint32_t = __uint32_t;
pub type crypto_word = uint32_t;
pub type Limb = crypto_word;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct P256_POINT {
pub X: [Limb; 8],
pub Y: [Limb; 8],
pub Z: [Limb; 8],
}
pub type Elem = [Limb; 8];
pub type BN_ULONG = crypto_word;
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word) -> crypto_word {
core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word) -> crypto_word {
return (0 as std::os::raw::c_uint)
.wrapping_sub(
a
>> (std::mem::size_of::<crypto_word>() as u64)
.wrapping_mul(8 as std::os::raw::c_int as u64)
.wrapping_sub(1 as std::os::raw::c_int as u64),
);
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word) -> crypto_word {
return constant_time_msb_w(!a & a.wrapping_sub(1 as std::os::raw::c_int as std::os::raw::c_uint));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
mut a: crypto_word,
mut b: crypto_word,
) -> crypto_word {
return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
mut mask: crypto_word,
mut a: crypto_word,
mut b: crypto_word,
) -> crypto_word {
return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn limbs_copy(
mut r: *mut Limb,
mut a: *const Limb,
mut num_limbs: size_t,
) {
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
#[no_mangle]
pub unsafe extern "C" fn GFp_p256_scalar_mul_mont(
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
GFp_bn_mul_mont(
r,
a,
b,
N.as_ptr(),
N_N0.as_ptr(),
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
}
#[no_mangle]
pub unsafe extern "C" fn GFp_p256_scalar_sqr_mont(mut r: *mut Limb, mut a: *const Limb) {
GFp_p256_scalar_mul_mont(r, a, a);
}
#[no_mangle]
pub unsafe extern "C" fn GFp_p256_scalar_sqr_rep_mont(
mut r: *mut Limb,
mut a: *const Limb,
mut rep: Limb,
) {
GFp_p256_scalar_sqr_mont(r, a);
let mut i: Limb = 1 as std::os::raw::c_int as Limb;
while i < rep {
GFp_p256_scalar_sqr_mont(r, r as *const Limb);
i = i.wrapping_add(1);
}
}
#[no_mangle]
pub unsafe extern "C" fn GFp_nistz256_select_w5(
mut out: *mut P256_POINT,
mut table: *const P256_POINT,
mut index: crypto_word,
) {
let mut x: Elem = [0; 8];
limbs_zero(
x.as_mut_ptr(),
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
let mut y: Elem = [0; 8];
limbs_zero(
y.as_mut_ptr(),
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
let mut z: Elem = [0; 8];
limbs_zero(
z.as_mut_ptr(),
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
let mut i: size_t = 0 as std::os::raw::c_int as size_t;
while i < 16 as std::os::raw::c_int as u64 {
let mut equal: crypto_word = constant_time_eq_w(
index,
(i as crypto_word).wrapping_add(1 as std::os::raw::c_int as std::os::raw::c_uint),
);
let mut j: size_t = 0 as std::os::raw::c_int as size_t;
while j < (256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as u64
{
x[j
as usize] = constant_time_select_w(
equal,
(*table.offset(i as isize)).X[j as usize],
x[j as usize],
);
y[j
as usize] = constant_time_select_w(
equal,
(*table.offset(i as isize)).Y[j as usize],
y[j as usize],
);
z[j
as usize] = constant_time_select_w(
equal,
(*table.offset(i as isize)).Z[j as usize],
z[j as usize],
);
j = j.wrapping_add(1);
}
i = i.wrapping_add(1);
}
limbs_copy(
((*out).X).as_mut_ptr(),
x.as_mut_ptr() as *const Limb,
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
limbs_copy(
((*out).Y).as_mut_ptr(),
y.as_mut_ptr() as *const Limb,
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
limbs_copy(
((*out).Z).as_mut_ptr(),
z.as_mut_ptr() as *const Limb,
(256 as std::os::raw::c_uint).wrapping_div(32 as std::os::raw::c_uint) as size_t,
);
}
