// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Polyfills for functionality that will (hopefully) be added to Rust's
//! standard library soon.

#[inline(always)]
pub const fn u64_from_usize(x: usize) -> u64 {
    x as u64
}

pub fn usize_from_u32(x: u32) -> usize {
    x as usize
}

pub mod slice {
    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill<T>(dest: &mut [T], value: T)
    where
        T: Copy,
    {
        for d in dest {
            *d = value;
        }
    }
}

use core::convert::TryInto;

/// Allows splitting a reference to an array type into fixed-length chunks.
pub trait ChunksFixed<'a, Chunks>
where
    Chunks: 'a,
{
    fn chunks_fixed(self) -> Chunks;
}

/// Allows iterating over a mutable array in fixed-length chunks.
///
/// The design of this is different than that for `ChunksFixed` because it
/// isn't clear that we can legally (according to Rust's rules) convert create
/// a mutable reference to the chunked type from a mutable reference.
///
/// TODO: Get clarification on the rules and refactor this tp be more like
/// `ChunksFixed`.
pub trait ChunksFixedMut<'a, Chunk>
where
    Chunk: 'a,
{
    type MutIterator: Iterator<Item = &'a mut Chunk>;

    fn chunks_fixed_mut(self) -> Self::MutIterator;
}

/// `$unchuncked_len` must be divisible by `$chunk_len`.
macro_rules! define_chunks_fixed {
    ( $unchuncked_len:expr, $chunk_len:expr ) => {
        define_chunks_fixed!($unchuncked_len, $chunk_len, $unchuncked_len / $chunk_len);
    };

    ( $unchuncked_len:expr, $chunk_len:expr, $chunked_len:expr ) => {
        impl<'a, T> ChunksFixed<'a, &'a [[T; $chunk_len]; $chunked_len]>
            for &'a [T; $unchuncked_len]
        {
            #[inline(always)]
            fn chunks_fixed(self) -> &'a [[T; $chunk_len]; $chunked_len] {
                let as_ptr: *const [T; $chunk_len] = self.as_ptr() as *const [T; $chunk_len];
                let as_ptr = as_ptr as *const [[T; $chunk_len]; $chunked_len];
                unsafe { &*as_ptr }
            }
        }

        impl<'a, T> ChunksFixedMut<'a, [T; $chunk_len]> for &'a mut [T; $unchuncked_len] {
            type MutIterator = core::iter::Map<
                core::slice::ChunksExactMut<'a, T>,
                fn(&'a mut [T]) -> &'a mut [T; $chunk_len],
            >;

            #[inline(always)]
            fn chunks_fixed_mut(self) -> Self::MutIterator {
                // There will be no remainder because `$unchuncked_len` must be divisible by
                // `$chunk_len`. The `unwrap()` will not fail for the same reason.
                self.chunks_exact_mut($chunk_len)
                    .map(|slice| slice.try_into().unwrap())
            }
        }
    };
}

// Sorted by the first value, then the second value.
define_chunks_fixed!(12, 4);
define_chunks_fixed!(16, 4);
define_chunks_fixed!(16, 8);
define_chunks_fixed!(32, 4);
define_chunks_fixed!(64, 4);
define_chunks_fixed!(64, 32);
define_chunks_fixed!(80, 20);
