use alloc::{format, string::String, vec::Vec, vec};

use crate::{bits, digest, error};

use core::char::MAX;
use core::marker::PhantomData;

/// A test case. A test case consists of a set of named attributes. Every
/// attribute in the test case must be consumed exactly once; this helps catch
/// typos and omissions.
///
/// Requires the `alloc` default feature to be enabled.
#[derive(Debug)]
pub struct TestCase {
    attributes: Vec<(String, String, bool)>,
}

#[cfg(feature = "alloc")]
impl TestCase {
    /// Maps the string "true" to true and the string "false" to false.
    pub fn consume_bool(&mut self, key: &str) -> bool {
        match self.consume_string(key).as_ref() {
            "true" => true,
            "false" => false,
            s => panic!("Invalid bool value: {}", s),
        }
    }

    /// Maps the strings "SHA1", "SHA256", "SHA384", and "SHA512" to digest
    /// algorithms, maps "SHA224" to `None`, and panics on other (erroneous)
    /// inputs. "SHA224" is mapped to None because *ring* intentionally does
    /// not support SHA224, but we need to consume test vectors from NIST that
    /// have SHA224 vectors in them.
    pub fn consume_digest_alg(&mut self, key: &str) -> Option<&'static digest::Algorithm> {
        let name = self.consume_string(key);
        match name.as_ref() {
            "SHA1" => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
            "SHA224" => None, // We actively skip SHA-224 support.
            "SHA256" => Some(&digest::SHA256),
            "SHA384" => Some(&digest::SHA384),
            "SHA512" => Some(&digest::SHA512),
            "SHA512_256" => Some(&digest::SHA512_256),
            _ => panic!("Unsupported digest algorithm: {}", name),
        }
    }

    /// Returns the value of an attribute that is encoded as a sequence of an
    /// even number of hex digits, or as a double-quoted UTF-8 string. The
    /// empty (zero-length) value is represented as "".
    pub fn consume_bytes(&mut self, key: &str) -> Vec<u8> {
        let s = self.consume_string(key);
        if s.starts_with('\"') {
            // The value is a quoted UTF-8 string.

            let mut bytes = Vec::with_capacity(s.as_bytes().len() - 2);
            let mut s = s.as_bytes().iter().skip(1);
            loop {
                let b = match s.next() {
                    Some(b'\\') => {
                        match s.next() {
                            // We don't allow all octal escape sequences, only "\0" for null.
                            Some(b'0') => 0u8,
                            Some(b't') => b'\t',
                            Some(b'n') => b'\n',
                            // "\xHH"
                            Some(b'x') => {
                                let hi = s.next().expect("Invalid hex escape sequence in string.");
                                let lo = s.next().expect("Invalid hex escape sequence in string.");
                                if let (Ok(hi), Ok(lo)) = (from_hex_digit(*hi), from_hex_digit(*lo))
                                {
                                    (hi << 4) | lo
                                } else {
                                    panic!("Invalid hex escape sequence in string.");
                                }
                            }
                            _ => {
                                panic!("Invalid hex escape sequence in string.");
                            }
                        }
                    }
                    Some(b'"') => {
                        if s.next().is_some() {
                            panic!("characters after the closing quote of a quoted string.");
                        }
                        break;
                    }
                    Some(b) => *b,
                    None => panic!("Missing terminating '\"' in string literal."),
                };
                bytes.push(b);
            }
            bytes
        } else {
            // The value is hex encoded.
            match from_hex(&s) {
                Ok(s) => s,
                Err(err_str) => {
                    panic!("{} in {}", err_str, s);
                }
            }
        }
    }

    /// Returns the value of an attribute that is an integer, in decimal
    /// notation.
    pub fn consume_usize(&mut self, key: &str) -> usize {
        let s = self.consume_string(key);
        s.parse::<usize>().unwrap()
    }

    /// Returns the value of an attribute that is an integer, in decimal
    /// notation, as a bit length.
    #[cfg(feature = "alloc")]
    pub fn consume_usize_bits(&mut self, key: &str) -> bits::BitLength {
        let s = self.consume_string(key);
        let bits = s.parse::<usize>().unwrap();
        bits::BitLength::from_usize_bits(bits)
    }

    /// Returns the raw value of an attribute, without any unquoting or
    /// other interpretation.
    pub fn consume_string(&mut self, key: &str) -> String {
        self.consume_optional_string(key)
            .unwrap_or_else(|| panic!("No attribute named \"{}\"", key))
    }

    /// Like `consume_string()` except it returns `None` if the test case
    /// doesn't have the attribute.
    pub fn consume_optional_string(&mut self, key: &str) -> Option<String> {
        for (name, value, consumed) in &mut self.attributes {
            if key == name {
                if *consumed {
                    panic!("Attribute {} was already consumed", key);
                }
                *consumed = true;
                return Some(value.clone());
            }
        }
        None
    }
}

/// A test input file.
#[cfg(feature = "alloc")]
pub struct File<'a> {
    /// The name (path) of the file.
    pub file_name: &'a str,

    /// The contents of the file.
    pub contents: &'a str,
}

/// Decode an string of hex digits into a sequence of bytes. The input must
/// have an even number of digits.
#[cfg(feature = "alloc")]
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(String::from(
            "Hex string does not have an even number of digits",
        ));
    }

    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

#[cfg(feature = "alloc")]
fn from_hex_digit(d: u8) -> Result<u8, String> {
    use core::ops::RangeInclusive;
    const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
    const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
    const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
    for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
        if range.contains(&d) {
            return Ok(d - range.start() + offset);
        }
    }
    Err(format!("Invalid hex digit '{}'", d as char))
}

#[cfg(feature = "alloc")]
fn parse_test_case(
    current_section: &mut String,
    lines: &mut dyn Iterator<Item = &str>,
) -> Option<TestCase> {
    let mut attributes = Vec::new();

    let mut is_first_line = true;
    loop {
        let line = lines.next();

        #[cfg(feature = "test_logging")]
        {
            if let Some(text) = &line {
                std::println!("Line: {}", text);
            }
        }

        match line {
            // If we get to EOF when we're not in the middle of a test case,
            // then we're done.
            None if is_first_line => {
                return None;
            }

            // End of the file on a non-empty test cases ends the test case.
            None => {
                return Some(TestCase { attributes });
            }

            // A blank line ends a test case if the test case isn't empty.
            Some(ref line) if line.is_empty() => {
                if !is_first_line {
                    return Some(TestCase { attributes });
                }
                // Ignore leading blank lines.
            }

            // Comments start with '#'; ignore them.
            Some(ref line) if line.starts_with('#') => (),

            Some(ref line) if line.starts_with('[') => {
                assert!(is_first_line);
                assert!(line.ends_with(']'));
                current_section.truncate(0);
                current_section.push_str(line);
                let _ = current_section.pop();
                let _ = current_section.remove(0);
            }

            Some(ref line) => {
                is_first_line = false;

                let parts: Vec<&str> = line.splitn(2, " = ").collect();
                if parts.len() != 2 {
                    panic!("Syntax error: Expected Key = Value.");
                };

                let key = parts[0].trim();
                let value = parts[1].trim();

                // Don't allow the value to be ommitted. An empty value can be
                // represented as an empty quoted string.
                assert_ne!(value.len(), 0);

                // Checking is_none() ensures we don't accept duplicate keys.
                attributes.push((String::from(key), String::from(value), false));
            }
        }
    }
}

/// Parses test cases out of the given file, calling `f` on each vector until
/// `f` fails or until all the test vectors have been read. `f` can indicate
/// failure either by returning `Err()` or by panicking.
///
/// Requires the `alloc` default feature to be enabled
#[cfg(feature = "alloc")]
pub fn run<F>(test_file: File, mut f: F)
where
    F: FnMut(&str, &mut TestCase) -> Result<(), error::Unspecified>,
{
    let lines = &mut test_file.contents.lines();

    let mut current_section = String::from("");
    let mut failed = false;

    while let Some(mut test_case) = parse_test_case(&mut current_section, lines) {
        let result = match f(&current_section, &mut test_case) {
            Ok(()) => {
                if !test_case
                    .attributes
                    .iter()
                    .any(|&(_, _, consumed)| !consumed)
                {
                    Ok(())
                } else {
                    failed = true;
                    Err("Test didn't consume all attributes.")
                }
            }
            Err(error::Unspecified) => Err("Test returned Err(error::Unspecified)."),
        };

        if result.is_err() {
            failed = true;
        }

        #[cfg(feature = "test_logging")]
        {
            if let Err(msg) = result {
                std::println!("{}: {}", test_file.file_name, msg);

                for (name, value, consumed) in test_case.attributes {
                    let consumed_str = if consumed { "" } else { " (unconsumed)" };
                    std::println!("{}{} = {}", name, consumed_str, value);
                }
            };
        }
    }

    if failed {
        panic!("Test failed.")
    }
}

#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! xous_test_file {
    ($file_name:expr) => {
        File {
            file_name: $file_name,
            contents: include_str!($file_name),
        }
    };
}

use crate::ec::suite_b::ops::*;
use crate::arithmetic::montgomery::Unencoded;
use crate::arithmetic::montgomery::R;
use crate::limb::Limb;
use crate::limb::LIMB_BYTES;

pub fn p256_elem_add_test() {
    log::debug!("running elem_add_test");
    elem_add_test(
        &p256::PUBLIC_SCALAR_OPS,
        xous_test_file!("ec/suite_b/ops/p256_elem_sum_tests.txt"),
    );
}

fn consume_padded_bytes(
    ops: &CommonOps,
    test_case: &mut TestCase,
    name: &str,
) -> Vec<u8> {
    let unpadded_bytes = test_case.consume_bytes(name);
    let mut bytes = vec![0; (ops.num_limbs * LIMB_BYTES) - unpadded_bytes.len()];
    bytes.extend(&unpadded_bytes);
    bytes
}

fn consume_elem(ops: &CommonOps, test_case: &mut TestCase, name: &str) -> Elem<R> {
    let bytes = consume_padded_bytes(ops, test_case, name);
    let bytes = untrusted::Input::from(&bytes);
    let r: Elem<Unencoded> = elem_parse_big_endian_fixed_consttime(ops, bytes).unwrap();
    // XXX: “Transmute” this to an `Elem<R>`.
    Elem {
        limbs: r.limbs,
        m: PhantomData,
        encoding: PhantomData,
    }
}

fn assert_limbs_are_equal(
    ops: &CommonOps,
    actual: &[Limb; MAX_LIMBS],
    expected: &[Limb; MAX_LIMBS],
) {
    for i in 0..ops.num_limbs {
        if actual[i] != expected[i] {
            let mut s = alloc::string::String::new();
            for j in 0..ops.num_limbs {
                let formatted = format!("{:016x}", actual[ops.num_limbs - j - 1]);
                s.push_str(&formatted);
            }
            panic!("Actual != Expected,\nActual = {}", s);
        }
    }
}

fn elem_add_test(ops: &PublicScalarOps, test_file: File) {
    run(test_file, |section, test_case| {
        assert_eq!(section, "");

        let cops = ops.public_key_ops.common;
        let a = consume_elem(cops, test_case, "a");
        let b = consume_elem(cops, test_case, "b");
        let expected_sum = consume_elem(cops, test_case, "r");

        let mut actual_sum = a;
        log::debug!("performing add of {:?}+{:?}", actual_sum.limbs, b.limbs);
        log::debug!("pointers: {:x?}, {:x?}", actual_sum.limbs.as_ptr(), b.limbs.as_ptr());
        // -> a limb is 12 x 32 bits
        for i in 0..MAX_LIMBS {
            log::debug!("values b[{}]: {:x?}", i, unsafe{b.limbs.as_ptr().add(i).read()});
        }
        ops.public_key_ops.common.elem_add(&mut actual_sum, &b);
        log::debug!("result of {:?} == {:?}", actual_sum.limbs, expected_sum.limbs);
        assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

        let mut actual_sum = b;
        ops.public_key_ops.common.elem_add(&mut actual_sum, &a);
        assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

        Ok(())
    })
}

/*
rustup target add i686-pc-windows-msvc
cargo run --target i686-pc-windows-msvc
i686-unknown-linux-musl for linux 32-bit
*/