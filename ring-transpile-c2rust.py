#
# 1. Install c2rust dependencies:
#      sudo apt install build-essential llvm clang libclang-dev cmake libssl-dev pkg-config python3
# 2. Install c2rust:
#     cargo install c2rust:
# 3. Run this program inside the target directory:
#     python ring-transpile-c2rust.py
#
# This creates a bunch of `.rs` files with `#[no_mangle] extern "C"` declarations,
# which allow other Rust code to link against it. This program also tries hard to
# fixup the types so that they work without libc.
#
# The resulting code may even compile! But you may need to add more fixes under the
# `massage_line()` function in order to get things working.
#
# The idea behind this program is that you run it once on a project and then begin
# gradually rewriting parts of it.

import subprocess
import os
import re

RING_C_FILES = [
    "crypto/fipsmodule/aes/aes_nohw.c",
    "crypto/fipsmodule/bn/montgomery.c",
    "crypto/fipsmodule/bn/montgomery_inv.c",
    "crypto/limbs/limbs.c",
    "crypto/mem.c",
    "crypto/poly1305/poly1305.c",
    # Other libraries
    "crypto/crypto.c",
    "crypto/curve25519/curve25519.c",
    "crypto/fipsmodule/ec/ecp_nistz.c",
    "crypto/fipsmodule/ec/ecp_nistz256.c",
    "crypto/fipsmodule/ec/gfp_p256.c",
    "crypto/fipsmodule/ec/gfp_p384.c",
    "crypto/fipsmodule/ec/p256.c",
]


COMMANDS_FILE = "compile_commands.json"

p_sizeof = re.compile(r'(.*)(std::mem::size_of::)(.*)(as u64)(.*)')

def massage_line(line):
    line = line.strip()

    # Remove various compile-time directives
    if line == "#![register_tool(c2rust)]":
        return ""
    if line == "use core::arch::asm;":
        return ""
    if line.startswith("#![feature("):
        return ""
    if line.startswith("#![allow("):
        return ""

    # Convert types
    line = line.replace("std::os::raw::c_int", "i32")
    line = line.replace("std::os::raw::c_ulonglong", "u64")
    line = line.replace("std::os::raw::c_longlong", "i64")
    line = line.replace("std::os::raw::c_uint", "u32")
    line = line.replace("std::os::raw::c_char", "u8")
    line = line.replace("std::os::raw::c_uchar", "u8")
    line = line.replace("std::os::raw::c_schar", "i8")
    line = line.replace("std::os::raw::c_void", "u8")
    line = line.replace("::std::mem::transmute", "std::mem::transmute")
    line = line.replace("libc::c_char", "std::os::raw::c_char")
    line = line.replace("libc::c_schar", "std::os::raw::c_schar")
    line = line.replace("libc::c_uchar", "std::os::raw::c_uchar")
    line = line.replace("libc::c_int", "std::os::raw::c_int")
    line = line.replace("libc::c_uint", "std::os::raw::c_uint")
    line = line.replace("libc::c_ulonglong", "u64")
    line = line.replace("libc::c_longlong", "i64")
    line = line.replace("libc::c_ulong", "u32") # this must come after the longlong
    line = line.replace("libc::c_long", "i32")
    line = line.replace("libc::c_void", "std::os::raw::c_void")

    # Fix program-specific oddities
    line = line.replace(" bf16", " u128") # fixed in https://github.com/immunant/c2rust/issues/486, but not yet released
    if line == "GFp_memcpy(":
        line = line.replace("GFp_memcpy(", "let _ = GFp_memcpy(")
    if line == "GFp_memset(":
        line = line.replace("GFp_memset(", "let _ = GFp_memset(")
    if line == "GFp_bn_from_montgomery_in_place(":
        line = line.replace("GFp_bn_from_montgomery_in_place(", "let _ = GFp_bn_from_montgomery_in_place(")
    line = line.replace("::std::mem::size_of", "std::mem::size_of")
    line = line.replace("::std::vec::", "std::vec::")
    line = line.replace(": Vec::", ": std::vec::Vec::")
    line = line.replace(") = limbs_mul_add_limb(", ") = GFp_limbs_mul_add_limb(")
    if p_sizeof.search(line):
        line = p_sizeof.sub(r'\g<1>\g<2>\g<3>as u32\g<5>', line)

    # Replace this ASM weirdness with a barrier
    compiler_fence = (
        "core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);"
    )
    line = line.replace(
        'asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly));',
        compiler_fence,
    )

    return line


def run():

    # Generate the `compile_commands.json` file that c2rust uses
    cwd = os.getcwd()
    with open(COMMANDS_FILE, "w") as cmd_file:
        print("[", file=cmd_file)
        first_line = False
        for file in RING_C_FILES:
            rs_file = file.replace(".c", ".rs")
            if os.path.exists(rs_file):
                os.unlink(rs_file)
            if first_line is not False:
                print(",", file=cmd_file)
            first_line = True
            print("    {", file=cmd_file)
            print(
                f"""        "arguments": [
            "cc",
            "-c",
            "-o",
            "build/tmp.o",
            "-m32",
            "-Iinclude",
            "-UOPENSSL_X86_64",
            "-U__x86_64",
            "-D__xous__",
            "-D__riscv",
            "-D__riscv_xlen=32",
            "-DOPENSSL_USE_NISTZ256",
            "{file}"
        ],
        "directory": "{cwd}",
        "file": "{file}"
    }}""",
                file=cmd_file,
                end="",
            )
        print("", file=cmd_file)
        print("]", file=cmd_file)

    subprocess.run(["c2rust", "transpile", COMMANDS_FILE])

    if not os.path.exists("src/c2rust"):
        os.mkdir("src/c2rust")

    print("Add this to the end of `src/lib.rs`:")

    print("mod c2rust {")
    for file in RING_C_FILES:
        mod_name = file.split("/")[-1].split(".")[0]
        rs_file = file.replace(".c", ".rs")
        # print(f"    #[path = \"../{rs_file}\"]")
        print(f"    mod {mod_name};")
        with open(rs_file, "r") as src_file:
            with open(f"src/c2rust/{mod_name}.rs", "w") as dest_file:
                print("#![allow(non_camel_case_types)]", file=dest_file)
                print("#![allow(non_snake_case)]", file=dest_file)
                print("#![allow(non_upper_case_globals)]", file=dest_file)
                print("#![allow(unused_mut)]", file=dest_file) # this is dubious, let's fix these with another pass later on.
                print("extern crate std;", file=dest_file)
                #print("use core::ffi::*;", file=dest_file)
                for line in src_file:
                    print(massage_line(line), file=dest_file)
            subprocess.run(["rm", rs_file])
            subprocess.run(["rustfmt", "src/c2rust/{}.rs".format(mod_name)])
    print("}")


if __name__ == "__main__":
    run()
