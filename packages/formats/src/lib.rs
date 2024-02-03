use std::fs::File;
use std::intrinsics::transmute;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::path::Path;

use openssl::rsa::Padding;

pub use bhd::{Bhd, BhdKey};
pub use dcx::{DcxBuilder, DcxDecoder, DcxEncoder, DcxWriter};

mod bhd;
mod dcx;
mod read;
mod write;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn decrypt_bhd<P: AsRef<Path>>(path: P, key: BhdKey) {
    let key_size = key.size() as usize;

    let path = path.as_ref();
    let out_path = path.with_extension("plain");

    let mut out_file = File::create(out_path).unwrap();
    let mut file = File::open(path).unwrap();
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).unwrap();

    for block in encrypted_data.chunks(key_size) {
        let mut decrypted_with_padding = vec![MaybeUninit::<u8>::uninit(); key_size];

        let len = key
            .public_decrypt(
                block,
                unsafe { transmute(&mut decrypted_with_padding[..]) },
                Padding::NONE,
            )
            .unwrap();

        out_file
            .write_all(unsafe { transmute(&decrypted_with_padding[1..len]) })
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
