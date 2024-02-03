use std::io::{Cursor, Read, Seek, SeekFrom};
use std::mem::{transmute, MaybeUninit};

use byteorder::{BigEndian, LittleEndian};
use openssl::pkey::Public;
use openssl::rsa::{Padding, Rsa};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;

use crate::bhd::read::{read_header, read_toc};

mod read;

pub type BhdKey = Rsa<Public>;
pub struct Bhd {
    pub toc: Vec<BhdTocEntry>,
}

#[derive(Debug)]
pub struct BhdTocEntry {
    pub hash: u64,
    pub padded_size: u32,
    pub size: u32,
    pub offset: u64,
    pub aes_key: [u8; 16],
    pub encrypted_ranges: Vec<(i64, i64)>,
}
#[derive(Debug)]
pub struct BhdHeader {
    pub is_big_endian: bool,
    pub file_size: u32,
    pub buckets: u32,
    pub buckets_offset: u32,
    pub salt_length: u32,
    pub salt: Vec<u8>,
}

impl Bhd {
    pub fn read<R: Read + Seek>(mut file: R, key: BhdKey) -> Result<Self, std::io::Error> {
        let key_size = key.size() as usize;

        let file_len = file.seek(SeekFrom::End(0))? as usize;
        let decrypted_file_len = file_len - file_len / key_size;
        file.seek(SeekFrom::Start(0))?;

        let mut decrypted_data = vec![MaybeUninit::uninit(); decrypted_file_len];
        let mut encrypted_data = Vec::with_capacity(file_len);
        file.read_to_end(&mut encrypted_data)?;

        let decrypted_len = encrypted_data
            .par_chunks(key_size)
            .zip(decrypted_data.par_chunks_mut(key_size - 1))
            .map(|(encrypted_block, decrypted_block)| {
                let mut decrypted_with_padding = vec![MaybeUninit::<u8>::uninit(); key_size];

                let len = key
                    .public_decrypt(
                        encrypted_block,
                        unsafe { transmute(&mut decrypted_with_padding[..]) },
                        Padding::NONE,
                    )
                    .map_err(std::io::Error::other)?;

                decrypted_block.copy_from_slice(&decrypted_with_padding[1..len]);

                Ok::<_, std::io::Error>(len)
            })
            .try_reduce(|| 0, |len, block_len| Ok(len + block_len))?;

        // SAFETY: all elements from [0,decrypted_len) have been initialized.
        let decrypted_data: Vec<u8> = unsafe {
            decrypted_data.set_len(decrypted_len);
            transmute(decrypted_data)
        };

        let mut reader = Cursor::new(&decrypted_data[..]);
        let header = read_header(&mut reader)?;

        let toc = if header.is_big_endian {
            read_toc::<_, BigEndian>(header.buckets as usize, reader)
        } else {
            read_toc::<_, LittleEndian>(header.buckets as usize, reader)
        }?;

        Ok(Bhd { toc })
    }
}
