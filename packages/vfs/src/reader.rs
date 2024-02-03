use std::cmp::min;
use std::io::{Cursor, Error, Read, Write};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Block};

use crate::VfsFileEntry;

// TODO: handle case where padded_file_size != file_size and we emit padding bytes to the output
pub struct VfsEntryReader<'a> {
    pub(crate) cipher: Aes128,
    pub(crate) data: Cursor<&'a [u8]>,
    pub(crate) encrypted_range_index: usize,
    pub(crate) entry: &'a VfsFileEntry,
}

pub enum VfsEntryPartKind {
    Ciphertext,
    Plaintext,
}

impl<'a> VfsEntryReader<'a> {
    pub fn new(data: &'a [u8], entry: &'a VfsFileEntry) -> Self {
        Self {
            cipher: Aes128::new(&GenericArray::from(entry.aes_key)),
            data: Cursor::new(data),
            encrypted_range_index: 0,
            entry,
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.data.read(buf)
    }

    fn read_ciphertext(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut block = Block::from([0u8; 16]);
        let blocks = buf.len() / block.len();
        let mut writer = Cursor::new(buf);

        let mut read = 0;
        for _ in 0..blocks {
            read += self.data.read(&mut block)?;
            self.cipher.decrypt_block(&mut block);
            writer.write_all(&block)?;
        }

        Ok(read)
    }
}

impl<'a> Read for VfsEntryReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let requested = buf.len();
        let remaining = self.entry.file_size_with_padding as usize - self.data.position() as usize;
        let readable = min(requested, remaining);

        let mut read = 0;

        while read < readable {
            let pos = self.data.position() as usize;
            let range = self.entry.aes_ranges.get(self.encrypted_range_index);

            let (part_type, part_size) = match range {
                Some(range) if range.contains(&(pos as u64)) => {
                    (VfsEntryPartKind::Ciphertext, range.end as usize - pos)
                }
                Some(range) => (VfsEntryPartKind::Plaintext, range.start as usize - pos - 1),
                None => (VfsEntryPartKind::Plaintext, remaining),
            };

            let out_offset = read;
            let out_capacity = min(out_offset + part_size, buf.len());
            let out = &mut buf[out_offset..out_capacity];

            let part_read = match part_type {
                VfsEntryPartKind::Ciphertext => self.read_ciphertext(out)?,
                VfsEntryPartKind::Plaintext => self.read_plaintext(out)?,
            };

            read += part_read;

            if part_read == part_size && matches!(part_type, VfsEntryPartKind::Ciphertext) {
                self.encrypted_range_index += 1;
            } else if part_read < part_size {
                // Buffer not large enough, resume on next read.
                break;
            }
        }

        Ok(read)
    }
}
