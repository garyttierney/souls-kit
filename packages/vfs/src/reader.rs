use std::cmp::min;
use std::io::{Cursor, Error, Read, Seek, SeekFrom, Write};
use std::ops::Range;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Block};

use crate::VfsFileEntry;

// TODO: handle case where padded_file_size != file_size and we emit padding bytes to the output
pub struct VfsEntryReader<'a> {
    cipher: Aes128,
    data: Cursor<&'a [u8]>,
    encrypted_file_size: usize,
    encrypted_block: Block,
    encrypted_block_offset: usize,
    encrypted_data_ranges: &'a [Range<u64>],
    encrypted_data_range_index: usize,
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
            encrypted_block: Block::default(),
            encrypted_block_offset: 0,
            encrypted_data_range_index: 0,
            encrypted_data_ranges: &entry.aes_ranges,
            encrypted_file_size: entry.file_size_with_padding as usize,
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.data.read(buf)
    }

    fn read_ciphertext(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut writer = Cursor::new(buf);

        if self.encrypted_block_offset > 0 {
            writer.write_all(&self.encrypted_block[self.encrypted_block_offset..])?;
        }

        let mut bytes_written = 0;

        loop {
            self.data.read_exact(&mut self.encrypted_block)?;

            self.cipher.decrypt_block(&mut self.encrypted_block);
            self.encrypted_block_offset = writer.write(&self.encrypted_block)?;

            bytes_written += self.encrypted_block_offset;

            // Couldn't write the complete block, continue on the next read.
            if self.encrypted_block_offset < self.encrypted_block.len() {
                break;
            }
        }

        Ok(bytes_written)
    }
}

impl<'a> Read for VfsEntryReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let requested = buf.len();
        let remaining = self.encrypted_file_size - self.data.position() as usize;
        let readable = min(requested, remaining);

        let mut read = 0;

        while read < readable {
            let pos = self.data.position() as usize;
            let range = self
                .encrypted_data_ranges
                .get(self.encrypted_data_range_index);

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
                self.encrypted_data_range_index += 1;
            } else if part_read < part_size {
                // Buffer not large enough, resume on next read.
                break;
            }
        }

        Ok(read)
    }
}

impl<'a> Seek for VfsEntryReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let pos = self.data.seek(pos)?;

        let encrypted_range = self
            .encrypted_data_ranges
            .iter()
            .enumerate()
            .find(|(_, block)| block.contains(&pos));

        if let Some((index, range)) = encrypted_range {
            // How far are we into this range after the seek?
            let range_offset = pos - range.start;
            let block_offset = range_offset % self.encrypted_block.len() as u64;

            self.data.seek(SeekFrom::Current(-(block_offset as i64)))?;
            self.data.read_exact(&mut self.encrypted_block)?;
            self.cipher.decrypt_block(&mut self.encrypted_block);

            self.encrypted_data_range_index = index;
            self.encrypted_block_offset = block_offset as usize;
        }

        Ok(pos)
    }
}

#[cfg(test)]
mod test {

    fn create_test_data() {}

    #[test]
    fn decodes() {}
}
