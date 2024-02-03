use crate::bhd::{BhdHeader, BhdTocEntry};
use crate::read::ReadFormatsExt;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

pub fn read_header_data<R: Read, O: ByteOrder>(
    mut reader: R,
    is_big_endian: bool,
) -> Result<BhdHeader, std::io::Error> {
    let mut unk = [0u8; 7];
    reader.read_exact(&mut unk[..])?;

    let file_size = reader.read_u32::<O>()?;
    let toc_buckets = reader.read_i32::<O>()?;
    let toc_offset = reader.read_i32::<O>()?;
    let salt_length = reader.read_u32::<O>()?;

    let mut salt = vec![0u8; salt_length as usize];
    reader.read_exact(&mut salt)?;

    Ok(BhdHeader {
        is_big_endian,
        file_size,
        buckets: toc_buckets as u32,
        buckets_offset: toc_offset as u32,
        salt_length,
        salt,
    })
}

pub fn read_header<R: Read>(mut reader: R) -> Result<BhdHeader, std::io::Error> {
    reader.read_magic(b"BHD5")?;

    let endianness = reader.read_i8()?;
    if endianness == -1 {
        read_header_data::<_, LittleEndian>(reader, false)
    } else {
        read_header_data::<_, BigEndian>(reader, true)
    }
}

pub fn read_toc<R: Read + Seek, O: ByteOrder>(
    buckets: usize,
    mut reader: R,
) -> Result<Vec<BhdTocEntry>, std::io::Error> {
    let mut entries = Vec::new();

    // TODO: split some of this out
    for _ in 0..buckets {
        let entry_count = reader.read_u32::<O>()?;
        let entry_data_offset = reader.read_u32::<O>()?;

        let next_bucket_pos = reader.stream_position()?;
        reader.seek(SeekFrom::Start(entry_data_offset as u64))?;

        for _ in 0..entry_count {
            let hash = reader.read_u64::<O>()?;
            let padded_size = reader.read_u32::<O>()?;
            let size = reader.read_u32::<O>()?;
            let offset = reader.read_u64::<O>()?;

            let _digest_offset = reader.read_u64::<O>()?;
            let encryption_offset = reader.read_u64::<O>()?;

            let next_file_pos = reader.stream_position()?;
            let mut aes_key = [0u8; 16];

            let mut encrypted_ranges = Vec::new();

            if encryption_offset != 0 {
                reader.seek(SeekFrom::Start(encryption_offset))?;

                reader.read_exact(&mut aes_key)?;

                let encrypted_range_count = reader.read_u32::<O>()?;

                for _ in 0..encrypted_range_count {
                    encrypted_ranges.push((reader.read_i64::<O>()?, reader.read_i64::<O>()?));
                }
            }

            reader.seek(SeekFrom::Start(next_file_pos))?;

            entries.push(BhdTocEntry {
                hash,
                padded_size,
                size,
                offset,
                aes_key,
                encrypted_ranges,
            })
        }

        reader.seek(SeekFrom::Start(next_bucket_pos))?;
    }

    Ok(entries)
}
