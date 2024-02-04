use std::io::Error;
use std::{
    io::Seek,
    io::{SeekFrom, Write},
    marker::PhantomData,
    mem::replace,
    num::TryFromIntError,
};

use byteorder::{ByteOrder, WriteBytesExt};

pub enum Reservation {
    Pending(u64),
    Complete,
}

pub struct Reserved<T: ReservedValue, E: ByteOrder> {
    inner: Reservation,
    _value_ty: PhantomData<T>,
    _byte_order_ty: PhantomData<E>,
}

pub trait ReservedValue: Sized + Copy {
    fn write_to<W: Write, O: ByteOrder>(self, output: W) -> std::io::Result<()>;
}

impl ReservedValue for u32 {
    fn write_to<W: Write, O: ByteOrder>(self, mut output: W) -> std::io::Result<()> {
        output.write_u32::<O>(self)
    }
}

impl<T: ReservedValue, E: ByteOrder> Reserved<T, E> {
    pub fn resolve<W: Write + Seek>(
        &mut self,
        mut writer: W,
        value: T,
    ) -> Result<T, std::io::Error> {
        let saved_pos = match replace(&mut self.inner, Reservation::Complete) {
            Reservation::Pending(pos) => pos,
            Reservation::Complete => return Err(Error::other("reservation already completed")),
        };

        let pos = writer.stream_position()?;
        writer.seek(SeekFrom::Start(saved_pos))?;
        value.write_to::<_, E>(&mut writer)?;
        writer.seek(SeekFrom::Start(pos))?;

        Ok(value)
    }
}

impl<T, E> Reserved<T, E>
where
    T: ReservedValue + TryFrom<u64, Error = TryFromIntError>,
    E: ByteOrder,
{
    pub fn resolve_with_position<W: Write + Seek>(
        &mut self,
        mut writer: W,
    ) -> Result<T, std::io::Error> {
        let value = T::try_from(writer.stream_position()?).unwrap();

        self.resolve(writer, value)
    }

    pub fn resolve_with_relative_offset<W: Write + Seek>(
        &mut self,
        mut writer: W,
        pos: u64,
    ) -> Result<T, std::io::Error> {
        let offset = writer.stream_position()? - pos;
        let value = T::try_from(offset).unwrap();

        self.resolve(writer, value)
    }
}

impl<T, E> Drop for Reserved<T, E>
where
    T: ReservedValue,
    E: ByteOrder,
{
    fn drop(&mut self) {
        if let Reservation::Pending(pos) = self.inner {
            panic!(
                "unresolved {} at 0x{:x} dropped before resolving",
                std::any::type_name::<T>(),
                pos
            );
        }
    }
}

pub trait WriteFormatsExt {
    fn reserve<T: ReservedValue, E: ByteOrder>(&mut self)
        -> Result<Reserved<T, E>, std::io::Error>;
    fn reserve_u32<E: ByteOrder>(&mut self) -> Result<Reserved<u32, E>, std::io::Error>;
}

impl<W: Write + Seek> WriteFormatsExt for W {
    fn reserve<T: ReservedValue, E: ByteOrder>(
        &mut self,
    ) -> Result<Reserved<T, E>, std::io::Error> {
        let offset = self.stream_position()?;
        let unresolved_value_size = std::mem::size_of::<T>();

        self.seek(SeekFrom::Current(unresolved_value_size as i64))?;

        Ok(Reserved {
            _value_ty: PhantomData,
            _byte_order_ty: PhantomData,
            inner: Reservation::Pending(offset),
        })
    }

    fn reserve_u32<E: ByteOrder>(&mut self) -> Result<Reserved<u32, E>, std::io::Error> {
        self.reserve::<u32, E>()
    }
}
