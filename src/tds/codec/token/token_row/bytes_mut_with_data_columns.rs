use crate::MetaDataColumn;
use bytes::buf::UninitSlice;
use bytes::{BufMut, BytesMut};
use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

pub(crate) struct BytesMutWithDataColumns<'a, 'c> {
    bytes: &'a mut BytesMut,
    data_columns: &'c [MetaDataColumn<'c>],
}

impl<'a, 'c> BytesMutWithDataColumns<'a, 'c> {
    pub fn new(bytes: &'a mut BytesMut, data_columns: &'c [MetaDataColumn<'c>]) -> Self {
        BytesMutWithDataColumns { bytes, data_columns }
    }

    pub fn data_columns(&self) -> &'c [MetaDataColumn<'c>] {
        self.data_columns
    }
}

unsafe impl<'a, 'c> BufMut for BytesMutWithDataColumns<'a, 'c> {
    fn remaining_mut(&self) -> usize {
        self.bytes.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.bytes.advance_mut(cnt)
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.bytes.chunk_mut()
    }
}

impl<'a, 'c> Borrow<[u8]> for BytesMutWithDataColumns<'a, 'c> {
    fn borrow(&self) -> &[u8] {
        self.bytes.deref()
    }
}

impl<'a, 'c> BorrowMut<[u8]> for BytesMutWithDataColumns<'a, 'c> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.bytes.borrow_mut()
    }
}

impl<'a, 'c> Deref for BytesMutWithDataColumns<'a, 'c> {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.bytes
    }
}

impl<'a, 'c> DerefMut for BytesMutWithDataColumns<'a, 'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bytes
    }
}
