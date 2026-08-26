use super::{Decode, Encode, PacketHeader, PacketStatus, HEADER_BYTES};
use crate::Error;
use bytes::BytesMut;

#[derive(Debug)]
pub struct Packet {
    pub(crate) header: PacketHeader,
    pub(crate) payload: BytesMut,
}

impl Packet {
    pub(crate) fn new(header: PacketHeader, payload: BytesMut) -> Self {
        Self { header, payload }
    }

    pub(crate) fn is_last(&self) -> bool {
        self.header.status() == PacketStatus::EndOfMessage
    }

    pub(crate) fn into_parts(self) -> (PacketHeader, BytesMut) {
        (self.header, self.payload)
    }
}

impl Encode<BytesMut> for Packet {
    fn encode(mut self, dst: &mut BytesMut) -> crate::Result<()> {
        let size = self.payload.len() + HEADER_BYTES;

        if size > u16::MAX as usize {
            return Err(Error::Protocol(
                format!("packet of {} bytes exceeds the maximum packet length", size).into(),
            ));
        }

        // The length is known before the header is written, so store it in the
        // header rather than back-patching `dst` afterwards. Back-patching only
        // works when the packet starts at offset zero, which is not the case
        // when `dst` already holds previously encoded packets.
        self.header.set_length(size as u16);
        self.header.encode(dst)?;
        dst.extend(self.payload);

        Ok(())
    }
}

impl Decode<BytesMut> for Packet {
    fn decode(src: &mut BytesMut) -> crate::Result<Self> {
        Ok(Self {
            header: PacketHeader::decode(src)?,
            payload: src.split(),
        })
    }
}

impl Extend<u8> for Packet {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.payload.extend(iter)
    }
}

impl<'a> Extend<&'a u8> for Packet {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.payload.extend(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::PacketType;

    fn packet(payload: &[u8]) -> Packet {
        let mut header = PacketHeader::new(0, 1);
        header.set_type(PacketType::TabularResult);
        header.set_status(PacketStatus::EndOfMessage);

        Packet::new(header, BytesMut::from(payload))
    }

    #[test]
    fn encodes_length_into_the_header() {
        let mut buf = BytesMut::new();
        packet(&[1, 2, 3, 4]).encode(&mut buf).unwrap();

        assert_eq!(&buf[2..4], &(HEADER_BYTES as u16 + 4).to_be_bytes());
    }

    #[test]
    fn appends_to_a_non_empty_buffer_without_corrupting_it() {
        let mut buf = BytesMut::new();
        packet(&[1, 2, 3, 4]).encode(&mut buf).unwrap();
        let first = buf.clone();

        packet(&[5, 6]).encode(&mut buf).unwrap();

        // The first packet is untouched and the second carries its own length.
        assert_eq!(&buf[..first.len()], &first[..]);
        assert_eq!(
            &buf[first.len() + 2..first.len() + 4],
            &(HEADER_BYTES as u16 + 2).to_be_bytes()
        );
        assert_eq!(buf.len(), 2 * HEADER_BYTES + 6);
    }

    #[test]
    fn rejects_a_payload_larger_than_the_length_field() {
        let mut buf = BytesMut::new();
        let oversized = packet(&vec![0u8; u16::MAX as usize]);

        assert!(oversized.encode(&mut buf).is_err());
    }
}
