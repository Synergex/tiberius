//! Internal macro that synthesises the shape shared by server-side handle
//! types (`PreparedHandle`, `CursorHandle`).
//!
//! Both types are semantically distinct newtypes but encode identical data
//! — an `i32` that decomposes into a 16-bit connection id (upper half) and
//! a 16-bit sequence number (lower half). The macro exists purely to keep
//! the impls in sync.

macro_rules! impl_server_handle {
    ($(#[$attr:meta])* $vis:vis $name:ident) => {
        $(#[$attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis struct $name(i32);

        impl $name {
            /// Construct from a connection id (upper 16 bits) and sequence
            /// number (lower 16 bits).
            pub fn new(conn_id: u16, sequence: u16) -> Self {
                Self(((conn_id as i32) << 16) | (sequence as i32))
            }

            /// Raw `i32` value carried on the wire.
            #[inline]
            pub fn as_i32(&self) -> i32 {
                self.0
            }

            /// Reconstruct from the raw `i32` carried on the wire.
            #[inline]
            pub fn from_i32(value: i32) -> Self {
                Self(value)
            }

            /// Connection id (upper 16 bits).
            #[inline]
            pub fn conn_id(&self) -> u16 {
                ((self.0 >> 16) & 0xFFFF) as u16
            }

            /// Sequence number within this connection (lower 16 bits).
            #[inline]
            pub fn sequence(&self) -> u16 {
                (self.0 & 0xFFFF) as u16
            }
        }

        impl From<i32> for $name {
            fn from(value: i32) -> Self {
                Self::from_i32(value)
            }
        }

        impl From<$name> for i32 {
            fn from(handle: $name) -> Self {
                handle.as_i32()
            }
        }
    };
}

pub(crate) use impl_server_handle;
