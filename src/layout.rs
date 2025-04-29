use zerocopy::{ IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned, U64, I32, LE };


#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogFile {
    pub metadata: Metadata,
    pub events: [Event]
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Metadata {
    pub sign: [u8; 8],
    pub base: U64<LE>,
}

pub const SIGN: &[u8; 8] = b"sf\0trace";

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Event {
    pub parent_ip: U64<LE>,
    pub child_ip: U64<LE>,
    pub time: U64<LE>,
    pub tid: I32<LE>,
    pub kind: Kind,
}

#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Unaligned)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Kind(u8);

impl Kind {
    pub const ENTRY: Kind = Kind(1);
    pub const EXIT: Kind = Kind(2);

    // malloc/free and more ...
}

