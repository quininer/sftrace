use serde::{ Serialize, Deserialize };


pub const SIGN: &[u8; 8] = b"sf\0trace";

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    #[serde(with = "serde_bytes")]
    pub shlibid: Vec<u8>,
    pub pid: u32,
    pub shlib_base: u64,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct Event {
    #[serde(rename = "k")]
    pub kind: Kind,
    #[serde(rename = "T")]
    pub time: u64,
    #[serde(rename = "t")]
    pub tid: i32,
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub parent_ip: u64,
    #[serde(rename = "c")]
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub child_ip: u64,
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(transparent)] 
pub struct Kind(u8);

impl Kind {
    pub const ENTRY: Kind = Kind(1);
    pub const EXIT: Kind = Kind(2);

    // malloc/free and more ...
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}
