use std::path::PathBuf;
use serde::{ Serialize, Deserialize };
use zerocopy::{ FromBytes, Immutable, KnownLayout };

pub const SIGN: &[u8; 8] = b"sf\0trace";

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    #[serde(with = "serde_bytes")]
    pub shlibid: Vec<u8>,
    pub pid: u32,
    pub shlib_base: u64,
    pub shlib_path: PathBuf,
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
    pub const TAIL_CALL: Kind = Kind(3);

    // malloc/free and more ...
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FilterMap {
    build_id_hash: u64,
    map: [u64]
}

#[allow(dead_code)]
impl FilterMap {
    pub fn build_id_hash(build_id: &[u8]) -> u64 {
        use siphasher::sip::SipHasher24;

        SipHasher24::new().hash(build_id)
    }
    
    pub fn parse<'map>(buf: &'map [u8], build_id: Option<&[u8]>) -> anyhow::Result<&'map FilterMap> {
        use anyhow::Context;
        
        let map = <FilterMap>::ref_from_bytes(buf)
            .ok()
            .context("filter map parse failed")?;

        if let Some(build_id) = build_id {
            let hash = Self::build_id_hash(build_id);

            if hash != map.build_id_hash {
                anyhow::bail!(
                    "filtermap build id hash does not match: {:?} vs {:?}",
                    hash, map.build_id_hash
                );
            }
        }

        Ok(map)
    }
    
    pub fn check(&self, addr: u64) -> bool {
        self.map.binary_search(&addr).is_ok()
    }
}
