use std::path::PathBuf;
use zerocopy::{ IntoBytes, FromBytes, Immutable, KnownLayout };
use serde::{ Serialize, Deserialize };

pub const SIGN_TRACE: &[u8; 8] = b"sf\0trace";
pub const SIGN_FILTE: &[u8; 8] = b"sf\0filte";

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
pub struct Event<ARGS, RV, ALLOC> {
    #[serde(rename = "k")]
    pub kind: Kind,
    #[serde(rename = "T")]
    pub time: u64,
    #[serde(rename = "t")]
    pub tid: i32,
    #[serde(rename = "c")]
    #[serde(skip_serializing_if = "u64_is_zero")]
    #[serde(default)]
    pub child_ip: u64,
    #[serde(rename = "a")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<ARGS>,
    #[serde(rename = "r")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<RV>,
    #[serde(rename = "A")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_event: Option<ALLOC>
}

#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct AllocEvent {
    #[serde(rename = "os")]
    pub old_size: u64,
    #[serde(rename = "ns")]
    pub new_size: u64,
    #[serde(rename = "a")]
    pub align: u64,
    #[serde(rename = "op")]
    pub old_ptr: u64,
    #[serde(rename = "np")]
    pub new_ptr: u64    
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(transparent)] 
pub struct Kind(u8);

impl Kind {
    pub const ENTRY: Kind = Kind(1);
    pub const EXIT: Kind = Kind(2);
    pub const TAIL_CALL: Kind = Kind(3);
    pub const ALLOC: Kind = Kind(4);
    pub const DEALLOC: Kind = Kind(5);
    pub const REALLOC: Kind = Kind(6);
}

fn u64_is_zero(n: &u64) -> bool {
    *n == 0
}

pub fn build_id_hash(build_id: &[u8]) -> u64 {
    use siphasher::sip::SipHasher24;

    SipHasher24::new().hash(build_id)
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FilterMap {
    sign: u64,
    build_id_hash: u64,
    mode: FilterMode,
    map: [FilterMark],
}

#[derive(IntoBytes, FromBytes, Immutable, KnownLayout)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct FilterMode(u64);

impl FilterMode {
    pub const MARK: FilterMode = FilterMode(0);
    pub const FILTER: FilterMode = FilterMode(1);
}

#[derive(IntoBytes, FromBytes, Immutable, KnownLayout)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct FilterMark(u64);

#[allow(dead_code)]
impl FilterMap {
    pub fn parse<'map>(buf: &'map [u8], build_id: Option<&[u8]>) -> anyhow::Result<&'map FilterMap> {
        use anyhow::Context;
        
        let map = <FilterMap>::ref_from_bytes(buf)
            .ok()
            .context("filter map parse failed")?;

        if &map.sign.to_le_bytes() != SIGN_FILTE {
            anyhow::bail!("bad filter sign: {:?}", map.sign);
        }

        if let Some(build_id) = build_id {
            let hash = build_id_hash(build_id);

            if hash != map.build_id_hash {
                anyhow::bail!(
                    "filtermap build id hash does not match: {:?} vs {:?}",
                    hash, map.build_id_hash
                );
            }
        }

        Ok(map)
    }

    pub fn mode(&self) -> FilterMode {
        self.mode
    }
    
    pub fn check(&self, addr: u64) -> Option<FilterMark> {
        self.map
            .binary_search_by_key(&addr, |mark| mark.addr())
            .ok()
            .map(|idx| self.map[idx])
    }
}

#[allow(dead_code)]
impl FilterMark {
    pub fn new(addr: u64, enable_log: bool) -> Option<FilterMark> {
        if addr <= 1 << 54 {
            let flag = (enable_log as u64) << 54;
            Some(FilterMark(addr | flag))
        } else {
            None
        }
    }

    pub fn addr(self) -> u64 {
        self.0 & ((1 << 54) - 1)
    }

    pub fn log(self) -> bool {
        ((self.0 >> 54) & 1) != 0
    }
}
