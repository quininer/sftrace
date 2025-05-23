use std::path::PathBuf;
use zerocopy::{ IntoBytes, FromBytes, Immutable, KnownLayout };
use zerocopy::byteorder::{ NativeEndian, U64 };
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
    #[serde(rename = "t")]
    pub tid: u32,
    #[serde(rename = "f")]
    #[serde(skip_serializing_if = "u32_is_zero")]
    #[serde(default)]
    pub func_id: u32,
    #[serde(rename = "T")]
    pub time: u64,
    #[serde(rename = "k")]
    pub kind: Kind,
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
    #[serde(rename = "s")]
    pub size: u64,
    #[serde(rename = "a")]
    pub align: u64,
    #[serde(rename = "p")]
    pub ptr: u64    
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
    pub const REALLOC_ALLOC: Kind = Kind(6);
    pub const REALLOC_DEALLOC: Kind = Kind(7);
}

fn u32_is_zero(n: &u32) -> bool {
    *n == 0
}

pub fn build_id_hash(build_id: &[u8]) -> u64 {
    use siphasher::sip::SipHasher24;

    SipHasher24::new().hash(build_id)
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/CodeGen/AsmPrinter/AsmPrinter.cpp#L4447
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct XRayFunctionEntry {
    pub address: U64<NativeEndian>,
    pub function: U64<NativeEndian>,
    pub kind: u8,
    pub always_instrument: u8,
    pub version: u8,
    padding: [u8; (4 * 8) - ((2 * 8) + 3)]
}

const _ASSERT_SIZE: () = [(); 1][std::mem::size_of::<XRayFunctionEntry>() - 32];

pub struct XRayInstrMap<'a>(pub &'a [XRayFunctionEntry]);

pub struct XRayEntry<'a> {
    idx: u32,
    section_offset: u64,
    entry: &'a XRayFunctionEntry
}

impl XRayInstrMap<'_> {
    #[allow(dead_code)]
    pub fn get(&self, section_offset: u64, idx: u32) -> XRayEntry<'_> {
        let idx2: usize = idx.try_into().unwrap();
        XRayEntry {
            idx, section_offset,
            entry: &self.0[idx2]
        }
    }

    pub fn iter(&self, section_offset: u64) -> impl Iterator<Item = XRayEntry<'_>> + '_ {
        self.0.iter()
            .enumerate()
            .filter(|(_, entry)| entry.version == 2)
            .map(move |(idx, entry)| XRayEntry {
                idx: idx.try_into().unwrap(),
                section_offset, entry
            })
        
    }
}

impl XRayEntry<'_> {
    const ENTRY_SIZE: u64 = std::mem::size_of::<XRayFunctionEntry>() as u64;
    
    pub fn id(&self) -> u32 {
        self.idx
    }
    
    #[allow(dead_code)]
    pub fn kind(&self) -> u8 {
        self.entry.kind
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_interface_internal.h#L59
        // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/XRay/InstrumentationMap.cpp#L199        
        let entry_offset = self.section_offset + u64::from(self.idx) * Self::ENTRY_SIZE;
        entry_offset + self.entry.address.get()
    }

    pub fn function(&self) -> u64 {
        let entry_offset = self.section_offset + u64::from(self.idx) * Self::ENTRY_SIZE;
        entry_offset + self.entry.function.get() + std::mem::size_of::<u64>() as u64
    }    
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
    #[allow(dead_code)]
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
    const CAP: usize = 64 - 8;
    
    pub fn new(addr: u64, flag: FuncFlag) -> Option<FilterMark> {
        let flag = (flag.bits() as u64) << Self::CAP;

        (addr < (1 << Self::CAP)).then(|| FilterMark(addr | flag))
    }

    pub fn addr(self) -> u64 {
        self.0 & ((1 << Self::CAP) - 1)
    }

    pub fn flag(self) -> FuncFlag {
        FuncFlag::from_bits_truncate((self.0 >> Self::CAP) as u8)        
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct FuncFlag: u8 {
        const LOG   = 0b00000001;
    }
}
