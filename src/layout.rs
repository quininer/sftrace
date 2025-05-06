use serde::{ Serialize, Deserialize };
use zerocopy::{ FromBytes, Immutable, KnownLayout };

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/CodeGen/AsmPrinter/AsmPrinter.cpp#L4447
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct XRayFunctionEntry {
    pub address: usize,
    pub function: usize,
    pub kind: u8,
    pub always_instrument: u8,
    pub version: u8,
    padding: [u8; (4 * 8) - ((2 * 8) + 3)]
}

const _ASSERT_SIZE: () = [(); 1][std::mem::size_of::<XRayFunctionEntry>() - 32];

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

pub struct XRayInstrMap<'a>(pub &'a [XRayFunctionEntry]);

impl XRayInstrMap<'_> {
    pub fn iter(&self, base: usize, section_offset: usize) -> impl Iterator<Item = (usize, usize, &'_ XRayFunctionEntry)> + '_ {
        const ENTRY_SIZE: usize = std::mem::size_of::<XRayFunctionEntry>();
        
        self.0.iter()
            .enumerate()
            .filter(|(_, entry)| entry.version == 2)
            .map(move |(i, entry)| {
                let entry_offset = section_offset + i * ENTRY_SIZE;

                // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_interface_internal.h#L59
                // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/XRay/InstrumentationMap.cpp#L199                
                let address = base + entry_offset + entry.address;
                let function = base + entry_offset + entry.address + ENTRY_SIZE;

                (address, function, entry)
            })
    }
}
