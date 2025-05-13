use std::path::{ Path, PathBuf };
use serde::Deserialize;


#[derive(Deserialize, Default)]
pub struct Config {
    pub object: Option<Object>,
    
}

#[derive(Deserialize, Default)]
pub struct Object {
    pub path: Option<PathBuf>,
    pub rlibs: Option<String>,
    pub allocator: Option<Allocator>,
}

#[derive(Deserialize)]
pub struct Allocator {
    pub alloc: String,
    pub dealloc: String,
    pub alloc_zeroed: String,
    pub realloc: String,
}

impl Config {
    pub fn path(&self) -> Option<&Path> {
        let obj = self.object.as_ref()?;
        obj.path.as_deref()
    }

    pub fn rlibs(&self) -> Option<&str> {
        let obj = self.object.as_ref()?;
        obj.rlibs.as_deref()
    }

    pub fn allocator(&self) -> Option<&Allocator> {
        let obj = self.object.as_ref()?;
        obj.allocator.as_ref()        
    }
}


impl Allocator {
    pub fn contains(&self, name: &[u8]) -> bool {
        [
            self.alloc.as_bytes(),
            self.dealloc.as_bytes(),
            self.alloc_zeroed.as_bytes(),
            self.realloc.as_bytes()
        ].contains(&name)
    }
}
