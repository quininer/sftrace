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
    #[serde(default)]
    pub record_args: Vec<String>,
}

impl Config {
    pub fn make(&mut self) {
        if let Some(obj) = self.object.as_mut() {
            obj.record_args.sort();
        }
    }
    
    pub fn path(&self) -> Option<&Path> {
        let obj = self.object.as_ref()?;
        obj.path.as_deref()
    }

    pub fn rlibs(&self) -> Option<&str> {
        let obj = self.object.as_ref()?;
        obj.rlibs.as_deref()
    }

    pub fn record_args(&self) -> &[String] {
        self.object.as_ref()
            .map(|obj| obj.record_args.as_slice())
            .unwrap_or_default()
    }
}
