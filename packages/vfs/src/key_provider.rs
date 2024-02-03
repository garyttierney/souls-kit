use souls_formats::BhdKey;
use std::collections::HashMap;

pub trait ArchiveKeyProvider {
    fn get_key(&self, name: &str) -> Option<BhdKey>;
}

impl ArchiveKeyProvider for HashMap<&str, BhdKey> {
    fn get_key(&self, name: &str) -> Option<BhdKey> {
        self.get(name).cloned()
    }
}
