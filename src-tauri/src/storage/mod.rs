pub mod identity_store;
pub mod key_store;

pub trait KeyStore {
    fn save(&self, key: &str, value: &[u8]) -> Result<(), String>;

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String>;

    fn delete(&self, key: &str) -> Result<(), String>;
}
