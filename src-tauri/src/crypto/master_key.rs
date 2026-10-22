use rand::RngCore;
use zeroize::Zeroizing;

const MASTER_KEY_LENGTH: usize = 32;

pub type MasterKey = Zeroizing<[u8; MASTER_KEY_LENGTH]>;

pub fn generate_master_key() -> MasterKey {
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);

    rand::rng().fill_bytes(&mut *key);

    key
}
