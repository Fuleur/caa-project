use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Debug)]
pub struct Key {
    pub target: String,
    pub key: Vec<u8>,
    pub keyring_id: i32,
}

#[derive(Deserialize, Clone, Debug)]
pub struct KeyringWithKeys {
    pub id: i32,
    pub keys: Vec<Key>,
}