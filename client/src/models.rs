use base64::prelude::*;
use serde::Deserialize;

use crate::crypto;

/// These models replicate the ones in the Server

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

#[derive(Deserialize, Clone, Debug)]
pub struct File {
    pub id: String,
    pub name: String,
    pub mtime: Option<i64>,
    pub sz: Option<i32>,
    pub data: Option<Vec<u8>>,
    pub keyring_id: Option<i32>,
}

impl File {
    pub fn decrypt(&mut self, key: &[u8]) {
        let raw_name = BASE64_STANDARD.decode(&self.name).unwrap();
        self.name = String::from_utf8(crypto::chacha_decrypt(&raw_name, key).unwrap()).unwrap();

        if self.data.is_some() {
            self.data = crypto::chacha_decrypt(self.data.as_ref().unwrap(), key).ok();
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct FileWithoutDataWithKeyring {
    pub id: String,
    pub name: String,
    pub keyring: Option<KeyringWithKeysAndFiles>,
}

impl FileWithoutDataWithKeyring {
    pub fn is_folder(&self) -> bool {
        self.keyring.is_some()
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct KeyWithFile {
    pub file: FileWithoutDataWithKeyring,
    pub key: Vec<u8>,
    pub keyring_id: i32,
}

#[derive(Deserialize, Clone, Debug)]
pub struct KeyringWithKeysAndFiles {
    pub id: i32,
    pub keys: Vec<KeyWithFile>,
}

impl KeyringWithKeysAndFiles {
    /// Load from encrypted Keyring, return an unencrypted Keyring
    /// With a huge file tree, this can take quite a while
    pub fn from_encrypted(encrypted_keyring: Self, key: &[u8], root: bool) -> Self {
        let mut decrypted_keyring = KeyringWithKeysAndFiles {
            id: encrypted_keyring.id,
            keys: Vec::new(),
        };

        for mut key_entry in encrypted_keyring.keys {
            let dec_key;

            // If root, need to decrypt with RSA
            // Else with ChaCha20
            if root {
                dec_key = crypto::rsa_decrypt(&key_entry.key, key).unwrap();
            } else {
                dec_key = crypto::chacha_decrypt(&key_entry.key, key).unwrap();
            }

            // Decrypt file name
            let filename_raw = BASE64_STANDARD.decode(key_entry.file.name).unwrap();
            key_entry.file.name =
                String::from_utf8(crypto::chacha_decrypt(&filename_raw, &dec_key).unwrap())
                    .unwrap();

            let mut decrypted_key = KeyWithFile {
                file: key_entry.file.clone(),
                key: dec_key.clone(),
                keyring_id: key_entry.keyring_id,
            };

            // If folder, need to decrypt in depth
            if key_entry.file.is_folder() {
                let decrypted_folder_keyring = KeyringWithKeysAndFiles::from_encrypted(
                    key_entry.file.keyring.unwrap(),
                    &dec_key,
                    false,
                );
                decrypted_key.file.keyring = Some(decrypted_folder_keyring);
            }

            decrypted_keyring.keys.push(decrypted_key);
        }

        decrypted_keyring
    }

    /// Find a file with the given UUID
    pub fn get_file(&self, folder_uuid: &str) -> Option<KeyWithFile> {
        for key in &self.keys {
            if key.file.id == folder_uuid.to_string() {
                return Some(key.clone());
            }

            if let Some(folder_keyring) = &key.file.keyring {
                if let Some(file) = folder_keyring.get_file(folder_uuid) {
                    return Some(file);
                }
            }
        }

        None
    }

    /// Find a file with the given name in this keyring level (no depth)
    pub fn get_file_by_name(&self, folder_name: &str) -> Option<KeyWithFile> {
        for key in self.keys.iter() {
            if key.file.name == folder_name {
                return Some(key.clone());
            }
        }

        None
    }
}
