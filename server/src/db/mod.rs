use diesel::prelude::*;
use serde::{Deserialize, Serialize};

pub mod schema;

#[derive(Identifiable, Queryable, Selectable, Insertable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::users, primary_key(username))]
pub struct User {
    pub username: String,
    pub password: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub priv_key: Vec<u8>,
    pub keyring: i32,
}

#[derive(Queryable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::users)]
pub struct UserWithKeyring {
    pub username: String,
    pub password: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub priv_key: Vec<u8>,
    pub keyring: Keyring,
}

#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Serialize, Deserialize, Debug)]
#[diesel(table_name = self::schema::sessions)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub expiration_date: i64,
}

#[derive(Insertable, Queryable, Selectable, Serialize, Deserialize, Associations, Clone, PartialEq, Debug)]
#[diesel(belongs_to(Keyring, foreign_key = keyring_id))]
#[diesel(table_name = self::schema::keys)]
pub struct Key {
    pub id: i32,
    pub target: String,
    pub key: Vec<u8>,
    pub keyring_id: i32,
}

#[derive(Insertable, Queryable, Selectable, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::keys)]
pub struct NewKey {
    pub target: String,
    pub key: Vec<u8>,
    pub keyring_id: i32
}   

#[derive(Identifiable, Queryable, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::keyrings)]
pub struct Keyring {
    pub id: i32,
}

#[derive(Queryable, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[diesel(belongs_to(Key))]
#[diesel(table_name = self::schema::keyrings)]
pub struct KeyringWithKeys {
    pub id: i32,
    pub keys: Vec<Key>,
}

#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::keyrings)]
pub struct NewKeyring {
    pub id: Option<i32>
}

#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::files)]
pub struct NewFile {
    pub id: String,
    pub name: String,
    pub mtime: i64,
    pub sz: i32,
    pub data: Vec<u8>,
    pub keyring_id: Option<i32>,
}

#[derive(Serialize, Insertable, Queryable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::files)]
pub struct File {
    pub id: String,
    pub name: String,
    pub mtime: Option<i64>,
    pub sz: Option<i32>,
    pub data: Option<Vec<u8>>,
    pub keyring_id: Option<i32>,
}

#[derive(Queryable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::files)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub keyring: Keyring,
}

#[derive(Serialize, Queryable, Clone, Debug)]
#[diesel(table_name = self::schema::files)]
pub struct FileWithoutData {
    pub id: String,
    pub name: String,
    pub keyring_id: Option<i32>,
}

#[derive(Serialize, Clone, Debug)]
pub struct FileWithoutDataWithKeyring {
    pub id: String,
    pub name: String,
    pub keyring: Option<KeyringWithKeysAndFiles>,
}

#[derive(Serialize, Clone, Debug)]
pub struct KeyWithFile {
    pub file: FileWithoutDataWithKeyring,
    pub key: Vec<u8>,
    pub keyring_id: i32,
}

#[derive(Serialize, Clone, Debug)]
pub struct KeyringWithKeysAndFiles {
    pub id: i32,
    pub keys: Vec<KeyWithFile>
}