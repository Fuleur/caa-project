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

#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Serialize, Deserialize, Debug)]
#[diesel(table_name = self::schema::sessions)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub expiration_date: i64,
}

#[derive(Queryable, Selectable, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::keyrings)]
pub struct Keyring {
    pub id: i32,
}


#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::keyrings)]
pub struct NewKeyring {
    pub id: Option<i32>
}