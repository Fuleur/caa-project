use diesel::prelude::*;
use serde::{Serialize, Deserialize};

pub mod schema;

#[derive(Queryable, Selectable, Insertable, Clone, PartialEq, Debug)]
#[diesel(table_name = self::schema::users)]
pub struct User {
    pub username: String,
    pub password: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub priv_key: Vec<u8>
}

#[derive(Insertable, Queryable, Selectable, Clone, PartialEq, Serialize, Deserialize, Debug)]
#[diesel(table_name = self::schema::sessions)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub expiration_date: i64,
}
