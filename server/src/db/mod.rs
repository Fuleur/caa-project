use diesel::prelude::*;

pub mod schema;

#[derive(Insertable, Queryable, Clone, Debug, PartialEq)]
#[diesel(table_name = self::schema::users)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: Vec<u8>,
}