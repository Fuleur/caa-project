// @generated automatically by Diesel CLI.

diesel::table! {
    sqlar (name) {
        name -> Nullable<Text>,
        mode -> Nullable<Integer>,
        mtime -> Nullable<Integer>,
        sz -> Nullable<Integer>,
        data -> Nullable<Binary>,
    }
}

diesel::table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    sqlar,
    users,
);
