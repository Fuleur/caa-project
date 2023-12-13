// @generated automatically by Diesel CLI.

diesel::table! {
    sessions (token) {
        token -> Text,
        user -> Text,
        expiration_date -> BigInt,
    }
}

diesel::table! {
    users (username) {
        username -> Text,
        password -> Binary,
        pub_key -> Binary,
        priv_key -> Binary,
    }
}

diesel::joinable!(sessions -> users (user));

diesel::allow_tables_to_appear_in_same_query!(
    sessions,
    users,
);
