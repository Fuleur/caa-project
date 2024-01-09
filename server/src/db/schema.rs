// @generated automatically by Diesel CLI.

diesel::table! {
    files (id) {
        id -> Nullable<Text>,
        name -> Nullable<Text>,
        mtime -> Nullable<BigInt>,
        sz -> Nullable<Integer>,
        data -> Nullable<Binary>,
        keyring -> Nullable<Integer>,
    }
}

diesel::table! {
    keyrings (id) {
        id -> Integer,
    }
}

diesel::table! {
    keys (target) {
        target -> Text,
        key -> Binary,
        keyring_id -> Integer,
    }
}

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
        keyring -> Integer,
    }
}

diesel::joinable!(keys -> files (target));
diesel::joinable!(keys -> keyrings (keyring_id));
diesel::joinable!(sessions -> users (user));
diesel::joinable!(users -> keyrings (keyring));

diesel::allow_tables_to_appear_in_same_query!(
    files,
    keyrings,
    keys,
    sessions,
    users,
);
