// @generated automatically by Diesel CLI.

diesel::table! {
    files (name) {
        name -> Nullable<Binary>,
        mtime -> Nullable<Integer>,
        sz -> Nullable<Integer>,
        data -> Nullable<Binary>,
        keyring -> Nullable<Integer>,
    }
}

diesel::table! {
    keyrings (id) {
        id -> Nullable<Integer>,
    }
}

diesel::table! {
    keys (target) {
        target -> Binary,
        key -> Binary,
        keyring -> Integer,
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

diesel::joinable!(keys -> keyrings (keyring));
diesel::joinable!(sessions -> users (user));

diesel::allow_tables_to_appear_in_same_query!(
    files,
    keyrings,
    keys,
    sessions,
    users,
);
