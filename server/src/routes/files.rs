use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Extension, Json};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{
        schema::{files, keyrings, keys, users},
        File, Key, KeyringWithKeys, NewFile, NewKey, Session,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct UploadFileRequest {
    path: String,
    filename: String,
    file: Vec<u8>,
    encrypted_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct UploadFileResponse {
    keyring: KeyringWithKeys,
}

/// Allow a user to upload a file.
/// 
/// The file uploaded is encrypted and his encrypted symmetric encryption key
/// is send along with it. The file symmetric key is encrypted with the user's public key.
/// The file will be "placed" in the specified path starting from the user's root.
/// 
/// If the specified path doesn't exist, return an error
/// Else return a response with the updated user root keyring
pub async fn upload_file(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
    Json(upload_request): Json<UploadFileRequest>,
) -> Json<UploadFileResponse> {
    let conn = app_state.pool.get().await.unwrap();

    let file = NewFile {
        id: Uuid::new_v4().to_string(),
        name: upload_request.filename,
        mtime: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        sz: upload_request.file.len() as i32,
        data: upload_request.file,
        keyring: None,
    };

    conn.interact({
        let file = file.clone();
        |conn| diesel::insert_into(files::table).values(file).execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    let user_keyring_id: i32 = conn
        .interact(|conn| {
            users::table
                .find(user_session.user)
                .select(users::keyring)
                .first::<i32>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    conn.interact({
        let user_keyring_id = user_keyring_id.clone();
        let file_id = file.id.clone();
        move |conn| {
            diesel::insert_into(keys::table)
                .values(NewKey {
                    target: file_id,
                    key: upload_request.encrypted_key,
                    keyring_id: user_keyring_id,
                })
                .execute(conn)
        }
    })
    .await
    .unwrap()
    .unwrap();

    let user_keys: Vec<Key> = conn
        .interact(move |conn| {
            keys::table
                .filter(keys::keyring_id.eq(user_keyring_id))
                .load::<Key>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    let keyring_with_keys = KeyringWithKeys {
        id: user_keyring_id,
        keys: user_keys,
    };

    Json(UploadFileResponse {
        keyring: keyring_with_keys,
    })
}

/// Allow a user to download a file.
/// 
/// The file should not be sent to the user if he has no access to it.
/// The path specified is the path starting from the user's root, by following the path
/// from the user's root keyring we can check if it exist or not. Each user has his own file hierarchy.
/// 
/// Note: the path is not a path by name, but a path by uuid. The client application transform
/// the path input from the user to files uuid using the informations in the keyring chain.
pub async fn download_file() {}

/// Allow a user to delete a file
pub async fn delete_file() {}

/// Allow a use to share a file with another user
/// 
/// Receive the file key encrypted with the destination user public key from the client
/// push this key in the destination user root keychain.
/// 
/// If it's a file, then the destination user will have access to this file from his root.
/// If it's a folder, then the destination user will have access to this folder
/// and all subsequent files/folder from his root.
pub async fn share_file() {}