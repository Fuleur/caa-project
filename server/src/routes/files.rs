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

pub async fn download_file() {}

pub async fn delete_file() {}

pub async fn share_file() {}
