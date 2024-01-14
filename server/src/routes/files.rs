use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Extension, Json};
use deadpool_diesel::SyncGuard;
use diesel::prelude::*;
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{
        schema::{files, keyrings, keys, users},
        File, FileWithoutData, FileWithoutDataWithKeyring, Folder, Key, KeyWithFile, Keyring,
        KeyringWithKeys, KeyringWithKeysAndFiles, NewFile, NewKey, Session,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct UploadFileRequest {
    parent_uid: Option<String>,
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
) -> Result<Json<UploadFileResponse>, StatusCode> {
    let conn = app_state.pool.get().await.unwrap();

    // Get user keyring informations
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

    let user_keyring: Keyring = conn
        .interact(move |conn| keyrings::table.find(user_keyring_id).first::<Keyring>(conn))
        .await
        .unwrap()
        .unwrap();

    // Check if user has access to parent folder
    if let Some(parent_uid) = upload_request.parent_uid.clone() {
        if !has_access(&user_keyring, parent_uid, &mut conn.lock().unwrap()) {
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Create new file
    let file = NewFile {
        id: Uuid::new_v4().to_string(),
        name: upload_request.filename,
        mtime: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        sz: upload_request.file.len() as i32,
        data: upload_request.file,
        keyring_id: None,
    };

    // Insert new file in DB
    conn.interact({
        let file = file.clone();
        |conn| diesel::insert_into(files::table).values(file).execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    // Get parent folder keyring
    let parent_keyring = if let Some(parent_uid) = upload_request.parent_uid {
        let parent_folder: Folder = conn
            .interact(move |conn| {
                files::table
                    .find(parent_uid)
                    .inner_join(keyrings::table)
                    .select((files::id, files::name, (keyrings::all_columns)))
                    .first::<Folder>(conn)
            })
            .await
            .unwrap()
            .unwrap();

        parent_folder.keyring
    } else {
        user_keyring
    };

    // Update keyring
    conn.interact({
        let file_id = file.id.clone();
        move |conn| {
            diesel::insert_into(keys::table)
                .values(NewKey {
                    target: file_id,
                    key: upload_request.encrypted_key,
                    keyring_id: parent_keyring.id,
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

    Ok(Json(UploadFileResponse {
        keyring: keyring_with_keys,
    }))
}

#[derive(Deserialize)]
pub struct DownloadFileRequest {
    file_uid: String,
}

/// Allow a user to download a file.
///
/// The file should not be sent to the user if he has no access to it.
/// The path specified is the path starting from the user's root, by following the path
/// from the user's root keyring we can check if it exist or not. Each user has his own file hierarchy.
///
/// Note: the path is not a path by name, but a path by uuid. The client application transform
/// the path input from the user to files uuid using the informations in the keyring chain.
pub async fn download_file(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
    Json(download_request): Json<DownloadFileRequest>,
) -> Result<Json<File>, StatusCode> {
    let conn = app_state.pool.get().await.unwrap();

    // Get user keyring informations
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

    let user_keyring: Keyring = conn
        .interact(move |conn| keyrings::table.find(user_keyring_id).first::<Keyring>(conn))
        .await
        .unwrap()
        .unwrap();

    // Check if aser has access to the file
    if !has_access(
        &user_keyring,
        download_request.file_uid.clone(),
        &mut conn.lock().unwrap(),
    ) {
        return Err(StatusCode::FORBIDDEN);
    }

    let file = conn
        .interact(move |conn| {
            files::table
                .find(download_request.file_uid)
                .first::<File>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    Ok(Json(file))
}

/// Allow a user to delete a file
pub async fn delete_file() {
    todo!()
}

/// Allow a use to share a file with another user
///
/// Receive the file key encrypted with the destination user public key from the client
/// push this key in the destination user root keychain.
///
/// If it's a file, then the destination user will have access to this file from his root.
/// If it's a folder, then the destination user will have access to this folder
/// and all subsequent files/folder from his root.
pub async fn share_file() {
    todo!()
}

/// Check if a user has access to a given file or folder
fn has_access(
    keyring: &Keyring,
    file_uuid: String,
    conn: &mut SyncGuard<SqliteConnection>,
) -> bool {
    let keys: Vec<Key> = keys::table
        .filter(keys::keyring_id.eq(keyring.id))
        .load::<Key>(conn.as_mut())
        .unwrap();

    for key in keys {
        if key.target == file_uuid {
            return true;
        }

        let folder: Folder = files::table
            .find(key.target)
            .inner_join(keyrings::table)
            .select((files::id, files::name, (keyrings::all_columns)))
            .first::<Folder>(conn.as_mut())
            .unwrap();

        return has_access(&folder.keyring, file_uuid, conn);
    }

    false
}

/// Allow a user to get his Keyring Tree
pub async fn get_tree(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
) -> Json<KeyringWithKeysAndFiles> {
    let conn = app_state.pool.get().await.unwrap();

    // Get user keyring informations
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

    let user_keyring: Keyring = conn
        .interact(move |conn| keyrings::table.find(user_keyring_id).first::<Keyring>(conn))
        .await
        .unwrap()
        .unwrap();

    let keyring_files = get_files_in_keyring(&user_keyring, &mut conn.lock().unwrap());

    Json(KeyringWithKeysAndFiles {
        id: user_keyring.id,
        keys: keyring_files,
    })
}

fn get_files_in_keyring(
    keyring: &Keyring,
    conn: &mut SyncGuard<SqliteConnection>,
) -> Vec<KeyWithFile> {
    let mut files: Vec<KeyWithFile> = Vec::new();

    let keys: Vec<Key> = keys::table
        .filter(keys::keyring_id.eq(keyring.id))
        .load::<Key>(conn.as_mut())
        .unwrap();

    for key in keys {
        let file: FileWithoutData = files::table
            .find(key.target)
            .select((files::id, files::name, files::keyring_id))
            .first::<FileWithoutData>(conn.as_mut())
            .unwrap();

        let file_keyring = if let Some(keyring_id) = file.keyring_id {
            let keyring: Keyring = keyrings::table
                .find(keyring_id)
                .first(conn.as_mut())
                .unwrap();

            Some(KeyringWithKeysAndFiles {
                id: keyring.id,
                keys: get_files_in_keyring(&keyring, conn),
            })
        } else {
            None
        };

        let file = FileWithoutDataWithKeyring {
            id: file.id,
            name: file.name,
            keyring: file_keyring,
        };

        files.push(KeyWithFile {
            file,
            key: key.key,
            keyring_id: keyring.id,
        });
    }

    files
}
