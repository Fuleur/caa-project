use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Extension, Json};
use deadpool_diesel::{sqlite::Pool, SyncGuard};
use diesel::prelude::*;
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{
        schema::{files, keyrings, keys, users},
        File, FileWithoutData, FileWithoutDataWithKeyring, Folder, Key, KeyWithFile, Keyring,
        KeyringWithKeys, KeyringWithKeysAndFiles, NewFile, NewKey, NewKeyring, Session, User,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct UploadFileRequest {
    /// The parent folder to put the file in.
    /// None = root
    parent_uid: Option<String>,
    /// Encrypted filename
    filename: String,
    /// Encrypted file content
    file: Vec<u8>,
    /// Encrypted symmetric key with user pubkey
    encrypted_key: Vec<u8>,
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
) -> StatusCode {
    let conn = app_state.pool.get().await.unwrap();

    // Get user keyring informations
    let user_keyring_id: i32 = conn
        .interact({
            let user = user_session.user.clone();
            move |conn| {
                users::table
                    .find(user)
                    .select(users::keyring)
                    .first::<i32>(conn)
            }
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
            return StatusCode::FORBIDDEN;
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

    StatusCode::OK
}

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    /// The parent folder to put the file in.
    /// None = root
    parent_uid: Option<String>,
    /// Encrypted filename
    filename: String,
    /// Encrypted symmetric key with user pubkey
    encrypted_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct CreateFolderResponse {
    keyring: KeyringWithKeys,
}

/// Allow a user to create a folder at a given location
///
/// Folders are basically a File but without data and with a Keyring
pub async fn create_folder(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
    Json(create_folder_request): Json<CreateFolderRequest>,
) -> Result<Json<CreateFolderResponse>, StatusCode> {
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
    if let Some(parent_uid) = create_folder_request.parent_uid.clone() {
        if !has_access(&user_keyring, parent_uid, &mut conn.lock().unwrap()) {
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Create folder keyring
    let folder_keyring: Keyring = conn
        .interact(|conn| {
            diesel::insert_into(keyrings::table)
                .values(NewKeyring { id: None })
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Create new folder
    let file = File {
        id: Uuid::new_v4().to_string(),
        name: create_folder_request.filename,
        mtime: Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
        ),
        sz: None,
        data: None,
        keyring_id: Some(folder_keyring.id),
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
    let parent_keyring = if let Some(parent_uid) = create_folder_request.parent_uid {
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
                    key: create_folder_request.encrypted_key,
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

    Ok(Json(CreateFolderResponse {
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

#[derive(Deserialize)]
pub struct DeleteFileRequest {
    file_uid: String,
}

/// Allow a user to delete a file
pub async fn delete_file(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
    Json(delete_request): Json<DeleteFileRequest>,
) -> StatusCode {
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
        delete_request.file_uid.clone(),
        &mut conn.lock().unwrap(),
    ) {
        return StatusCode::FORBIDDEN;
    }

    // Delete file
    // TODO: Proper folder deletion
    // Currently, if file is a folder, we lost access to all files and folders inside it, no problem
    // but files and folders remains in the database, but nobody can access them anymore as the link to them is broken
    conn.interact(move |conn| {
        conn.transaction(|conn| {
            // Delete all keys to this file
            diesel::delete(keys::table.filter(keys::target.eq(&delete_request.file_uid)))
                .execute(conn)?;
            // Delete file
            diesel::delete(files::table.find(&delete_request.file_uid)).execute(conn)?;

            diesel::result::QueryResult::Ok(())
        })
    })
    .await
    .unwrap()
    .unwrap();

    StatusCode::OK
}

#[derive(Deserialize)]
pub struct ShareFileRequest {
    /// File to share
    file_uid: String,
    /// Symmetric key of the file, encrypted with target_user public key
    encrypted_key: Vec<u8>,
    /// The user to share the file with
    target_user: String,
}

/// Allow a use to share a file with another user
///
/// Receive the file key encrypted with the destination user public key from the client
/// push this key in the destination user root keyring.
///
/// If it's a file, then the destination user will have access to this file from his root.
/// If it's a folder, then the destination user will have access to this folder
/// and all subsequent files/folder from his root.
pub async fn share_file(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
    Json(share_request): Json<ShareFileRequest>,
) -> StatusCode {
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
        share_request.file_uid.clone(),
        &mut conn.lock().unwrap(),
    ) {
        return StatusCode::FORBIDDEN;
    }

    conn.interact(move |conn| {
        conn.transaction(|conn| {
            // Get target_user keyring id
            let target_user: User = users::table
                .find(share_request.target_user)
                .first::<User>(conn)?;

            // Add shared key to the target_user keyring
            diesel::insert_into(keys::table)
                .values(NewKey {
                    target: share_request.file_uid,
                    key: share_request.encrypted_key,
                    keyring_id: target_user.keyring,
                })
                .execute(conn)?;

            diesel::result::QueryResult::Ok(())
        })
    })
    .await
    .unwrap()
    .unwrap();

    StatusCode::OK
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

        let folder = files::table
            .find(key.target)
            .inner_join(keyrings::table)
            .select((files::id, files::name, (keyrings::all_columns)))
            .first::<Folder>(conn.as_mut());

        if let Ok(folder) = folder {
            if has_access(&folder.keyring, file_uuid.clone(), conn) {
                return true;
            }
        }
    }

    false
}

/// Allow a user to get his Keyring Tree
pub async fn get_tree(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
) -> Json<KeyringWithKeysAndFiles> {
    Json(
        get_user_tree(user_session.user, app_state.pool)
            .await
            .unwrap(),
    )
}

pub async fn get_user_tree(user: String, pool: Pool) -> Option<KeyringWithKeysAndFiles> {
    let conn = pool.get().await.unwrap();

    // Get user keyring informations
    let user_keyring_id: i32 = conn
        .interact(|conn| {
            users::table
                .find(user)
                .select(users::keyring)
                .first::<i32>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    let user_keyring = conn
        .interact(move |conn| keyrings::table.find(user_keyring_id).first::<Keyring>(conn))
        .await
        .unwrap();

    if let Ok(keyring) = user_keyring {
        let keyring_files = get_files_in_keyring(&keyring, &mut conn.lock().unwrap());

        Some(KeyringWithKeysAndFiles {
            id: keyring.id,
            keys: keyring_files,
        })
    } else {
        None
    }
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
