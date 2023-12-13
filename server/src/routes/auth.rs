use argon2::Argon2;
use axum::{extract::State, http::StatusCode, Extension, Json};
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use diesel::prelude::*;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::db::schema::{sessions, users};
use crate::db::{Session, User};
use crate::log;
use crate::AppState;

pub struct DefaultCS;
impl CipherSuite for DefaultCS {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

/// Token lifetime in secs
const TOKEN_LIFETIME: u64 = 3600;

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterRequest {
    username: String,
    registration_request: RegistrationRequest<DefaultCS>,
}

/// OPAQUE Register Start
pub async fn register_start(
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    Json(register_request): Json<RegisterRequest>,
) -> Result<Json<RegistrationResponse<DefaultCS>>, StatusCode> {
    log::debug("New registration request");

    // Create ServerRegistration
    let server_registration_start_result = ServerRegistration::<DefaultCS>::start(
        &server_setup,
        register_request.registration_request,
        register_request.username.as_bytes(),
    )
    .unwrap();

    // Send back the RegistrationResponse to the Client
    Ok(Json(server_registration_start_result.message))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    username: String,
    registration_upload: RegistrationUpload<DefaultCS>,
    user_keypair: (Vec<u8>, Vec<u8>),
}

/// OPAQUE Register Finish
pub async fn register_finish(
    State(app_state): State<AppState>,
    Json(register_request): Json<RegisterFinishRequest>,
) -> StatusCode {
    log::debug(&format!("New registration finish request"));

    let conn = app_state.pool.get().await.unwrap();

    // Check if a user with this username already exists
    // If yes, return a 409 Conflict
    let res: Result<User, _> = conn
        .interact({
            let username = register_request.username.clone();

            |conn| {
                users::table
                    .filter(users::username.eq(username))
                    .first(conn)
            }
        })
        .await
        .unwrap();

    if res.is_ok() {
        return StatusCode::CONFLICT;
    }

    // Finalize the registration and get the Password File from it
    // Serialize it and store it in redis
    let password_file =
        ServerRegistration::<DefaultCS>::finish(register_request.registration_upload);
    let serialized_password: Vec<u8> = password_file.serialize().to_vec();

    let conn = app_state.pool.get().await.unwrap();

    // Create User and store it in DB
    let new_user = User {
        username: register_request.username,
        password: serialized_password,
        pub_key: register_request.user_keypair.0,
        priv_key: register_request.user_keypair.1,
    };

    conn.interact(|conn| {
        diesel::insert_into(users::table)
            .values(new_user)
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    StatusCode::OK
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    username: String,
    credential_request: CredentialRequest<DefaultCS>,
}

/// OPAQUE Login Start
pub async fn login_start(
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    State(app_state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<CredentialResponse<DefaultCS>>, (StatusCode, String)> {
    log::debug(&format!(
        "Login start initiated from {}",
        login_request.username.cyan()
    ));

    let conn = app_state.pool.get().await.unwrap();

    let user: Result<User, _> = conn
        .interact({
            let username = login_request.username.clone();

            |conn| {
                users::table
                    .filter(users::username.eq(username))
                    .first::<User>(conn)
            }
        })
        .await
        .unwrap();

    let mut password = None;

    if let Ok(user) = user {
        password = Some(ServerRegistration::<DefaultCS>::deserialize(&user.password).unwrap());
    }

    let mut rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut rng,
        &server_setup,
        password,
        login_request.credential_request,
        login_request.username.as_bytes(),
        ServerLoginStartParameters {
            context: None,
            identifiers: Identifiers {
                client: Some(login_request.username.as_bytes()),
                server: Some(b"TSFSServer"),
            },
        },
    )
    .unwrap();

    // Store the ServerLoginStartResult in a HashMap in a Axum State
    // We'll need to use it later for the login_finish
    app_state
        .server_login_states
        .write()
        .unwrap()
        .insert(login_request.username, server_login_start_result.clone());

    // Send back the CredentialResponse to the Client
    Ok(Json(server_login_start_result.message))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestFinish {
    username: String,
    credential_finalization: CredentialFinalization<DefaultCS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestResult {
    keypair: (Vec<u8>, Vec<u8>),
}

/// OPAQUE Login Finish
pub async fn login_finish(
    State(app_state): State<AppState>,
    Json(login_request): Json<LoginRequestFinish>,
) -> Json<LoginRequestResult> {
    log::debug(&format!(
        "Login finish initiated from {}",
        login_request.username.cyan()
    ));

    // We need to recover the ServerLoginStartResult from the login_start
    let server_login_start_result = app_state
        .server_login_states
        .read()
        .unwrap()
        .get(&login_request.username)
        .unwrap()
        .to_owned();

    // We can remove it from the HashMap
    app_state
        .server_login_states
        .write()
        .unwrap()
        .remove(&login_request.username)
        .unwrap();

    // get the ServerLoginFinishResult
    let server_login_finish_result = server_login_start_result
        .state
        .finish(login_request.credential_finalization)
        .unwrap();

    // Here is our Session Key that will be used as Session Token for this Client session
    let b64_token = general_purpose::STANDARD_NO_PAD.encode(server_login_finish_result.session_key);

    log::debug(&format!(
        "Login successfull for {} ! Token: {}",
        login_request.username.cyan(),
        b64_token
    ));

    let conn = app_state.pool.get().await.unwrap();

    // Create Session and store it in DB
    let session = Session {
        token: b64_token.clone(),
        user: login_request.username.clone(),
        expiration_date: SystemTime::now()
            .add(Duration::from_secs(TOKEN_LIFETIME))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
    };

    conn.interact(|conn| {
        diesel::insert_into(sessions::table)
            .values(session)
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    // Get user public and private key
    let user = conn
        .interact(|conn| {
            users::table
                .find(login_request.username)
                .first::<User>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    Json(LoginRequestResult {
        keypair: (user.pub_key, user.priv_key),
    })
}

/// Return the current user Session data (testing purpose)
pub async fn check_session(
    Extension(user_session): Extension<Session>,
) -> Result<Json<Session>, StatusCode> {
    Ok(Json(user_session))
}

#[derive(Serialize, Debug)]
pub struct SessionInfo {
    token_short: String,
    expiration_date: i64,
    current: bool,
}

/// Get all active user sessions
pub async fn active_sessions(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
) -> Json<Vec<SessionInfo>> {
    let conn = app_state.pool.get().await.unwrap();
    let sessions: Vec<Session> = conn
        .interact(|conn| {
            sessions::table
                .filter(sessions::user.eq(user_session.user))
                .get_results(conn)
        })
        .await
        .unwrap()
        .unwrap();

    let sessions = sessions
        .iter()
        .map(|s| SessionInfo {
            token_short: s.token[..16].to_string(),
            expiration_date: s.expiration_date,
            current: s.token == user_session.token,
        })
        .collect();

    Json(sessions)
}

/// Revoke the current user session
pub async fn revoke(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
) -> StatusCode {
    let conn = app_state.pool.get().await.unwrap();

    conn.interact(|conn| diesel::delete(sessions::table.find(user_session.token)).execute(conn))
        .await
        .unwrap()
        .unwrap();

    StatusCode::OK
}

/// Revoke all user sessions except current
pub async fn revoke_all(
    Extension(user_session): Extension<Session>,
    State(app_state): State<AppState>,
) -> StatusCode {
    let conn = app_state.pool.get().await.unwrap();

    conn.interact(|conn| {
        diesel::delete(
            sessions::table.filter(
                sessions::user
                    .eq(user_session.user)
                    .and(sessions::token.ne(user_session.token)),
            ),
        )
        .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    StatusCode::OK
}
