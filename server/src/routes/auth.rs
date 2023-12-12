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
use redis::Commands;
use redis_derive::{FromRedisValue, ToRedisArgs};
use serde::{Deserialize, Serialize};
use std::ops::Add;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::db::schema::users;
use crate::db::User;
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
    State(app_state): State<Arc<RwLock<AppState>>>,
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    Json(register_request): Json<RegisterRequest>,
) -> Result<Json<RegistrationResponse<DefaultCS>>, StatusCode> {
    log::debug("New registration request");

    let mut conn = app_state
        .read()
        .unwrap()
        .redis_client
        .get_connection()
        .unwrap();

    // Check if a user with this username already exists
    // If yes, return a 409 Conflict
    let res: Result<Vec<u8>, _> = conn.get(format!("password/{}", register_request.username));
    if let Some(password) = res.ok() {
        if password.len() > 0 {
            return Err(StatusCode::CONFLICT);
        }
    }

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
    State(app_state): State<Arc<RwLock<AppState>>>,
    Json(register_request): Json<RegisterFinishRequest>,
) -> StatusCode {
    log::debug(&format!("New registration finish request"));

    // Finalize the registration and get the Password File from it
    // Serialize it and store it in redis
    let password_file =
        ServerRegistration::<DefaultCS>::finish(register_request.registration_upload);
    let serialized_password: Vec<u8> = password_file.serialize().to_vec();

    let mut conn = app_state
        .read()
        .unwrap()
        .redis_client
        .get_connection()
        .unwrap();

    // Store user password file
    let _: () = conn
        .set(
            format!("password/{}", register_request.username),
            serialized_password,
        )
        .unwrap();

    // Store user keypair
    let _: () = conn
        .set(
            format!("keypair/{}/public", register_request.username),
            register_request.user_keypair.0,
        )
        .unwrap();

    let _: () = conn
        .set(
            format!("keypair/{}/private", register_request.username),
            register_request.user_keypair.1,
        )
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
    State(app_state): State<Arc<RwLock<AppState>>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<CredentialResponse<DefaultCS>>, (StatusCode, String)> {
    log::debug(&format!(
        "Login start initiated from {}",
        login_request.username.cyan()
    ));

    let conn = app_state.read().unwrap().pool.get().await.unwrap();

    let user: User = conn
        .interact(|conn| {
            users::table
                .filter(users::username.eq(login_request.username))
                .first(conn)
        })
        .await
        .unwrap()
        .unwrap();
    let password = ServerRegistration::<DefaultCS>::deserialize(&user.password).ok();

    let mut rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut rng,
        &server_setup,
        password,
        login_request.credential_request,
        user.username.as_bytes(),
        ServerLoginStartParameters {
            context: None,
            identifiers: Identifiers {
                client: Some(user.username.as_bytes()),
                server: Some(b"TSFSServer"),
            },
        },
    )
    .unwrap();

    // Store the ServerLoginStartResult in a HashMap in a Axum State
    // We'll need to use it later for the login_finish
    app_state
        .write()
        .unwrap()
        .server_login_states
        .insert(user.username, server_login_start_result.clone());

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
    State(app_state): State<Arc<RwLock<AppState>>>,
    Json(login_request): Json<LoginRequestFinish>,
) -> Json<LoginRequestResult> {
    log::debug(&format!(
        "Login finish initiated from {}",
        login_request.username.cyan()
    ));

    // We need to recover the ServerLoginStartResult from the login_start
    let server_login_start_result = app_state
        .read()
        .unwrap()
        .server_login_states
        .get(&login_request.username)
        .unwrap()
        .to_owned();

    // We can remove it from the HashMap
    app_state
        .write()
        .unwrap()
        .server_login_states
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

    let mut conn = app_state
        .read()
        .unwrap()
        .redis_client
        .get_connection()
        .unwrap();

    let session = Session {
        token: b64_token.clone(),
        user: login_request.username.clone(),
        expiration_date: SystemTime::now()
            .add(Duration::from_secs(TOKEN_LIFETIME))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    };

    let _: () = conn
        .set(
            format!("session/{}", b64_token),
            serde_json::to_string(&session).unwrap(),
        )
        .unwrap();

    // Get the User Keypair from redis
    let pub_key: Vec<u8> = conn
        .get(format!("keypair/{}/public", login_request.username))
        .unwrap();

    let priv_key: Vec<u8> = conn
        .get(format!("keypair/{}/private", login_request.username))
        .unwrap();

    Json(LoginRequestResult {
        keypair: (pub_key, priv_key),
    })
}

/// Return the current user Session data (testing purpose)
pub async fn check_session(
    Extension(user_session): Extension<Session>,
) -> Result<Json<Session>, StatusCode> {
    Ok(Json(user_session))
}

/// Revoke the current user Session
pub async fn revoke(
    Extension(user_session): Extension<Session>,
    State(app_state): State<Arc<RwLock<AppState>>>,
) -> StatusCode {
    let mut conn = app_state
        .read()
        .unwrap()
        .redis_client
        .get_connection()
        .unwrap();

    let _: () = conn.del(format!("session/{}", user_session.token)).unwrap();

    StatusCode::OK
}

#[derive(ToRedisArgs, FromRedisValue, Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub expiration_date: u64,
}
