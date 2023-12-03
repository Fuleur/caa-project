use argon2::Argon2;
use axum::{extract::State, http::StatusCode, Extension, Json};
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::log;
use crate::AppState;

pub struct DefaultCS;
impl CipherSuite for DefaultCS {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterRequest {
    username: String,
    registration_request: RegistrationRequest<DefaultCS>,
}

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
}

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

    let _: () = conn
        .set(
            format!("password/{}", register_request.username),
            serialized_password,
        )
        .unwrap();

    StatusCode::OK
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    username: String,
    credential_request: CredentialRequest<DefaultCS>,
}

pub async fn login_start(
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    State(app_state): State<Arc<RwLock<AppState>>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<CredentialResponse<DefaultCS>>, (StatusCode, String)> {
    log::debug(&format!(
        "Login start initiated from {}",
        login_request.username.cyan()
    ));

    let mut conn = app_state
        .read()
        .unwrap()
        .redis_client
        .get_connection()
        .unwrap();

    // Get the Password from redis
    let password: Vec<u8> = conn
        .get(format!("password/{}", login_request.username))
        .unwrap();
    let password = ServerRegistration::<DefaultCS>::deserialize(&password).ok();

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
        .write()
        .unwrap()
        .server_login_states
        .insert(login_request.username, server_login_start_result.clone());

    // Send back the CredentialResponse to the Client
    Ok(Json(server_login_start_result.message))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestFinish {
    username: String,
    credential_finalization: CredentialFinalization<DefaultCS>,
}

pub async fn login_finish(
    State(app_state): State<Arc<RwLock<AppState>>>,
    Json(login_request): Json<LoginRequestFinish>,
) -> StatusCode {
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

    StatusCode::OK
}
