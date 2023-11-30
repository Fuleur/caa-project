use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::{Arc, RwLock},
};

use axum::{extract::State, http::StatusCode, Extension, Json};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::log;

pub struct DefaultCS;
impl CipherSuite for DefaultCS {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterRequest {
    username: String,
    registration_request: RegistrationRequest<DefaultCS>,
}

pub async fn register_start(
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    Json(register_request): Json<RegisterRequest>,
) -> Json<RegistrationResponse<DefaultCS>> {
    log::debug("New registration request");

    // TODO: Need to check if user is already registered
    // If this is the case we MUST refuse the registration (because someone could overwrite a user password)
    // Need to make another route to perform password reset

    let server_registration_start_result = ServerRegistration::<DefaultCS>::start(
        &server_setup,
        register_request.registration_request,
        register_request.username.as_bytes(),
    )
    .unwrap();

    Json(server_registration_start_result.message)
}

pub async fn register_finish(
    Json(registration_upload): Json<RegistrationUpload<DefaultCS>>,
) -> StatusCode {
    log::debug(&format!("New registration finish request"));

    let password_file = ServerRegistration::<DefaultCS>::finish(registration_upload);

    // TODO: One file per user
    // Also using another method to store registrations (like redis)
    let mut file = File::create("./passwords").unwrap();
    file.write_all(&password_file.serialize()).unwrap();

    StatusCode::OK
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    username: String,
    credential_request: CredentialRequest<DefaultCS>,
}

pub async fn login_start(
    Extension(server_setup): Extension<Arc<ServerSetup<DefaultCS>>>,
    State(server_states): State<Arc<RwLock<HashMap<String, ServerLoginStartResult<DefaultCS>>>>>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<CredentialResponse<DefaultCS>>, (StatusCode, String)> {
    let mut password_file: Option<ServerRegistration<DefaultCS>> = None;
    if Path::new("./passwords").exists() {
        let mut file = File::open("./passwords").unwrap();
        let mut password_file_bytes: Vec<u8> = Vec::new();
        file.read_to_end(&mut password_file_bytes).unwrap();

        password_file = ServerRegistration::<DefaultCS>::deserialize(&password_file_bytes).ok();
    }

    let mut server_rng = OsRng;

    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_setup,
        password_file,
        login_request.credential_request,
        login_request.username.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();

    server_states
        .write()
        .unwrap()
        .insert(login_request.username, server_login_start_result.clone());

    Ok(Json(server_login_start_result.message))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequestFinish {
    username: String,
    credential_finalization: CredentialFinalization<DefaultCS>,
}

pub async fn login_finish(
    State(server_states): State<Arc<RwLock<HashMap<String, ServerLoginStartResult<DefaultCS>>>>>,
    Json(login_request): Json<LoginRequestFinish>,
) -> StatusCode {
    let server_login_start_result = server_states
        .read()
        .unwrap()
        .get(&login_request.username)
        .unwrap()
        .to_owned();

    server_states
        .write()
        .unwrap()
        .remove(&login_request.username)
        .unwrap();

    let server_login_finish_result = server_login_start_result
        .state
        .finish(login_request.credential_finalization)
        .unwrap();

    log::debug(&format!(
        "Login successfull. token: {:?}",
        server_login_finish_result.session_key
    ));

    StatusCode::OK
}
