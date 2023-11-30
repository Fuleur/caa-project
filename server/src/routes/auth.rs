use axum::{Json, http::StatusCode, debug_handler};
use opaque_ke::{
    CipherSuite, ClientRegistration, ClientRegistrationFinishResult, ClientRegistrationStartResult,
    ServerRegistration, ServerRegistrationStartResult, ServerSetup,
};
use rand::rngs::OsRng;

use crate::log;

struct Default;
impl CipherSuite for Default {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

pub async fn register_start(
    Json(client_registration_start): Json<ClientRegistrationStartResult<Default>>,
) -> Json<ServerRegistrationStartResult<Default>> {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<Default>::new(&mut rng);

    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_registration_start.message,
        b"alice@example.com",
    )
    .unwrap();

    Json(server_registration_start_result)
}

pub async fn register_finish(
    Json(client_registration_finish): Json<ClientRegistrationFinishResult<Default>>,
) -> StatusCode {
    let password_file = ServerRegistration::<Default>::finish(
        client_registration_finish.message,
    );

    log::debug(&format!("{:?}", password_file));

    StatusCode::OK
}
