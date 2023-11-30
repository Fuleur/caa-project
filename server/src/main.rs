use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    routing::{get, post},
    Extension, Router,
};
use opaque_ke::{ServerLoginStartResult, ServerSetup};
use rand::rngs::OsRng;
use routes::auth::{self, DefaultCS};

mod log;
mod routes;

const LISTENING_ADDRESS: &str = "0.0.0.0";
const PORT: u16 = 1315;

#[tokio::main]
async fn main() {
    let mut rng = OsRng;
    let server_setup = Arc::new(ServerSetup::<DefaultCS>::new(&mut rng));
    let server_states = Arc::new(RwLock::new(HashMap::<
        String,
        ServerLoginStartResult<DefaultCS>,
    >::new()));

    let app = Router::new()
        .route("/", get(hello))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .layer(Extension(server_setup))
        .with_state(server_states);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", LISTENING_ADDRESS, PORT))
        .await
        .unwrap();

    log::info(&format!(
        "Server listening on {}:{}",
        LISTENING_ADDRESS, PORT
    ));

    axum::serve(listener, app).await.unwrap();
}

async fn hello() -> &'static str {
    "héhé"
}
