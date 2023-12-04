use axum::{routing::{post, get}, Extension, Router};
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use dotenv::dotenv;
use opaque_ke::*;
use rand::rngs::OsRng;
use routes::auth::{self, DefaultCS};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, RwLock},
};

mod log;
mod routes;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // If --setup arg is passed, generate a fresh ServerSetup and print it's base64 serialization
    if env::args().find(|a| a == "--setup").is_some() {
        println!("Generating a fresh ServerSetup. Use it in your OPAQUE_SERVER_SETUP env var.\n");
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCS>::new(&mut rng);
        let b64_server_setup = general_purpose::STANDARD_NO_PAD.encode(server_setup.serialize());
        println!("{}: {}", "OPAQUE ServerSetup".cyan(), b64_server_setup);

        return;
    }

    // Loading env variables
    let opaque_server_setup =
        env::var("OPAQUE_SERVER_SETUP").expect("Missing `OPAQUE_SERVER_SETUP` env variable");
    let listening_address =
        env::var("LISTENING_ADDRESS").expect("Missing `LISTENING_ADDRESS` env variable");
    let port = env::var("PORT").expect("Missing `PORT` env variable");
    let redis_url = env::var("REDIS_URL").expect("Missing `REDIS_URL` env variable");

    // Get the ServerSetup from env
    // Using a saved ServerSetup is needed to have persistence
    // Otherwise new Keypair and other parameters will be re-generated
    // Or we want to have everytime the same, otherwise goodbye all existing users
    // To create a fresh ServerSetup:
    //      let mut rng = OsRng;
    //      let server_setup = ServerSetup::<DefaultCS>::new(&mut rng);
    //      let b64_server_setup = general_purpose::STANDARD_NO_PAD.encode(server_setup.serialize());
    //      println!("{}", b64_server_setup); <--- Put this in OPAQUE_SERVER_SETUP env var
    let server_setup_serialized = general_purpose::STANDARD_NO_PAD
        .decode(opaque_server_setup)
        .unwrap();

    // Deserialize the ServerSetup
    let server_setup: ServerSetup<DefaultCS> =
        ServerSetup::<DefaultCS>::deserialize(&server_setup_serialized).unwrap();
    let server_setup_state = Arc::new(server_setup);

    let app_state = Arc::new(RwLock::new(AppState {
        server_login_states: HashMap::<String, ServerLoginStartResult<DefaultCS>>::new(),
        redis_client: redis::Client::open(redis_url).unwrap(),
    }));

    // Initilize Axum app
    let app = Router::new()
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/session", get(auth::check_session))
        .layer(Extension(server_setup_state))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", listening_address, port))
        .await
        .unwrap();

    log::info(&format!(
        "Server listening on {}:{}",
        listening_address, port
    ));

    axum::serve(listener, app).await.unwrap();
}

pub struct AppState {
    server_login_states: HashMap<String, ServerLoginStartResult<DefaultCS>>,
    redis_client: redis::Client,
}