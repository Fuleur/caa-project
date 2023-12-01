use axum::{routing::post, Extension, Router};
use base64::{engine::general_purpose, Engine as _};
use dotenv::dotenv;
use opaque_ke::{ServerLoginStartResult, ServerSetup};
use routes::auth::{self, DefaultCS};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, RwLock},
};

mod log;
mod routes;

const LISTENING_ADDRESS: &str = "0.0.0.0";
const PORT: u16 = 1315;

#[tokio::main]
async fn main() {
    dotenv().ok();

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
        .decode(env::var("OPAQUE_SERVER_SETUP").expect("Missing OPAQUE_SERVER_SETUP in env file"))
        .unwrap();

    // Deserialize the ServerSetup
    let server_setup: ServerSetup<DefaultCS> =
        ServerSetup::<DefaultCS>::deserialize(&server_setup_serialized).unwrap();
    let server_setup_state = Arc::new(server_setup);

    let app_state = Arc::new(RwLock::new(AppState {
        server_login_states: HashMap::<String, ServerLoginStartResult<DefaultCS>>::new(),
        redis_client: redis::Client::open("redis://127.0.0.1/").unwrap(),
    }));

    // Initilize Axum app
    let app = Router::new()
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .layer(Extension(server_setup_state))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", LISTENING_ADDRESS, PORT))
        .await
        .unwrap();

    log::info(&format!(
        "Server listening on {}:{}",
        LISTENING_ADDRESS, PORT
    ));

    axum::serve(listener, app).await.unwrap();
}

pub struct AppState {
    server_login_states: HashMap<String, ServerLoginStartResult<DefaultCS>>,
    redis_client: redis::Client,
}
