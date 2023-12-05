use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Extension, Router,
};
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use dotenv::dotenv;
use opaque_ke::*;
use rand::rngs::OsRng;
use redis::Commands;
use routes::auth::{self, DefaultCS, Session};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;

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
        .route(
            "/auth/session",
            get(auth::check_session).route_layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth_middleware,
            )),
        )
        .layer(ServiceBuilder::new().layer(Extension(server_setup_state)))
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

async fn auth_middleware(
    headers: HeaderMap,
    State(app_state): State<Arc<RwLock<AppState>>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(token) = headers.get("Authorization") {
        // Get String token (strip the "Bearer " from the header value)
        let Some(token) = token.to_str().unwrap().get(7..) else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        let mut conn = app_state
            .read()
            .unwrap()
            .redis_client
            .get_connection()
            .unwrap();

        // Verify token validity
        match conn.get::<String, String>(format!("session/{}", token)) {
            Ok(session) => {
                let session: Session = serde_json::from_str(&session).unwrap();
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                if session.expiration_date <= current_time {
                    log::debug(&format!("Expired token: {}", token));
                    // Expired token
                    let _: () = conn.del(format!("session/{}", token)).unwrap();

                    return Err(StatusCode::UNAUTHORIZED);
                }

                request.extensions_mut().insert(session);
                let response = next.run(request).await;
                Ok(response)
            }

            Err(_) => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
