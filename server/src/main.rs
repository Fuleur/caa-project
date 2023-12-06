use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Extension, Router,
};
use axum_server::tls_rustls::RustlsConfig;
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
    fs::{self, File},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
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

    // If --self-signed arg is passed, generate new self signed certificates for HTTPS
    // This certificate is ONLY for local development as this app only serve HTTPS
    if env::args().find(|a| a == "--self-signed").is_some() {
        log::warning("Generating new self-signed certificate. Use only for development !\n");
        let cert = rcgen::generate_simple_self_signed(vec![]).unwrap();

        fs::create_dir_all(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs/")).unwrap();

        // Write Certificate file
        let mut cert_file =
            File::create(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs/cert.pem")).unwrap();
        cert_file
            .write_all(&cert.serialize_pem().unwrap().as_bytes())
            .unwrap();

        // Write Private Key file
        let mut key_file =
            File::create(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs/key.pem")).unwrap();
        key_file
            .write_all(&cert.serialize_private_key_pem().as_bytes())
            .unwrap();

        log::info("Self-signed certificate generated !");
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
        .route("/", get(hello))
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
        .route(
            "/auth/revoke",
            post(auth::revoke).route_layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth_middleware,
            )),
        )
        .layer(ServiceBuilder::new().layer(Extension(server_setup_state)))
        .with_state(app_state);

    // Start HTTPS Server

    // Set HTTPS config
    // TODO: Set certificate and key file path in env
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs/cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs/key.pem"),
    )
    .await
    .unwrap();

    let addr = SocketAddr::from_str(&format!("{}:{}", listening_address, port)).unwrap();

    log::info(&format!(
        "Server listening on https://{}:{}",
        listening_address, port
    ));

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
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

async fn hello() -> &'static str {
    "hello world"
}
