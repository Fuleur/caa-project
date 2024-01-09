use axum::{routing::post, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use deadpool_diesel::{sqlite::Pool, Manager, Runtime};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use dotenv::dotenv;
use opaque_ke::*;
use rand::rngs::OsRng;
use routes::{
    auth::{self, DefaultCS},
    authenticated_router,
};
use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};
use tower::ServiceBuilder;

mod db;
mod log;
mod routes;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/");

#[tokio::main]
async fn main() {
    dotenv().ok();

    // If --setup arg is passed, generate a fresh ServerSetup and print it's base64 serialization
    if env::args().find(|a| a == "--setup").is_some() {
        generate_opaque_setup();
        return;
    }

    // If --self-signed arg is passed, generate new self signed certificates for HTTPS
    // This certificate is ONLY for local development as this app only serve HTTPS
    if env::args().find(|a| a == "--self-signed").is_some() {
        generate_ss_certs();
        return;
    }

    // Loading env variables
    let opaque_server_setup =
        env::var("OPAQUE_SERVER_SETUP").expect("Missing `OPAQUE_SERVER_SETUP` env variable");
    let listening_address =
        env::var("LISTENING_ADDRESS").expect("Missing `LISTENING_ADDRESS` env variable");
    let port = env::var("PORT").expect("Missing `PORT` env variable");
    let db_url = env::var("DATABASE_URL").expect("Missing `DATABASE_URL` env variable");

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

    // Init Database
    let manager = Manager::new(db_url, Runtime::Tokio1);
    let pool = Pool::builder(manager).build().unwrap();

    // Run diesel migrations
    let conn = pool.get().await.unwrap();
    conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ()))
        .await
        .unwrap()
        .unwrap();

    let app_state = AppState {
        server_login_states: Arc::new(RwLock::new(HashMap::<
            String,
            ServerLoginStartResult<DefaultCS>,
        >::new())),
        pool,
    };

    // Axum app
    let app = Router::new()
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .merge(authenticated_router(app_state.clone()))
        .layer(ServiceBuilder::new().layer(Extension(server_setup_state)))
        .with_state(app_state);

    // Setup HTTPS Server
    let config = RustlsConfig::from_pem_file(
        env::var("CERT_FILE").expect("Missing CERT_FILE env var"),
        env::var("CERT_KEY_FILE").expect("Missing CERT_KEY_FILE env var"),
    )
    .await
    .expect("Can't load Certificate Files. You can run with --self-signed to generate self-signed certificate for development");

    let addr = SocketAddr::from_str(&format!("{}:{}", listening_address, port)).unwrap();

    log::info(&format!(
        "Server listening on https://{}:{}",
        listening_address, port
    ));

    // Bind and serve Axum app over HTTPS
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// Generate a new OPAQUE ServerSetup
fn generate_opaque_setup() {
    println!("Generating a fresh ServerSetup. Use it in your OPAQUE_SERVER_SETUP env var.\n");
    let mut rng = OsRng;
    let server_setup = ServerSetup::<DefaultCS>::new(&mut rng);
    let b64_server_setup = general_purpose::STANDARD_NO_PAD.encode(server_setup.serialize());
    println!("{}: {}", "OPAQUE ServerSetup".cyan(), b64_server_setup);
}

/// Generate new self-signed certificate
fn generate_ss_certs() {
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
}

#[derive(Clone)]
pub struct AppState {
    server_login_states: Arc<RwLock<HashMap<String, ServerLoginStartResult<DefaultCS>>>>,
    pool: Pool,
}
