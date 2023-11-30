use axum::{
    routing::{get, post},
    Router,
};
use routes::auth;

mod log;
mod routes;

const LISTENING_ADDRESS: &str = "0.0.0.0";
const PORT: u16 = 1315;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(hello))
        .route("/auth/register_start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish));

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
