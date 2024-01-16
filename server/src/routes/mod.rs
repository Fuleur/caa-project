use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    routing::{get, post, delete},
    Router,
};
use diesel::prelude::*;
use hyper::{HeaderMap, StatusCode};

use crate::{
    db::{schema::sessions, Session},
    log, AppState,
};

pub mod auth;
pub mod files;

pub fn authenticated_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/auth/session", get(auth::check_session))
        .route("/auth/sessions", get(auth::active_sessions))
        .route("/auth/revoke", post(auth::revoke))
        .route("/auth/revoke_all", post(auth::revoke_all))
        .route(
            "/auth/change_password/start",
            post(auth::change_password_start),
        )
        .route(
            "/auth/change_password/finish",
            post(auth::change_password_finish),
        )
        .route("/pubkey/:user", get(auth::get_user_public_key))
        .route("/keyring", get(files::get_tree))
        .route("/file/upload", post(files::upload_file))
        .route("/file/download", get(files::download_file))
        .route("/file/delete", delete(files::delete_file))
        .route("/file/share", post(files::share_file))
        .route("/folder/create", post(files::create_folder))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

async fn auth_middleware(
    headers: HeaderMap,
    State(app_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(token) = headers.get("Authorization") {
        // Get String token (strip the "Bearer " from the header value)
        let Some(token) = token.to_str().unwrap().get(7..) else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        let conn = app_state.pool.get().await.unwrap();

        // Verify token validity
        match conn
            .interact({
                let token = token.to_owned();
                |conn| sessions::table.find(token).first::<Session>(conn)
            })
            .await
            .unwrap()
        {
            Ok(session) => {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                if session.expiration_date as u64 <= current_time {
                    log::debug(&format!("Expired token: {}", token));
                    // Expired token
                    conn.interact(|conn| {
                        diesel::delete(sessions::table.find(session.token)).execute(conn)
                    })
                    .await
                    .unwrap()
                    .unwrap();

                    return Err(StatusCode::UNAUTHORIZED);
                }

                request.extensions_mut().insert(session);
                let response = next.run(request).await;
                Ok(response)
            }

            Err(_e) => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
