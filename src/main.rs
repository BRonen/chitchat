use axum::{
    Router,
    routing::get,
};
use dotenv::dotenv;
use std::env;

mod db;
mod users;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url: String = env::var("DATABASE_URL").unwrap();
    let pool = db::connect(database_url).await;

    db::migrate(&pool).await;

    let app = Router::new()
        .route("/healthcheck", get(|| async { "{\"status\": \"running...\"}" }))
        .nest("/users", users::router(pool));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}