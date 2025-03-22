use sqlx::PgPool;

pub async fn connect(database_url: String) -> PgPool {
    PgPool::connect(&database_url)
    .await
    .unwrap()
}

pub async fn migrate(pool: &PgPool) -> () {
    sqlx::migrate!()
    .run(pool)
    .await
    .unwrap();
}