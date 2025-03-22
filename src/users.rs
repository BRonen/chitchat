use axum::{
    extract::State,
    http::header::HeaderMap,
    routing::get,
    Json,
    Router
};
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashSet;

#[derive(Clone)]
struct UserState {
    pool: PgPool
}

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ReadUserRequest {
    id: Option<String>,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReadUserResponse {
    id: String,
    name: String,
    email: String,
}

async fn read_users(
    State(state): State<UserState>,
    Json(_payload): Json<ReadUserRequest>
) -> String {
    let users = sqlx::query_as!(
        ReadUserResponse,
        "SELECT id, name, email FROM users"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    serde_json::to_string::<Vec<ReadUserResponse>>(&users).unwrap()
}

#[derive(Clone, Serialize, Deserialize)]
struct CreateUserRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct CreateUserResponse {
    id: String,
    name: String,
    email: String,
}

async fn create_user(
    State(state): State<UserState>,
    Json(payload): Json<CreateUserRequest>,
) -> String {
    let password_hash = hash(payload.password, 10).unwrap();

    let user = sqlx::query_as!(
        CreateUserResponse,
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email",
        payload.name,
        payload.email,
        password_hash
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();

    serde_json::to_string::<CreateUserResponse>(&user).unwrap()
}

#[derive(Serialize, Deserialize)]
struct UserAuthTokenClaims {
    id: String,
    name: String,
    email: String,
}

async fn read_user_auth(headers: HeaderMap) -> String {
    let mut validation = Validation::default();
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();

    let Some(authorization_token) = headers.get("authorization")
    else {
        return "{\"error\": \"unauthorized\"}".to_string();
    };

    let token = decode::<UserAuthTokenClaims>(
        authorization_token.to_str().unwrap(),
        &DecodingKey::from_secret("secret".as_ref()),
        &validation,
    ).unwrap();

    serde_json::to_string(&token.claims).unwrap()
}

#[derive(Clone, Serialize, Deserialize)]
struct CreateUserAuthRequest {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct CreateUserAuthResponse {
    token: String,
}

async fn create_user_auth(
    State(state): State<UserState>,
    Json(payload): Json<CreateUserAuthRequest>
) -> String {
    let mut users = sqlx::query_as!(
        User,
        "SELECT id, name, email, password_hash FROM users WHERE email = $1 LIMIT 1",
        payload.email,
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let Some(user) = users.pop()
    else {
        return "{\"error\": \"Invalid credentials\"}".to_string();
    };

    if !verify(&payload.password, &user.password_hash).unwrap() {
        return "{\"error\": \"Invalid credentials\"}".to_string();
    }

    let claims = UserAuthTokenClaims {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    
    let response = CreateUserAuthResponse {
        token: encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        ).unwrap(),
    };

    serde_json::to_string(&response).unwrap()
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
    .route(
        "/",
        get(read_users).post(create_user))
    .route(
        "/auth",
        get(read_user_auth).post(create_user_auth))
    .with_state(UserState { pool })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::dotenv;
    use std::env;
    use uuid;

    async fn setup_test_db(db_name: &str) -> PgPool {
        dotenv().ok();
        let base_url = env::var("DATABASE_URL").unwrap();
        
        let admin_pool = PgPool::connect(&base_url)
            .await
            .unwrap();

        sqlx::query(&format!("CREATE DATABASE {}", db_name))
            .execute(&admin_pool)
            .await
            .unwrap();

        let test_url = base_url.replace("/chitchat", &format!("/{}", db_name));
        let pool = PgPool::connect(&test_url)
            .await
            .unwrap();

        sqlx::migrate!()
            .run(&pool)
            .await
            .unwrap();

        pool
    }

    async fn cleanup_test_db(db_name: &str) {
        let base_url = env::var("DATABASE_URL").unwrap();
        let admin_pool = PgPool::connect(&base_url)
            .await
            .unwrap();

        sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
            .execute(&admin_pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_user_test() {
        let db_name = format!("test_create_user_{}", uuid::Uuid::new_v4().simple());
        let pool = setup_test_db(&db_name).await;
        let user_state = UserState { pool };

        let user = CreateUserRequest {
            name: "Chad".to_string(),
            email: "chad1@gmail.com".to_string(),
            password: "password".to_string()
        };

        let response = create_user(
            State(user_state.clone()),
            Json(user.clone()),
        ).await;

        let response: CreateUserResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
    }

    #[tokio::test]
    async fn read_user_test() {
        let db_name = format!("test_read_user_{}", uuid::Uuid::new_v4().simple());
        let pool = setup_test_db(&db_name).await;
        let user_state = UserState { pool };

        let user = ReadUserRequest {
            id: None,
            name: None,
            email: None,
        };

        {
            let response = read_users(
                State(user_state.clone()),
                Json(user.clone()),
            ).await;

            let response = serde_json::from_str::<Vec<ReadUserResponse>>(&response).unwrap();
            
            assert_eq!(response.len(), 0);
        }

        {
            let user = CreateUserRequest {
                name: "Chad".to_string(),
                email: "chad1@gmail.com".to_string(),
                password: "password".to_string()
            };

            create_user(
                State(user_state.clone()),
                Json(user.clone()),
            ).await;
        }

        {
            let response = read_users(
                State(user_state.clone()),
                Json(user.clone()),
            ).await;

            let response = serde_json::from_str::<Vec<ReadUserResponse>>(&response).unwrap();

            assert_eq!(response.len(), 1);
        }
    }

    #[tokio::test]
    async fn auth_user_test() {
        let db_name = format!("test_auth_user_{}", uuid::Uuid::new_v4().simple());
        let pool = setup_test_db(&db_name).await;
        let user_state = UserState { pool };

        let credentials = CreateUserAuthRequest {
            email: "chad".to_string(),
            password: "password_test".to_string(),
        };

        let response = create_user_auth (
            State(user_state.clone()),
            Json(credentials.clone()),
        ).await;

        let response = serde_json::from_str::<ErrorResponse>(&response).unwrap();
        
        assert_eq!(response.error, "Invalid credentials");

        let user = CreateUserRequest {
            name: "Chad".to_string(),
            email: credentials.clone().email,
            password: credentials.clone().password,
        };

        let response = create_user(
            State(user_state.clone()),
            Json(user.clone()),
        ).await;
        let userdata = serde_json::from_str::<CreateUserResponse>(&response).unwrap();

        let response = create_user_auth (
            State(user_state.clone()),
            Json(credentials.clone()),
        ).await;

        let response = serde_json::from_str::<CreateUserAuthResponse>(&response).unwrap();
        
        assert!(response.token.len() > 0);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", response.token.parse().unwrap());

        let response = read_user_auth(headers).await;
        let response = serde_json::from_str::<UserAuthTokenClaims>(&response).unwrap();
        
        assert_eq!(response.id, userdata.id);
        assert_eq!(response.name, userdata.name);
        assert_eq!(response.email, userdata.email);
    }
}