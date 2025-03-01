use actix_web::{web, HttpResponse, Responder};
use crate::models::user::{CreateUser, UpdateUser};
use crate::models::user_queries::{insert_user, fetch_users, fetch_user_by_id, update_user_by_id, delete_user_by_id};
use crate::middleware::auth::{generate_jwt, hash_password, verify_password, AuthMiddleware};
use sqlx::PgPool;
use serde_json::json;

/// Create a new user (POST /users)
pub async fn create_user(pool: web::Data<PgPool>, item: web::Json<CreateUser>) -> impl Responder {
    let hashed_password = match hash_password(&item.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
    };

    let new_user = CreateUser {
        username: item.username.clone(),
        email: item.email.clone(),
        password: hashed_password,
    };

    match insert_user(pool.get_ref(), new_user).await {
        Ok(user) => HttpResponse::Created().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Login and get JWT token (POST /login)
pub async fn login(pool: web::Data<PgPool>, item: web::Json<CreateUser>) -> impl Responder {
    let query = "SELECT id, password FROM users WHERE email = $1";
    match sqlx::query_as::<_, (i32, String)>(query)
        .bind(&item.email)
        .fetch_one(pool.get_ref())
        .await
    {
        Ok((user_id, stored_password)) => {
            if verify_password(&item.password, &stored_password).unwrap_or(false) {
                match generate_jwt(user_id) {
                    Ok(token) => HttpResponse::Ok().json(json!({ "token": token })),
                    Err(_) => HttpResponse::InternalServerError().body("Could not generate token"),
                }
            } else {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("User not found"),
    }
}

/// Get all users (GET /users) - Protected Route
pub async fn get_users(pool: web::Data<PgPool>, _auth: AuthMiddleware) -> impl Responder {
    match fetch_users(pool.get_ref()).await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Get a user by ID (GET /users/{id}) - Protected Route
pub async fn get_user(pool: web::Data<PgPool>, path: web::Path<i32>, _auth: AuthMiddleware) -> impl Responder {
    match fetch_user_by_id(pool.get_ref(), path.into_inner()).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Update a user by ID (PUT /users/{id}) - Protected Route
pub async fn update_user(pool: web::Data<PgPool>, path: web::Path<i32>, item: web::Json<UpdateUser>, _auth: AuthMiddleware) -> impl Responder {
    match update_user_by_id(pool.get_ref(), path.into_inner(), item.into_inner()).await {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Delete a user by ID (DELETE /users/{id}) - Protected Route
pub async fn delete_user(pool: web::Data<PgPool>, path: web::Path<i32>, _auth: AuthMiddleware) -> impl Responder {
    match delete_user_by_id(pool.get_ref(), path.into_inner()).await {
        Ok(_) => HttpResponse::Ok().body("User deleted"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
