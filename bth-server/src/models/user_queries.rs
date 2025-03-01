use crate::models::user::{User, CreateUser, UpdateUser};
use sqlx::PgPool;

pub async fn insert_user(pool: &PgPool, new_user: CreateUser) -> Result<User, sqlx::Error> {
    let query = "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, password";
    
    sqlx::query_as::<_, User>(query)
        .bind(&new_user.username)
        .bind(&new_user.email)
        .bind(&new_user.password)
        .fetch_one(pool)
        .await
}

pub async fn fetch_users(pool: &PgPool) -> Result<Vec<User>, sqlx::Error> {
    let query = "SELECT id, username, email, password FROM users ORDER BY id";
    
    sqlx::query_as::<_, User>(query)
        .fetch_all(pool)
        .await
}

pub async fn fetch_user_by_id(pool: &PgPool, user_id: i32) -> Result<User, sqlx::Error> {
    let query = "SELECT id, username, email, password FROM users WHERE id = $1";

    sqlx::query_as::<_, User>(query)
        .bind(user_id)
        .fetch_one(pool)
        .await
}

pub async fn update_user_by_id(pool: &PgPool, user_id: i32, updates: UpdateUser) -> Result<User, sqlx::Error> {
    let query = "UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), password = COALESCE($3, password) WHERE id = $4 RETURNING id, username, email, password";

    sqlx::query_as::<_, User>(query)
        .bind(updates.username.clone())
        .bind(updates.email.clone())
        .bind(updates.password.clone())
        .bind(user_id)
        .fetch_one(pool)
        .await
}

pub async fn delete_user_by_id(pool: &PgPool, user_id: i32) -> Result<(), sqlx::Error> {
    let query = "DELETE FROM users WHERE id = $1";

    sqlx::query(query)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
