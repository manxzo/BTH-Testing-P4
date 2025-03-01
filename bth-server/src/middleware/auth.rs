use actix_web::{ Error, HttpRequest};
use actix_web::FromRequest;
use futures_util::future::{ready, Ready};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHasher, PasswordVerifier,password_hash};
use password_hash::{SaltString, PasswordHash, rand_core::OsRng};

use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user_id
    pub exp: usize,   // Expiry timestamp
}

/// Generate a JWT token for a user
pub fn generate_jwt(user_id: i32) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration = chrono::Utc::now().timestamp() as usize + 3600;  // 1-hour expiry

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

/// Validate a JWT token
pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims)
}

/// Middleware for extracting the token from the request header
pub struct AuthMiddleware {
    pub claims: Claims,
}

impl FromRequest for AuthMiddleware {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok());

        if let Some(header_value) = auth_header {
            if header_value.starts_with("Bearer ") {
                let token = &header_value[7..];
                match validate_jwt(token) {
                    Ok(claims) => return ready(Ok(AuthMiddleware { claims })),
                    Err(_) => return ready(Err(actix_web::error::ErrorUnauthorized("Invalid token"))),
                }
            }
        }

        ready(Err(actix_web::error::ErrorUnauthorized("Missing token")))
    }
}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a password
pub fn verify_password(password: &str, hash: &str) -> Result<bool, password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
