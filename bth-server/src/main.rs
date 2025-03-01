use actix_web::{web, App, HttpServer};
use crate::routes::user_routes::{create_user, get_users, get_user, update_user, delete_user, login};

use crate::db::establish_connection;

mod db;
mod models;
mod routes;
mod middleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = establish_connection().await;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/users", web::post().to(create_user))
            .route("/login", web::post().to(login))
            .route("/users", web::get().to(get_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/users/{id}", web::put().to(update_user))
            .route("/users/{id}", web::delete().to(delete_user))
    })
    .bind("localhost:3000")?
    .run()
    .await
}
