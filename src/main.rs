use actix_web::{middleware::Logger, web, App, Error, HttpResponse, HttpServer};
use actix_cors::Cors;
use confik::{Configuration as _, EnvSource};
use deadpool_postgres::Pool;
use dotenvy::dotenv;
use tokio_postgres::NoTls;
use actix_files as fs;

mod commands;
use commands::*;

pub async fn add_user(
    user: web::Json<User>,
    db_pool: web::Data<Pool>,
) -> Result<HttpResponse, Error> {
    let user_info = user.into_inner();
    
    let client = db_pool.get().await.map_err(|e| {
        log::error!("DB pool error: {}", e);
        MyError::PoolError(e)
    })?;

    let new_user = create_user(&client, user_info).await.map_err(|e| {
        log::error!("Create user error: {}", e);
        e
    })?;

    Ok(HttpResponse::Ok().json(new_user))
}

pub async fn add_group(
    group: web::Json<Group>,
    db_pool: web::Data<Pool>,
) -> Result<HttpResponse, Error> {
    let group_info = group.into_inner();

    let client = db_pool.get().await.map_err(|e| {
        log::error!("DB pool error {}", e);
        MyError::PoolError(e)
    })?;

    let new_group = create_group(&client, group_info).await.map_err(|e| {
        log::error!("Create group error: {}", e);
        e
    })?;

    Ok(HttpResponse::Ok().json(new_group))
}

pub async fn login_user(
    credentials: web::Json<LoginUser>,
    db_pool: web::Data<Pool>,
) -> Result<HttpResponse, Error> {
    let credentials = credentials.into_inner();
    let client = db_pool.get().await.map_err(|e| {
        log::error!("DB pool error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    match sign_in(&client, &credentials.username).await {
        Ok(Some(hash)) => {
            if check_pass(&hash, &credentials.password) {
                Ok(HttpResponse::Ok().json("Login successful"))
            } else {
                Ok(HttpResponse::Unauthorized().json("Invalid credentials"))
            }
        }
        Ok(None) => Ok(HttpResponse::NotFound().json("User not found")),
        Err(e) => {
            log::error!("Sign in error: {}", e);
            Ok(HttpResponse::InternalServerError().json("Internal server error"))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    dotenv().ok();

    let config = ExampleConfig::builder()
        .override_with(EnvSource::new())
        .try_build()
        .unwrap();

    let pool = config.pg.create_pool(None, NoTls).unwrap();
    let _num_workers = num_cpus::get();
    let server = HttpServer::new(move || {
        
    let cors = Cors::default()
            .allow_any_origin() 
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"]) 
            .allowed_header(actix_web::http::header::CONTENT_TYPE);


        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::resource("/users")
                .route(web::post().to(add_user))
            )
            .service(
                web::resource("/groups")
                .route(web::post().to(add_group))
            )
            .service(
                fs::Files::new("/static", "./static")
                .show_files_listing()
            )
            .service(
                web::resource("/login")
                .route(web::post().to(login_user))
            )
            .service(get_manifest)
            .service(download_stream)
            
    })
    .bind(config.server_addr.clone())?
    .run();
    println!("Server running at http://{}/", config.server_addr);

    server.await
}
