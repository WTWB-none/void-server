use actix_web::{middleware::Logger, web, App, Error, HttpResponse, HttpServer};
use actix_cors::Cors;
use confik::{Configuration as _, EnvSource};
use deadpool_postgres::Pool;
use dotenvy::dotenv;
use tokio_postgres::NoTls;
use actix_files as fs;

mod commands;
use commands::*;
use crate::{create_user, check_pass};



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

pub async fn login_user(
    db_pool: web::Data<Pool>,
) -> Result<HttpResponse, MyError> {
    let client = db_pool.get().await.map_err(|e| {
        log::error!("DB pool error: {}", e);
        MyError::PoolError(e)
    })?;

    match sign_in(&client,&"sasha").await.map_err(|e| {
        log::error!("Sign in error: {}", e);
        e
    }){
        Ok(hash) => {
            match check_pass(&hash.unwrap()) {
                true => Ok(HttpResponse::Ok().json("Заебись")),
                false => todo!(),
            }
        },
        Err(e) => todo!(),
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
                fs::Files::new("/static", "./static")
                .show_files_listing()
            )
            .service(
                web::resource("/login")
                .route(web::get().to(login_user))
            )
            .service(get_manifest)
            .service(download_stream)
            
    })
    .bind(config.server_addr.clone())?
    .run();
    println!("Server running at http://{}/", config.server_addr);

    server.await
}
