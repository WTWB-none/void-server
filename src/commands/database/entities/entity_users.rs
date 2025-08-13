use actix_web::{http::header::HttpDate, HttpResponse, get, post};
use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;
use chrono::Utc;
use tokio_postgres::types::ToSql;
use super::{User, MyError};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

#[derive(serde::Deserialize)]
pub struct LoginUser {
    username: String,
}

pub async fn create_user(client: &Client, user_info: User) -> Result<User, MyError> {
    let _stmt = include_str!("../sql/create_user.sql");
    let stmt = client.prepare(&_stmt).await?;

    let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let hash_pass = pass_hash(&user_info.hash_pass);

    client
        .query(
            &stmt,
            &[
                &user_info.id as &(dyn ToSql + Sync),
                &user_info.username,
                &hash_pass,
                &user_info.is_admin,
                &created_at,
            ],
        )
        .await?
        .iter()
        .map(|row| User::from_row_ref(row).unwrap())
        .collect::<Vec<User>>()
        .pop()
        .ok_or(MyError::NotFound)
}



pub async fn sign_in(client: &Client, username: &str) -> Result<Option<String>, MyError> {
    let _stmt = include_str!("../sql/get_user_pass.sql");
    let stmt = client.prepare(&_stmt).await?;

    match client.query_opt(&stmt, &[&username]).await? {
        Some(row) => {
            let hash_pass: String = row.get("hash_pass");
            println!("{}", hash_pass);
            Ok(Some(hash_pass))
        },
        None => Ok(None)
    }
}

fn pass_hash(pass: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    argon2.hash_password(pass.as_bytes(), &salt).unwrap().to_string()
}

pub fn check_pass(hash_pass: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash_pass).unwrap();

    match Argon2::default().verify_password(b"Topparol754", &parsed_hash) {
        Ok(_) => true,
        Err(_) => false,
    }
}


#[cfg(test)]
mod test {
    use actix_web::web;
    use deadpool_postgres::{Pool, Manager, ManagerConfig, RecyclingMethod};
    use tokio_postgres::NoTls;
    use super::*;

    // Вспомогательная функция для создания тестового пула
    async fn create_test_pool() -> Pool {
        let mut cfg = tokio_postgres::Config::new();
        cfg.host("localhost")
            .user("exerted")
            .password("Topparol754")
            .dbname("my_db");
        
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(cfg, NoTls, mgr_config);
        Pool::builder(mgr).max_size(16).build().unwrap()
    }

    async fn connect(db_pool: web::Data<Pool>) -> Result<HttpResponse, MyError> {
        let client = db_pool.get().await.map_err(|e| {
            log::error!("penis");
            MyError::PoolError(e)
        })?;

        print!("penis");
        sign_in(&client, "sasha").await?;

        Ok(HttpResponse::Ok().json(""))
    }

    #[actix_rt::test]
    async fn test_connect() {
        let pool = create_test_pool().await;
        let db_pool = web::Data::new(pool);
        print!("ertyui");
        
        let result = connect(db_pool).await;
        assert!(result.is_ok());
    }
}