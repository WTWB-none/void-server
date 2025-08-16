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
    pub username: String,
    pub password: String,
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
            Ok(Some(hash_pass))
        }
        None => Ok(None)
    }
}

fn pass_hash(pass: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    argon2.hash_password(pass.as_bytes(), &salt).unwrap().to_string()
}

pub fn check_pass(hash_pass: &str, password: &str) -> bool {
    match PasswordHash::new(hash_pass) {
        Ok(parsed_hash) => {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        }
        Err(_) => false,
    }
}
