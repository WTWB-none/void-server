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

pub async fn create_user(client: &Client, user_info: User) -> Result<User, MyError> {
    let _stmt = include_str!("../sql/create_user.sql");
    let _stmt = _stmt.replace("$table_fields", &User::sql_table_fields());
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

fn pass_hash(pass: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    argon2.hash_password(pass.as_bytes(), &salt).unwrap().to_string()
}

fn check_pass() -> bool {
    let hash_pass = String::from("$argon2id$v=19$m=19456,t=2,p=1$NzQ1HNQ5txvOPfSDME/ETA$blfLwtnFWM5UDvPmCZj9zd2RwydLgWs/GhBoelXt/pk");
    let parsed_hash = PasswordHash::new(&hash_pass).unwrap();

    match Argon2::default().verify_password(b"Topparol754", &parsed_hash) {
        Ok(_) => true,
        Err(_) => false,
    }
}
