use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;
use chrono::Utc;
use tokio_postgres::types::ToSql;
use super::{User, MyError};

pub async fn create_user(client: &Client, user_info: User) -> Result<User, MyError> {
    let _stmt = include_str!("../sql/create_user.sql");
    let _stmt = _stmt.replace("$table_fields", &User::sql_table_fields());
    let stmt = client.prepare(&_stmt).await?;  // Убрал unwrap() в пользу ?

    let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    client
        .query(
            &stmt,
            &[
                &user_info.id as &(dyn ToSql + Sync),
                &user_info.username,
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