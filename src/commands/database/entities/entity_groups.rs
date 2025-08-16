use std::collections::VecDeque;

use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;
use chrono::Utc;
use tokio_postgres::types::ToSql;
use crate::commands::Group;

use super::MyError;

pub async fn create_group(client: &Client, group_info: Group) -> Result<Group, MyError> {
    let _stmt = include_str!("../sql/create_group.sql");
    let stmt = client.prepare(&_stmt).await?;
    let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    client
        .query(
            &stmt,
            &[
                &group_info.id as &(dyn ToSql + Sync),
                &group_info.name,
                &group_info.description,
                &group_info.created_by,
                &created_at,
            ],
        )
        .await?
        .iter()
        .map(|row| Group::from_row_ref(row).unwrap())
        .collect::<Vec<Group>>()
        .pop()
        .ok_or(MyError::NotFound)
}