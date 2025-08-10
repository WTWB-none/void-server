use serde::{Deserialize, Serialize};
use tokio_pg_mapper_derive::PostgresMapper;
use uuid::Uuid;

#[derive(Debug, Deserialize, PostgresMapper, Serialize)]
#[pg_mapper(table = "users")]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_deserializing)]
    pub created_at: String, 
}