use serde::{Deserialize, Serialize};
use tokio_pg_mapper_derive::PostgresMapper;
use uuid::Uuid;
use strum_macros::{Display, EnumString};

#[derive(Debug, Deserialize, PostgresMapper, Serialize)]
#[pg_mapper(table = "users")]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub hash_pass: String,
    pub is_admin: bool,
    #[serde(skip_deserializing)]
    pub created_at: String, 
}

#[derive(Debug, Deserialize, PostgresMapper, Serialize)]
#[pg_mapper(table = "group")]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_by: Uuid,
    #[serde(skip_deserializing)]
    pub created_at: String, 
}

#[derive(Debug, Deserialize, PostgresMapper, Serialize)]
#[pg_mapper(table = "group_member")]
pub struct GroupMember {
    pub user_id: Uuid,
    pub group_id: Uuid,
    pub role: String,
    #[serde(skip_deserializing)]
    pub joined_at: String,
}

#[derive(Debug, Serialize, Deserialize, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum GroupRole {
    Owner(String),
    Admin(String),
    Moderator(String),
    User(String),
}