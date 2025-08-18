use serde::{Deserialize, Serialize};
use tokio_pg_mapper_derive::PostgresMapper;
use uuid::Uuid;
use postgres_types::{FromSql, ToSql, IsNull};
use postgres_types::accepts;
use postgres_types::to_sql_checked;
use std::error::Error;
use std::fmt;



#[derive(Debug, Clone, PartialEq)]
pub struct InvalidRoleError(String);

impl fmt::Display for InvalidRoleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid role value: {}", self.0)
    }
}

impl Error for InvalidRoleError {}

#[derive(Debug, Deserialize, PostgresMapper, Serialize)]
#[pg_mapper(table = "users")]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub hash_pass: String,
    #[serde(skip_deserializing)]
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
    pub role: GroupRole,
    #[serde(skip_deserializing)]
    pub joined_at: String,
}

#[derive(Debug, Serialize, Deserialize, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum GroupRole {
    Owner,
    Admin,
    Moderator,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString, strum::EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum Permission {
    DeleteGroup,
    AddMember,
    ChangeRole,
    DeleteMember,
    CreateFile,
    DeleteFile,
    ChangeFile,
    ReadFile,
}

impl<'a> FromSql<'a> for GroupRole {
    fn from_sql(ty: &postgres_types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        let s = <&str as FromSql>::from_sql(ty, raw)?;
        match s {
            "owner" => Ok(GroupRole::Owner),
            "admin" => Ok(GroupRole::Admin),
            "moderator" => Ok(GroupRole::Moderator),
            "user" => Ok(GroupRole::User),
            _ => Err(Box::new(InvalidRoleError(s.to_string()))),
        }
    }

    accepts!(TEXT, VARCHAR);
}

impl ToSql for GroupRole {
    fn to_sql(
        &self,
        ty: &postgres_types::Type,
        out: &mut postgres_types::private::BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.as_str().to_sql(ty, out)
    }

    accepts!(TEXT, VARCHAR);
    to_sql_checked!();
}


impl GroupRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            GroupRole::Owner => "owner",
            GroupRole::Admin => "admin",
            GroupRole::Moderator => "moderator",
            GroupRole::User => "user",
        }
    }

    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            GroupRole::Owner => vec![
                Permission::DeleteGroup,
                Permission::AddMember,
                Permission::ChangeRole,
                Permission::DeleteMember,
                Permission::CreateFile,
                Permission::DeleteFile,
                Permission::ChangeFile,
                Permission::ReadFile,
            ],
            GroupRole::Admin => vec![
                Permission::AddMember,
                Permission::ChangeRole,
                Permission::DeleteMember,
                Permission::CreateFile,
                Permission::DeleteFile,
                Permission::ChangeFile,
                Permission::ReadFile,
            ],
            GroupRole::Moderator => vec![
                Permission::CreateFile,
                Permission::DeleteFile,
                Permission::ChangeFile,
                Permission::ReadFile,
            ],
            GroupRole::User => vec![
                Permission::ReadFile,
            ],
        }
    }

    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }

    pub fn can_remove(&self, target_role: &GroupRole) -> bool {
        match target_role.has_permission(Permission::DeleteMember) {
            true => match self {
                GroupRole::Owner => {
                    !matches!(target_role, GroupRole::Owner)
                }
                GroupRole::Admin => {
                    matches!(target_role, GroupRole::Moderator | GroupRole::User)
                }
                GroupRole::Moderator => false,
                GroupRole::User => false,
                            }
            false => false
        } 
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn check_group_role() {
        assert_eq!(true, GroupRole::Owner.can_remove(&GroupRole::Owner));
        assert_eq!(true, GroupRole::Moderator.can_remove(&GroupRole::Owner));
        assert_eq!(true, GroupRole::Moderator.can_remove(&GroupRole::Moderator));
    }
}
