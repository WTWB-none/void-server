use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;
use chrono::Utc;
use tokio_postgres::types::ToSql;
use crate::commands::{Group, GroupMember, GroupRole};
use uuid::Uuid;

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



pub async fn get_user_role(
    client: &Client,
    user_id: Uuid,
    group_id: Uuid,
) -> Result<GroupRole, MyError> {
    let _stmt = include_str!("../sql/get_user_role.sql");
    let stmt = client.prepare(&_stmt).await?;

    let row = client.query_opt(&stmt, &[&user_id, &group_id])
        .await?
        .ok_or(MyError::NotFound)?;

    Ok(row.get("role"))
}

pub async fn create_group_member(client: &Client, group_member_info: GroupMember) -> Result<GroupMember, MyError> {
    let _stmt = include_str!("../sql/create_group_member.sql");
    let stmt = client.prepare(&_stmt).await?;
    let joined_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let role = match group_member_info.role.as_str() {
        "owner" => GroupRole::Owner,
        "admin" => GroupRole::Admin,
        "moderator" => GroupRole::Moderator,
        "user" => GroupRole::User,
        _ => return Err(MyError::NotFound),
    };

    let role_str = match role {
        GroupRole::Owner => "owner",
        GroupRole::Admin => "admin",
        GroupRole::Moderator => "moderator",
        GroupRole::User => "user",
    };

    client
        .query(
            &stmt,
            &[
                &group_member_info.user_id as &(dyn ToSql + Sync),
                &group_member_info.group_id as &(dyn ToSql + Sync),
                &role_str,
                &joined_at,
            ],
        )
        .await?
        .iter()
        .map(|row| GroupMember::from_row_ref(row).unwrap())
        .collect::<Vec<GroupMember>>()
        .pop()
        .ok_or(MyError::NotFound)
}


pub async fn delete_group_member(
    client: &Client,
    delete_who: Uuid,
    delete_by: Uuid,
    group_info: Group,
) -> Result<GroupMember, MyError> {
    let group_id = group_info.id;
    let delete_who_role = get_user_role(client, delete_who, group_id).await.map_err(|e| {
        log::error!("Error get_role user {}", e);
        e
    })?;
    let delete_by_role = get_user_role(client, delete_by, group_id).await.map_err(|e| {
        log::error!("Error get_role user {}", e);
        e
    })?;

    if !delete_by_role.can_remove(&delete_who_role) {
        return Err(MyError::PermissionDenied);
    }

    let _stmt = include_str!("../sql/delete_group_member.sql");
    let stmt = client.prepare(&_stmt).await?;

    client
        .query(
            &stmt,
            &[&delete_who, &group_id] 
        )
        .await?
        .iter()
        .map(|row| GroupMember::from_row_ref(row).unwrap())
        .collect::<Vec<GroupMember>>()
        .pop()
        .ok_or(MyError::NotFound)
}