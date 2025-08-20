INSERT INTO void_server.group_member(user_id, group_id, role, joined_at)
VALUES ($1, $2, $3, $4)
RETURNING user_id, group_id, role, joined_at;