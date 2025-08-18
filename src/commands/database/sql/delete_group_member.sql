DELETE FROM void_server.group_member
WHERE user_id = $1 AND group_id = $2
RETURNING user_id, group_id, role, joined_at;