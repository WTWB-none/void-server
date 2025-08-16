INSERT INTO void_server.users(id, username, hash_pass, is_admin, created_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, username, hash_pass, is_admin, created_at;