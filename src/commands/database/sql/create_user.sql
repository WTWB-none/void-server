INSERT INTO void_server.users(id, username, created_at)
VALUES ($1, $2, $3)
RETURNING id, username, created_at;