INSERT INTO void_server.groups(id, name, description, created_by, created_at)
VALUES ($1, $2, $3, $4, $5)

RETURNING id, name, description, created_by, created_at;