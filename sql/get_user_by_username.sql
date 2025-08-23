SELECT id, hash_pass, is_admin, is_active, token_version 
FROM void_server.users 
WHERE username = $1;