UPDATE void_server.refresh_tokens
SET revoked_at = now()
WHERE jti = $1 AND revoked_at IS NULL;