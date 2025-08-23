SELECT 1
FROM void_server.refresh_tokens
WHERE jti = $1 AND user_id = $2
  AND revoked_at IS NULL
  AND to_timestamp(expires_at::bigint) > now();