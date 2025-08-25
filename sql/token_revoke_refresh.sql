UPDATE void_server.refresh_tokens
      SET revoked_at = now()
      WHERE jti = $1 AND user_id = $2
        AND revoked_at IS NULL
        AND to_timestamp(expires_at::bigint) > now()
      RETURNING jti;