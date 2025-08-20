INSERT INTO void_server.refresh_tokens (jti, user_id, issued_at, expires_at, user_agent, ip_addr)
VALUES ($1, $2, now(), $3, $4, $5::inet)
ON CONFLICT (jti) DO NOTHING;