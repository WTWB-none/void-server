use actix_web::{get, post, web, HttpResponse, Error};
use actix_web::http::header;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use std::net::IpAddr;
use crate::commands::auth::jwt::{JwtKeys, Claims, sign, verify};
use argon2::{Algorithm, Argon2, PasswordHash, PasswordVerifier, Params, Version};


#[derive(Deserialize)] struct LoginBody { username: String, password: String }
#[derive(Serialize)] struct TokenPair { access: String, refresh: String }
#[derive(Deserialize)] struct RefreshBody { refresh: String }

const SQL_GET_USER_BY_USERNAME: &str = include_str!("../../../sql/get_user_by_username.sql");
const SQL_GET_USER_BY_ID: &str       = include_str!("../../../sql/get_user_by_id.sql");
const SQL_REFRESH_INSERT: &str = include_str!("../../../sql/insert_refresh_tokens.sql");
const SQL_REFRESH_EXISTS_VALID: &str = include_str!("../../../sql/insert_if_need_refresh_token.sql");
const SQL_REFRESH_REVOKE: &str = include_str!("../../../sql/refresh_token.sql");
const SQL_REFRESH_REVOKE_ACTIVE: &str = include_str!("../../../sql/token_revoke_refresh.sql");

fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed = PasswordHash::new(hash).map_err(actix_web::error::ErrorInternalServerError)?;
    let params = Params::new(19 * 1024, 2, 1, None).map_err(actix_web::error::ErrorInternalServerError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

#[post("/login")]
async fn login(
    db_pool: web::Data<Pool>,
    jwt: web::Data<Arc<JwtKeys>>,
    body: web::Json<LoginBody>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let client = db_pool.get().await.map_err(actix_web::error::ErrorInternalServerError)?;
    
    let row = client.query_one(SQL_GET_USER_BY_USERNAME, &[&body.username]).await
    .map_err(|e| {
        log::error!("Database error: {}", e);
        if e.to_string().contains("no rows returned") {
            actix_web::error::ErrorUnauthorized("Invalid credentials")
        } else {
            actix_web::error::ErrorInternalServerError("Database error")
        }
    })?;

    let user_id: Uuid = row.get("id");
    let hash_pass: String = row.get("hash_pass");
    let is_admin: bool = row.get("is_admin");
    let is_active: bool = row.try_get("is_active").unwrap_or(true);
    let token_version: i32 = row.try_get("token_version").unwrap_or(0);

    if !is_active {
        return Ok(HttpResponse::Forbidden().json("User account is disabled"));
    }

    if !verify_password(&body.password, &hash_pass)? {
        return Ok(HttpResponse::Unauthorized().json("Invalid credentials"));
    }

    let now = OffsetDateTime::now_utc();

    let access_claims = Claims {
        iss: jwt.issuer.clone(),
        aud: jwt.audience.clone(),
        sub: user_id,
        is_admin,
        token_version,
        iat: now.unix_timestamp(),
        exp: (now + jwt.access_ttl).unix_timestamp(),
        jti: Uuid::new_v4(),
    };
    let access_token = sign(&access_claims, &jwt);

    let refresh_jti = Uuid::new_v4();
    let refresh_claims = Claims {
        iss: jwt.issuer.clone(),
        aud: jwt.audience.clone(),
        sub: user_id,
        is_admin,
        token_version,
        iat: now.unix_timestamp(),
        exp: (now + jwt.refresh_ttl).unix_timestamp(),
        jti: refresh_jti,
    };
    let refresh_token = sign(&refresh_claims, &jwt);

    let ua = req.headers().get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
        
    let ip_addr: Option<IpAddr> = req.peer_addr()
        .map(|socket_addr| socket_addr.ip());

    let expires_at = now + jwt.refresh_ttl;

    let expires_at_timestamp = expires_at.unix_timestamp();

    client.execute(SQL_REFRESH_INSERT, &[
        &refresh_jti, 
        &user_id, 
        &expires_at_timestamp.to_string(), 
        &ua, 
        &ip_addr
    ]).await.map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(TokenPair {
        access: access_token,
        refresh: refresh_token,
    }))
}

#[post("/refresh")]
async fn refresh(
    db_pool: web::Data<Pool>,
    jwt: web::Data<Arc<JwtKeys>>,
    body: web::Json<RefreshBody>,
) -> Result<HttpResponse, Error> {
    let claims = verify(&body.refresh, &jwt)?;
    let mut client = db_pool.get().await.map_err(actix_web::error::ErrorInternalServerError)?;

    let row = client
        .query_opt(SQL_GET_USER_BY_ID, &[&claims.sub])
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let row = match row { Some(r) => r, None => return Ok(HttpResponse::Unauthorized().finish()) };
    let is_active: bool = row.try_get("is_active").unwrap_or(true);
    let token_version_db: i32 = row.try_get("token_version").unwrap_or(0);
    let is_admin: bool = row.try_get("is_admin").unwrap_or(false);
    if !is_active || token_version_db != claims.token_version {
        return Ok(HttpResponse::Unauthorized().finish());
    }

    let now = OffsetDateTime::now_utc();
    let new_access_claims = Claims {
        iss: jwt.issuer.clone(),
        aud: jwt.audience.clone(),
        sub: claims.sub,
        is_admin,
        token_version: token_version_db,
        iat: now.unix_timestamp(),
        exp: (now + jwt.access_ttl).unix_timestamp(),
        jti: Uuid::new_v4(),
    };
    let access_token = sign(&new_access_claims, &jwt);

    let new_refresh_jti = Uuid::new_v4();
    let new_refresh_claims = Claims {
        iss: jwt.issuer.clone(),
        aud: jwt.audience.clone(),
        sub: claims.sub,
        is_admin,
        token_version: token_version_db,
        iat: now.unix_timestamp(),
        exp: (now + jwt.refresh_ttl).unix_timestamp(),
        jti: new_refresh_jti,
    };
    let refresh_token = sign(&new_refresh_claims, &jwt);
    let expires_at_ts = (now + jwt.refresh_ttl).unix_timestamp();
    
    // Ротация refresh в одной транзакции
    let transaction = client.build_transaction().start().await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let revoked = transaction
        .query_opt(SQL_REFRESH_REVOKE_ACTIVE, &[&claims.jti, &claims.sub])
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;
    if revoked.is_none() {
        transaction.rollback().await.ok();
        return Ok(HttpResponse::Unauthorized().finish());
    }

    transaction.execute(
        SQL_REFRESH_INSERT,
        &[&new_refresh_jti, &claims.sub, &expires_at_ts.to_string(), &None::<String>, &None::<std::net::IpAddr>],
    )
    .await
    .map_err(actix_web::error::ErrorInternalServerError)?;

    transaction.commit()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;


    Ok(HttpResponse::Ok().json(serde_json::json!({ "access": access_token, "refresh": refresh_token })))
}

#[post("/logout")]
async fn logout(
    db_pool: web::Data<Pool>,
    jwt: web::Data<Arc<JwtKeys>>,
    body: web::Json<RefreshBody>,
) -> Result<HttpResponse, Error> {
    let claims = verify(&body.refresh, &jwt)?;
    let client = db_pool.get().await.map_err(actix_web::error::ErrorInternalServerError)?;

    let row = client
        .query_opt(SQL_REFRESH_REVOKE_ACTIVE, &[&claims.jti, &claims.sub])
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    if row.is_none() {
        return Ok(HttpResponse::Unauthorized().json("Invalid or inactive refresh token"));
    }
    Ok(HttpResponse::Ok().finish())
}
