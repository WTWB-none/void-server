use actix_web::{error, Error};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;



#[derive(Clone)]
pub struct JwtKeys {
    pub alg: Algorithm,
    pub enc: EncodingKey,
    pub dec: DecodingKey,
    pub issuer: String,
    pub audience: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

impl Default for Role { fn default() -> Self { Role::User } }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub is_admin: bool,
    pub token_version: i32,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}

pub fn sign(claims: &Claims, keys: &JwtKeys) -> String {
    let mut header = Header::new(keys.alg);
    header.kid = Some("v1".into());
    jsonwebtoken::encode(&header, claims, &keys.enc).expect("sign jwt")
}

pub fn verify(token: &str, keys: &JwtKeys) -> Result<Claims, Error> {
    let mut validation = Validation::new(keys.alg);
    validation.set_audience(&[&keys.audience]);
    validation.set_issuer(&[&keys.issuer]);
    validation.validate_exp = true;
    validation.leeway = 10;

    jsonwebtoken::decode::<Claims>(token, &keys.dec, &validation)
        .map(|data| data.claims)
        .map_err(|_| error::ErrorUnauthorized("invalid_token"))
}