use actix_web::{dev::ServiceRequest, error, http::header, web, Error, FromRequest, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc};
use time::{Duration, OffsetDateTime};
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

pub type JwtState = Arc<JwtKeys>;

pub struct JwtSettings {
    pub alg: String, 
    pub secret: Option<String>,
    pub private_pem: Option<String>,
    pub public_pem: Option<String>,
    pub iss: String,
    pub aud: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
}

impl JwtKeys {
    pub fn from_env() -> Self {
        use std::env::var;

        let alg = match var("JWT_ALG").unwrap_or_else(|_| "HS256".into()).as_str() {
            "RS256" => Algorithm::RS256,
            _ => Algorithm::HS256,
        };

        // HS256 через секрет или RS256 через PEM
        let (enc, dec) = match alg {
            Algorithm::HS256 => {
                let secret = var("JWT_SECRET").expect("JWT_SECRET required");
                (EncodingKey::from_secret(secret.as_bytes()), DecodingKey::from_secret(secret.as_bytes()))
            }
            Algorithm::RS256 => {
                let private_pem = var("RSA_PRIVATE_KEY_PEM").expect("RSA_PRIVATE_KEY_PEM required");
                let public_pem  = var("RSA_PUBLIC_KEY_PEM").expect("RSA_PUBLIC_KEY_PEM required");
                (EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("bad RSA private key"),
                 DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("bad RSA public key"))
            }
            _ => panic!("Unsupported alg"),
        };

        let issuer   = var("JWT_ISS").unwrap_or_else(|_| "void-server".into());
        let audience = var("JWT_AUD").unwrap_or_else(|_| "void-client".into());

        let access_ttl  = Duration::seconds(var("JWT_ACCESS_TTL_SECS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(900));
        let refresh_ttl = Duration::seconds(var("JWT_REFRESH_TTL_SECS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(14 * 24 * 3600));

        Self { alg, enc, dec, issuer, audience, access_ttl, refresh_ttl }
    }
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

impl Claims {
    // Обновите методы new_access и new_refresh
    pub fn new_access(user_id: Uuid, is_admin: bool, token_version: i32, keys: &JwtKeys) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp = now + keys.access_ttl;
        Self {
            iss: keys.issuer.clone(),
            aud: keys.audience.clone(),
            sub: user_id,
            is_admin,
            token_version,
            iat: now.unix_timestamp(),
            exp: exp.unix_timestamp(),
            jti: Uuid::new_v4(),
        }
    }

    pub fn new_refresh(user_id: Uuid, is_admin: bool, token_version: i32, role: Role, keys: &JwtKeys) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp = now + keys.refresh_ttl;
        Self {
            iss: keys.issuer.clone(),
            aud: keys.audience.clone(),
            sub: user_id,
            is_admin,
            token_version,
            iat: now.unix_timestamp(),
            exp: exp.unix_timestamp(),
            jti: Uuid::new_v4(),
        }
    }
}

pub fn sign(claims: &Claims, keys: &JwtKeys) -> String {
    let mut header = Header::new(keys.alg);
    header.kid = Some("v1".into()); // на будущее под ротацию ключей
    jsonwebtoken::encode(&header, claims, &keys.enc).expect("sign jwt")
}

pub fn verify(token: &str, keys: &JwtKeys) -> Result<Claims, Error> {
    let mut validation = Validation::new(keys.alg);
    validation.set_audience(&[&keys.audience]);
    validation.set_issuer(&[&keys.issuer]);
    validation.validate_exp = true;
    validation.leeway = 10; // сек на рассинхрон часов

    jsonwebtoken::decode::<Claims>(token, &keys.dec, &validation)
        .map(|data| data.claims)
        .map_err(|_| error::ErrorUnauthorized("invalid_token"))
}

/// Extractor, чтобы в хендлерах получать авторизованного пользователя
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub Claims);

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let keys = req.app_data::<web::Data<JwtState>>().cloned();
        let auth = BearerAuth::extract(req);

        Box::pin(async move {
            let keys = keys.ok_or_else( ||error::ErrorInternalServerError("missing JwtState"))?;
            let auth = auth.await.map_err(|_| error::ErrorUnauthorized("no_token"))?;
            let claims = verify(auth.token(), &keys)?;
            Ok(AuthenticatedUser(claims))
        })
    }
}

/// Middleware‑валидатор для scope‑ов
/// Middleware‑валидатор для scope‑ов
pub async fn bearer_validator(
    req: ServiceRequest, 
    credentials: BearerAuth
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let keys = match req.app_data::<web::Data<JwtState>>() {
        Some(keys) => keys.clone(),
        None => {
            return Err((
                error::ErrorInternalServerError("missing JwtState"),
                req,
            ))
        }
    };

    match verify(credentials.token(), &keys) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(e) => {
            // Логируем ошибку, если нужно
            log::error!("JWT validation error: {}", e);
            Err((e, req))
        }
    }
}

pub fn require_role(user: &AuthenticatedUser, need: Role) -> Result<(), Error> {
    use Role::*;
    let user_role = if user.0.is_admin { Admin } else { User };
    match (user_role, need) {
        (Admin, _) => Ok(()),
        (User, User) => Ok(()),
        _ => Err(error::ErrorForbidden("forbidden")),
    }
}