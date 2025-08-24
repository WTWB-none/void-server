use confik::Configuration;
use serde::Deserialize;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use time::Duration;
use std::sync::Arc;

use crate::commands::JwtKeys;

#[derive(Debug, Default, Configuration)]
pub struct ExampleConfig {
    pub server_addr: String,
    pub allowed_origins: Option<String>,
    pub show_dir_listing: Option<String>,

    pub jwt_alg: String,
    pub jwt_secret: Option<String>,
    pub jwt_private_pem: Option<String>,
    pub jwt_public_pem: Option<String>,
    pub jwt_iss: String,
    pub jwt_aud: String,
    pub jwt_access_ttl_secs: i64,
    pub jwt_refresh_ttl_secs: i64,
    
    #[confik(from = DbConfig)]
    pub pg: deadpool_postgres::Config,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct DbConfig(deadpool_postgres::Config);

impl From<DbConfig> for deadpool_postgres::Config {
    fn from(value: DbConfig) -> Self {
        value.0
    }
}

impl confik::Configuration for DbConfig {
    type Builder = Option<Self>;
}


pub type JwtState = Arc<JwtKeys>;

impl ExampleConfig {
    pub fn init_jwt(&self) -> Result<JwtState, String> {
        let alg = match self.jwt_alg.as_str() {
            "RS256" => Algorithm::RS256,
            _ => Algorithm::HS256,
        };

        let (enc, dec) = match alg {
            Algorithm::HS256 => {
                let secret = self.jwt_secret.as_ref().ok_or("JWT_SECRET required")?;
                (
                    EncodingKey::from_secret(secret.as_bytes()),
                    DecodingKey::from_secret(secret.as_bytes()),
                )
            }
            Algorithm::RS256 => {
                let private_pem = self.jwt_private_pem.as_ref().ok_or("RSA_PRIVATE_KEY_PEM required")?;
                let public_pem = self.jwt_public_pem.as_ref().ok_or("RSA_PUBLIC_KEY_PEM required")?;
                (
                    EncodingKey::from_rsa_pem(private_pem.as_bytes()).map_err(|e| e.to_string())?,
                    DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(|e| e.to_string())?,
                )
            }
            _ => return Err("Unsupported algorithm".into()),
        };

        let keys = JwtKeys {
            alg,
            enc,
            dec,
            issuer: self.jwt_iss.clone(),
            audience: self.jwt_aud.clone(),
            access_ttl: Duration::seconds(self.jwt_access_ttl_secs),
            refresh_ttl: Duration::seconds(self.jwt_refresh_ttl_secs),
        };

        Ok(Arc::new(keys))
    }
}