use actix_web::{HttpResponse, ResponseError};
use deadpool_postgres::PoolError;
use derive_more::{Display, Error, From};
use tokio_pg_mapper::Error as PGMError;
use tokio_postgres::error::Error as PGError;

#[derive(Debug, Display, Error, From)]
pub enum MyError {
    NotFound,
    PermissionDenied,
    PGError(PGError),
    PGMError(PGMError),
    PoolError(PoolError),
}

#[derive(Debug, Error, From)]
pub struct StreamError {
    pub message: String,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for StreamError {
    fn error_response(&self) -> HttpResponse {
        match self {
            StreamError => {
                HttpResponse::InternalServerError().body(self.message.clone())
            }
        }
    }
}


impl ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            MyError::NotFound => HttpResponse::NotFound().finish(),
            MyError::PoolError(ref err) => {
                HttpResponse::InternalServerError().body(err.to_string())
            }
            _ => HttpResponse::InternalServerError().finish(),
        }
    }
}