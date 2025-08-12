use actix_web::{get, HttpResponse, http::header, error::ResponseError};
use futures::{channel::mpsc::{channel, Sender}, SinkExt};
use serde::{Serialize, Deserialize};
use std::fs::{self, File, metadata};
use std::io::{self, Read, Write};
use std::path::Path;
use std::thread;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;
use sha2::{Digest, Sha256};
use actix_web::web::Bytes;
use tar::Builder;
use rayon::prelude::*;
use super::StreamError;

const STATIC_DIR: &str = "./static";
const MANIFEST_CACHE: &str = "./manifest_cache.json";
const MAX_ZIP_SIZE: u64 = 1_000_000_000;

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    path: String,
    mtime: u64,
    size: u64,
    hash: String,
}

fn dir_size(path: &Path) -> u64 {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

struct ChannelWriter<'a> {
    sender: &'a mut Sender<Result<Bytes, StreamError>>,
}

impl<'a> Write for ChannelWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = Bytes::copy_from_slice(buf);
        futures::executor::block_on(self.sender.send(Ok(bytes)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[get("/download-stream")]
async fn download_stream() -> HttpResponse {
    let dir_path = Path::new(STATIC_DIR);
    let total_size = dir_size(dir_path);
    if total_size > MAX_ZIP_SIZE {
        return HttpResponse::PayloadTooLarge().body("Directory too large for full download. Use /manifest and download individual files via /file/{path}.");
    }

    let (mut tx, rx) = channel::<Result<Bytes, StreamError>>(100);

    thread::spawn(move || {
        let mut errors = Vec::new();
        {
            let mut tar_builder = Builder::new(ChannelWriter { sender: &mut tx });

            for entry in WalkDir::new(STATIC_DIR).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                let rel_path = match path.strip_prefix(STATIC_DIR) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if path.is_file() {
                    let mut file = match File::open(path) {
                        Ok(f) => f,
                        Err(e) => {
                            errors.push(StreamError { message: e.to_string() });
                            continue;
                        }
                    };

                    if let Err(e) = tar_builder.append_file(rel_path, &mut file) {
                        errors.push(StreamError { message: e.to_string() });
                        continue;
                    }
                } else if path.is_dir() {
                    if let Err(e) = tar_builder.append_dir(rel_path, path) {
                        errors.push(StreamError { message: e.to_string() });
                        continue;
                    }
                }
            }
        }

        for error in errors {
            let _ = tx.try_send(Err(error));
        }
    });

    HttpResponse::Ok()
        .content_type("application/x-tar")
        .append_header((header::CONTENT_DISPOSITION, "attachment; filename=\"static.tar\""))
        .streaming(rx)
}

#[get("/manifest")]
async fn get_manifest() -> HttpResponse {
    if let Ok(cache_file) = File::open(MANIFEST_CACHE) {
        if let Ok(cache_meta) = metadata(MANIFEST_CACHE) {
            let dir_meta = match metadata(STATIC_DIR) {
                Ok(m) => m,
                Err(_) => return HttpResponse::InternalServerError().body("Dir not found"),
            };

            if cache_meta.modified().unwrap() > dir_meta.modified().unwrap() {
                let mut content = String::new();
                let mut file = cache_file;
                if file.read_to_string(&mut content).is_ok() {
                    return HttpResponse::Ok().json(serde_json::from_str::<Vec<FileMetadata>>(&content).unwrap_or_default());
                }
            }
        }
    }

    let entries: Vec<_> = WalkDir::new(STATIC_DIR)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    let files: Vec<FileMetadata> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let rel_path = path.strip_prefix(STATIC_DIR).ok()?.to_str()?.to_string();
            let meta = fs::metadata(path).ok()?;
            let mtime = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
            let size = meta.len();
            let mut file = File::open(path).ok()?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).ok()?;
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            let hash = format!("{:x}", hasher.finalize());
            Some(FileMetadata { path: rel_path, mtime, size, hash })
        })
        .collect();

    if let Ok(json) = serde_json::to_string(&files) {
        let _ = fs::write(MANIFEST_CACHE, json);
    }

    HttpResponse::Ok().json(files)
}
