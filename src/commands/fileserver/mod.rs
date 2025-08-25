// src/commands/fileserver/mod.rs
use actix_files::NamedFile;
use actix_web::{get, web, HttpRequest, HttpResponse};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const STATIC_DIR: &str = "./static";

fn safe_join(root: &Path, tail: &str) -> Option<PathBuf> {
    let mut out = PathBuf::from(root);
    for part in Path::new(tail) {
        let s = part.to_string_lossy();
        if s.is_empty() || s == "." || s == ".." { continue; }
        if s.contains(':') { return None; }
        out.push(s.as_ref());
    }
    Some(out)
}

#[get("/file/{tail:.*}")]
pub async fn file_get(req: HttpRequest, tail: web::Path<String>) -> HttpResponse {
    let base = PathBuf::from(STATIC_DIR);
    let target = match safe_join(&base, &tail.into_inner()) { Some(p) => p, None => return HttpResponse::BadRequest().finish() };
    match NamedFile::open_async(target).await {
        Ok(f) => f.use_last_modified(true).prefer_utf8(false).into_response(&req),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[get("/manifest")]
pub async fn manifest() -> HttpResponse {
    let base = PathBuf::from(STATIC_DIR);
    if !base.exists() { return HttpResponse::NotFound().finish(); }
    let files: Vec<String> = WalkDir::new(&base)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.path().strip_prefix(&base).ok().map(|p| p.to_string_lossy().replace('\\', "/")))
        .collect();
    HttpResponse::Ok().json(files)
}


/*
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
*/


#[get("/downloader")]
pub async fn downloader_page() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(r###"<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>Void Downloader</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font:16px/1.4 system-ui,Segoe UI,Roboto,Arial;margin:24px}
    input,button{font:inherit;padding:6px 10px}
    #log{white-space:pre-wrap;background:#111;color:#ddd;padding:10px;border-radius:8px;max-height:40vh;overflow:auto}
  </style>
</head>
<body>
  <h1>Скачивание файлов по списку</h1>
  <div>
    Префикс API:
    <input id="prefix" value="" placeholder="/fs (если есть префикс)">
    Параллельно:
    <input id="conc" type="number" value="8" min="1" max="64">
    <button id="go">Скачать всё</button>
  </div>
  <p>Открой DevTools → Network, чтобы видеть параллельные загрузки.</p>
  <div id="log"></div>
  <script src="assets/downloader.js"></script>
</body></html>
"###)
}

#[get("/assets/downloader.js")]
pub async fn downloader_js() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/javascript; charset=utf-8")
        .body(r###"const $=s=>document.querySelector(s);function log(m){const el=$("#log");el.textContent+=m+"\n";el.scrollTop=el.scrollHeight}async function getManifest(prefix){const r=await fetch((prefix||"")+"/manifest");if(!r.ok)throw new Error("manifest HTTP "+r.status);return await r.json()}function downloadOne(prefix,p){const a=document.createElement("a");a.href=(prefix||"")+"/file/"+encodeURI(p);a.download=p.split("/").pop()||"file";document.body.appendChild(a);a.click();a.remove()}async function run(){const prefix=$("#prefix").value.trim();const conc=Math.max(1,Math.min(64,Number($("#conc").value)||8));log("Loading manifest...");const paths=await getManifest(prefix);log("Files: "+paths.length+"  Concurrency: "+conc);let i=0,active=0;function pump(){while(active<conc&&i<paths.length){const p=paths[i++];active++;try{downloadOne(prefix,p)}catch(e){log("error: "+p+" -> "+e)}active--;log("start: "+i+"/"+paths.length+" ("+p+")")}if(i>=paths.length&&active===0){log("DONE")}else{requestAnimationFrame(pump)}}pump()}window.addEventListener("DOMContentLoaded",function(){document.querySelector("#go").addEventListener("click",function(){document.querySelector("#log").textContent="";run().catch(function(e){log("FATAL: "+e)})})});"###)
}

