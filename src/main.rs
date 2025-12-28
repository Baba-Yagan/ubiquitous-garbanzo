use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html",
        "js" => "application/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn sanitize(root: &Path, req_path: &str) -> PathBuf {
    let p = PathBuf::from(root);
    let rel = req_path
        .split('?')
        .next()
        .unwrap_or("/")
        .trim_start_matches('/');
    let candidate = p.join(rel);
    if candidate.exists() {
        candidate
    } else {
        p.join("intercept")
    }
}

fn find_free(addr_base: &str, start_port: u16, max_tries: u16) -> Option<String> {
    for i in 0..max_tries {
        let port = start_port.wrapping_add(i);
        let addr = format!("{}:{}", addr_base, port);
        // try bind with short timeout by setting REUSEADDR not needed; just attempt bind
        if TcpListener::bind(&addr).is_ok() {
            return Some(addr);
        }
    }
    None
}

fn main() -> std::io::Result<()> {
    // preferred host and start port can come from env or args
    let host = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0".into());
    let start_port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let max_tries: u16 = 100;

    // Add a root directory (third arg) — default to current directory
    let root = std::env::args()
        .nth(3)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current dir"));

    // find a free port on host starting from start_port
    let addr = find_free(&host, start_port, max_tries).expect("no free port found");
    // Bind for real now (we know bind succeeded earlier but that socket was dropped; re-bind)
    let listener = TcpListener::bind(&addr)?;
    // Print chosen address so bash can capture it
    println!("{}", addr);

    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            let mut buf = [0; 1024];
            if s.read(&mut buf).is_ok() {
                let req = String::from_utf8_lossy(&buf);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");

                if path == "/" {
                    let loc = "/intercept";
                    let hdr = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        loc
                    );
                    let _ = s.write_all(hdr.as_bytes());
                    continue;
                }

                let file_path = sanitize(&root, path);
                match fs::read(&file_path) {
                    Ok(body) => {
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                            mime(&file_path)
                        );
                        let _ = s.write_all(hdr.as_bytes());
                        let _ = s.write_all(&body);
                    }
                    Err(_) => {
                        let notf = b"404 Not Found";
                        let hdr = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            notf.len()
                        );
                        let _ = s.write_all(hdr.as_bytes());
                        let _ = s.write_all(notf);
                    }
                }
            }
        }
    }
    Ok(())
}
