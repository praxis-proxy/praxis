// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Bounded, staged HTTP/1.1 exchanges for Expect conformance tests.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::mpsc::{self, Receiver},
    time::Duration,
};

/// Result observed by the controlled backend for the unique upload path.
pub(super) struct UploadBackend {
    /// Bound port for the proxy's upstream endpoint.
    port: u16,
    result: Receiver<Result<Vec<u8>, String>>,
}

impl UploadBackend {
    /// Return the bound upstream port.
    pub(super) fn port(&self) -> u16 {
        self.port
    }

    /// Await the unique upload and propagate fixture failures.
    pub(super) fn finish(self) -> Vec<u8> {
        self.result
            .recv_timeout(Duration::from_secs(5))
            .expect("backend did not observe the upload")
            .expect("backend exchange failed")
    }
}

/// Start a backend that sends 100 and records the body, or rejects with 417.
pub(super) fn start_upload_backend(path: &'static str, reject: bool) -> UploadBackend {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    let (sender, result) = mpsc::channel();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    let _send_result = sender.send(Err(error.to_string()));
                    break;
                },
            };
            let outcome = handle_backend(&mut stream, path, reject);
            if let Some(outcome) = outcome {
                let _send_result = sender.send(outcome);
                break;
            }
        }
    });
    UploadBackend { port, result }
}

/// Handle readiness separately from the unique POST test exchange.
fn handle_backend(stream: &mut TcpStream, path: &str, reject: bool) -> Option<Result<Vec<u8>, String>> {
    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
        return Some(Err(error.to_string()));
    }
    if let Err(error) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
        return Some(Err(error.to_string()));
    }
    let request = match read_head(stream) {
        Ok(request) => request,
        Err(error) => return Some(Err(error)),
    };
    if !request.starts_with(&format!("POST {path} HTTP/1.1")) {
        if let Err(error) = write_response(stream, 200, "ready") {
            return Some(Err(error));
        }
        return None;
    }
    Some(if reject {
        reject_upload(stream)
    } else {
        receive_upload(stream, &request)
    })
}

/// Send 100 before reading exactly the declared upload length.
fn receive_upload(stream: &mut TcpStream, request: &str) -> Result<Vec<u8>, String> {
    let length = content_length(request)?;
    stream
        .write_all(b"HTTP/1.1 100 Continue\r\nX-Upstream-Interim: yes\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body).map_err(|error| error.to_string())?;
    write_response(stream, 200, "upload-ok")?;
    Ok(body)
}

/// Reject before reading an upload and record any body bytes sent anyway.
fn reject_upload(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    write_response(stream, 417, "expectation-rejected")?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|error| error.to_string())?;
    let mut body = [0_u8; 256];
    match stream.read(&mut body) {
        Ok(count) => Ok(body[..count].to_vec()),
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(Vec::new())
        },
        Err(error) => Err(error.to_string()),
    }
}

/// Write one final response with an exact content length.
fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
    let reason = if status == 417 { "Expectation Failed" } else { "OK" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).map_err(|error| error.to_string())
}

/// Read a bounded HTTP head one byte at a time, retaining no hidden payload.
fn read_head(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    while bytes.len() < 16_384 {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte).map_err(|error| error.to_string())?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|error| error.to_string());
        }
    }
    Err("HTTP head exceeded 16 KiB".to_owned())
}

/// Parse one Content-Length field from a response or request head.
fn content_length(head: &str) -> Result<usize, String> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or_else(|| "missing Content-Length".to_owned())?
        .1
        .trim()
        .parse()
        .map_err(|error| format!("bad Content-Length: {error}"))
}

/// Observe a final response after zero or more informational heads.
fn final_response(stream: &mut TcpStream) -> Result<(u16, String, Vec<String>), String> {
    let mut interim = Vec::new();
    loop {
        let head = read_head(stream)?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| "missing HTTP status".to_owned())?
            .parse()
            .map_err(|error| format!("bad HTTP status: {error}"))?;
        if status < 200 {
            interim.push(head);
            continue;
        }
        let mut body = vec![0; content_length(&head)?];
        stream.read_exact(&mut body).map_err(|error| error.to_string())?;
        return Ok((
            status,
            String::from_utf8(body).map_err(|error| error.to_string())?,
            interim,
        ));
    }
}

/// Send headers, await 100, then release the payload in the requested chunks.
pub(super) fn staged_upload(
    addr: &str,
    path: &str,
    body: &[u8],
    chunks: &[usize],
    expect: bool,
) -> (u16, String, Vec<String>) {
    let mut stream = TcpStream::connect(addr).expect("connect staged upload");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let expect_header = if expect { "Expect: 100-continue\r\n" } else { "" };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{expect_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("send upload headers");
    let mut interim = Vec::new();
    if expect {
        let response = read_head(&mut stream).expect("receive 100 before upload");
        assert!(
            response.starts_with("HTTP/1.1 100 "),
            "expected 100 before upload: {response}"
        );
        interim.push(response);
    }
    let mut offset = 0;
    for &size in chunks {
        let end = offset + size;
        stream.write_all(&body[offset..end]).expect("send upload chunk");
        offset = end;
    }
    assert_eq!(offset, body.len(), "chunk lengths must cover upload");
    let (status, response_body, more_interim) = final_response(&mut stream).expect("complete final response");
    interim.extend(more_interim);
    (status, response_body, interim)
}

/// Send only headers and observe the final rejection without releasing a body.
pub(super) fn withheld_upload(addr: &str, path: &str, length: usize) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect rejected upload");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).expect("send rejection headers");
    let (status, body, _) = final_response(&mut stream).expect("complete rejection response");
    (status, body)
}
