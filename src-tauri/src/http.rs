//! Loopback-only HTTP client for the local Mihomo controller. No TLS, no
//! system or environment proxy, no redirects, short timeouts. Request and
//! response bodies are never logged or embedded in error texts: a generated
//! config carries proxy credentials.

use std::{net::Ipv4Addr, time::Duration};
use ureq::Agent;

const READ_TIMEOUT: Duration = Duration::from_secs(3);
/// `PUT /configs` returns after Mihomo applied the whole config.
const APPLY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ControllerError {
    /// Nothing answers on the port (or the connection broke).
    Unreachable,
    Timeout,
    Unauthorized,
    Status(u16),
    /// The response body is not what the controller should send.
    Invalid,
    /// Refused locally before any request (not a loopback URL).
    BadRequest,
}

impl ControllerError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Unreachable => "Mihomo не запущен".into(),
            Self::Timeout => "Mihomo не ответил вовремя".into(),
            Self::Unauthorized => "Контроллер Mihomo отклонил ключ доступа".into(),
            Self::Status(code) => format!("Контроллер Mihomo ответил HTTP {code}"),
            Self::Invalid => "Контроллер Mihomo вернул непонятный ответ".into(),
            Self::BadRequest => "Адрес контроллера не на 127.0.0.1".into(),
        }
    }
}

type HttpResult<T> = std::result::Result<T, ControllerError>;

fn agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        // Never inherit HTTP(S)_PROXY / ALL_PROXY: this is loopback traffic.
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .build()
        .into()
}

/// `http://127.0.0.1:<port><path>`, asserting the host really is loopback.
pub(crate) fn loopback_url(port: u16, path: &str) -> HttpResult<String> {
    if port == 0
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['@', '\\', '#'])
        || path.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ControllerError::BadRequest);
    }
    let url = format!("http://127.0.0.1:{port}{path}");
    let parsed = url::Url::parse(&url).map_err(|_| ControllerError::BadRequest)?;
    if parsed.scheme() != "http"
        || parsed.host() != Some(url::Host::Ipv4(Ipv4Addr::LOCALHOST))
        || parsed.port() != Some(port)
    {
        return Err(ControllerError::BadRequest);
    }
    Ok(url)
}

fn map_error(error: ureq::Error) -> ControllerError {
    match error {
        ureq::Error::Timeout(_) => ControllerError::Timeout,
        _ => ControllerError::Unreachable,
    }
}

fn check_status(code: u16) -> HttpResult<()> {
    match code {
        200..=299 => Ok(()),
        401 | 403 => Err(ControllerError::Unauthorized),
        _ => Err(ControllerError::Status(code)),
    }
}

fn bearer(secret: Option<&str>) -> Option<String> {
    secret
        .filter(|secret| !secret.is_empty())
        .map(|secret| format!("Bearer {secret}"))
}

pub(crate) fn get_json(
    port: u16,
    path: &str,
    secret: Option<&str>,
) -> HttpResult<serde_json::Value> {
    let url = loopback_url(port, path)?;
    let mut request = agent(READ_TIMEOUT).get(&url);
    if let Some(value) = bearer(secret) {
        request = request.header("Authorization", value);
    }
    let mut response = request.call().map_err(map_error)?;
    check_status(response.status().as_u16())?;
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| ControllerError::Invalid)?;
    serde_json::from_str(&body).map_err(|_| ControllerError::Invalid)
}

/// `PUT /configs` (no `force`) with an inline YAML payload.
pub(crate) fn put_config_payload(port: u16, payload: &str, secret: Option<&str>) -> HttpResult<()> {
    let url = loopback_url(port, "/configs")?;
    let body = serde_json::to_string(&serde_json::json!({ "path": "", "payload": payload }))
        .map_err(|_| ControllerError::BadRequest)?;
    let mut request = agent(APPLY_TIMEOUT)
        .put(&url)
        .header("Content-Type", "application/json");
    if let Some(value) = bearer(secret) {
        request = request.header("Authorization", value);
    }
    let response = request.send(body).map_err(map_error)?;
    check_status(response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_loopback_urls_only() {
        assert_eq!(
            loopback_url(9090, "/rules").unwrap(),
            "http://127.0.0.1:9090/rules"
        );
        for path in [
            "rules",
            "//evil.com/x",
            "/a@b",
            "/a\\b",
            "/a b",
            "/x#y",
            "/a\n",
        ] {
            assert_eq!(
                loopback_url(9090, path),
                Err(ControllerError::BadRequest),
                "{path:?}"
            );
        }
        assert_eq!(loopback_url(0, "/rules"), Err(ControllerError::BadRequest));
    }

    #[test]
    fn status_codes() {
        assert_eq!(check_status(200), Ok(()));
        assert_eq!(check_status(204), Ok(()));
        assert_eq!(check_status(401), Err(ControllerError::Unauthorized));
        assert_eq!(check_status(400), Err(ControllerError::Status(400)));
    }

    #[test]
    fn bearer_only_for_non_empty_secret() {
        assert_eq!(bearer(None), None);
        assert_eq!(bearer(Some("")), None);
        assert_eq!(bearer(Some("k")).as_deref(), Some("Bearer k"));
    }

    #[test]
    fn closed_port_is_unreachable() {
        // Bind and drop to get a port nobody listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            get_json(port, "/version", None),
            Err(ControllerError::Unreachable)
        );
    }

    #[test]
    fn reads_json_from_local_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 2048];
            let read = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let body = r#"{"version":"v1.19.34"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            request
        });
        let value = get_json(port, "/version", Some("s3")).unwrap();
        assert_eq!(value["version"], "v1.19.34");
        let request = server.join().unwrap();
        assert!(
            request.starts_with("GET /version HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("authorization: Bearer s3\r\n")
                || request.contains("Authorization: Bearer s3\r\n")
        );
    }
}
