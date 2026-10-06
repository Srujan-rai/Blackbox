//! IPC protocol between CLI and daemon.
//!
//! Uses a simple JSON protocol over Unix domain sockets.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Status,
    Dump { output: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    Dump(DumpResult),
    Error(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub events_recorded: u64,
    pub events_evicted: u64,
    pub events_dropped_kernel: u64,
    pub last_trigger_reason: Option<String>,
    pub last_trigger_time: Option<u64>, // unix ns
    pub socket: String,
    pub dump_dir: String,
    pub config_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DumpResult {
    pub success: bool,
    pub path: Option<String>,
    pub message: String,
}

/// Default socket paths to try
pub const DEFAULT_SOCKET_PATHS: &[&str] = &[
    "/run/blackbox/blackboxd.sock",
    "/var/run/blackbox/blackboxd.sock",
    "/tmp/blackboxd.sock",
];

pub fn default_socket_path() -> &'static str {
    DEFAULT_SOCKET_PATHS[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_json() {
        let req = Request::Status;
        let text = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&text).unwrap(), req);

        let resp = Response::Status(StatusInfo {
            running: true,
            pid: Some(42),
            uptime_secs: Some(7),
            events_recorded: 10,
            events_evicted: 3,
            events_dropped_kernel: 1,
            last_trigger_reason: Some("manual".into()),
            last_trigger_time: Some(123),
            socket: "/run/blackbox/blackboxd.sock".into(),
            dump_dir: "/var/lib/blackbox/dumps".into(),
            config_path: "/etc/blackbox/config.toml".into(),
        });
        let text = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&text).unwrap() {
            Response::Status(s) => {
                assert_eq!(s.pid, Some(42));
                assert_eq!(s.events_dropped_kernel, 1);
                assert_eq!(s.last_trigger_reason.as_deref(), Some("manual"));
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn dump_request_keeps_an_optional_output_path() {
        let with = Request::Dump {
            output: Some("/tmp/x.json".into()),
        };
        let without = Request::Dump { output: None };
        for req in [with, without] {
            let text = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&text).unwrap(), req);
        }
    }

    #[test]
    fn error_response_carries_its_message() {
        let resp = Response::Error("boom".into());
        let text = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serde_json::from_str::<Response>(&text).unwrap(),
            Response::Error("boom".into())
        );
    }

    #[test]
    fn default_socket_is_listed_first() {
        assert_eq!(default_socket_path(), DEFAULT_SOCKET_PATHS[0]);
    }
}
