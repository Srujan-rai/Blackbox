//! IPC protocol between CLI and daemon.
//!
//! Uses a simple JSON protocol over Unix domain sockets.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Status,
    Dump { output: Option<String> },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    Dump(DumpResult),
    Stop(StopResult),
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
    /// Whether the BPF program is attached and events are flowing.
    ///
    /// False is a legitimate state (no privileges, no object, `--no-bpf`), but
    /// it must be visible: a daemon quietly collecting nothing is exactly the
    /// failure this field exists to prevent.
    #[serde(default)]
    pub bpf_attached: bool,
    /// Why collection is not live when `bpf_attached` is false. `None` while
    /// the collector thread is still starting up. `#[serde(default)]` so this
    /// CLI still parses a status reply from an older daemon that lacks both
    /// fields.
    #[serde(default)]
    pub bpf_error: Option<String>,
    /// The pid filter applied at load, if any. Empty means machine-wide
    /// tracing. `#[serde(default)]` so a new CLI parses a status reply from an
    /// older daemon that does not have the field.
    #[serde(default)]
    pub filter_pids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DumpResult {
    pub success: bool,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopResult {
    pub success: bool,
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
            bpf_attached: true,
            bpf_error: None,
            filter_pids: vec![42, 43],
        });
        let text = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&text).unwrap() {
            Response::Status(s) => {
                assert_eq!(s.pid, Some(42));
                assert_eq!(s.events_dropped_kernel, 1);
                assert_eq!(s.last_trigger_reason.as_deref(), Some("manual"));
                assert!(s.bpf_attached);
                assert_eq!(s.bpf_error, None);
                assert_eq!(s.filter_pids, vec![42, 43]);
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn degraded_status_round_trips_with_its_reason() {
        let resp = Response::Status(StatusInfo {
            bpf_attached: false,
            bpf_error: Some("no blackbox-bpf.o found".into()),
            ..StatusInfo::default()
        });
        let text = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&text).unwrap() {
            Response::Status(s) => {
                assert!(!s.bpf_attached);
                assert_eq!(s.bpf_error.as_deref(), Some("no blackbox-bpf.o found"));
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn status_json_from_an_older_daemon_without_bpf_fields_still_parses() {
        // A new CLI talking to a pre-collection daemon must not fail on the
        // missing keys; it should read as "not attached, no reason given".
        let mut value = serde_json::to_value(Response::Status(StatusInfo {
            running: true,
            ..StatusInfo::default()
        }))
        .unwrap();
        let obj = value
            .get_mut("Status")
            .expect("externally tagged")
            .as_object_mut()
            .expect("object");
        obj.remove("bpf_attached");
        obj.remove("bpf_error");
        match serde_json::from_value::<Response>(value).unwrap() {
            Response::Status(s) => {
                assert!(s.running);
                assert!(!s.bpf_attached);
                assert_eq!(s.bpf_error, None);
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
    fn stop_request_and_response_round_trip_through_json() {
        let req = Request::Stop;
        let text = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&text).unwrap(), req);

        let resp = Response::Stop(StopResult {
            success: true,
            message: "stop requested".into(),
        });
        let text = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&text).unwrap() {
            Response::Stop(s) => {
                assert!(s.success);
                assert_eq!(s.message, "stop requested");
            }
            other => panic!("expected stop response, got {other:?}"),
        }
    }

    #[test]
    fn default_socket_is_listed_first() {
        assert_eq!(default_socket_path(), DEFAULT_SOCKET_PATHS[0]);
    }
}
