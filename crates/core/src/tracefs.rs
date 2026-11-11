//! Reading tracepoint layouts from tracefs.
//!
//! Some tracepoint records change shape between kernels (a `char[16]` comm
//! becoming a `__data_loc` string moves every later field), and reading a
//! field at the wrong offset fails silently with plausible-looking garbage.
//! Where the BPF side cannot avoid the record, the daemon reads the real
//! offset from the event's `format` file instead of trusting a constant.

use std::path::Path;

/// tracefs mount points, newest convention first.
pub const TRACEFS_ROOTS: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Offset of `field` in a tracepoint `format` file, e.g. the `20` in
/// `field:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;`.
pub fn field_offset(format: &str, field: &str) -> Option<u32> {
    format.lines().find_map(|line| {
        let decl = line.trim().strip_prefix("field:")?;
        let (decl, rest) = decl.split_once(';')?;
        // The name is the last word, minus any array suffix (`comm[16]`).
        let name = decl.split_whitespace().last()?;
        let name = name.split('[').next()?;
        if name != field {
            return None;
        }
        let offset = rest
            .split(';')
            .find_map(|kv| kv.trim().strip_prefix("offset:"))?;
        offset.trim().parse().ok()
    })
}

/// Read `field`'s offset in `category/event` from the first tracefs root that
/// has it.
pub fn read_field_offset(category: &str, event: &str, field: &str) -> Option<u32> {
    TRACEFS_ROOTS.iter().find_map(|root| {
        let path = Path::new(root)
            .join("events")
            .join(category)
            .join(event)
            .join("format");
        let text = std::fs::read_to_string(path).ok()?;
        field_offset(&text, field)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSIC: &str = "name: sched_process_fork
ID: 316
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;
";

    const DATA_LOC: &str = "name: sched_process_fork
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;
";

    #[test]
    fn finds_child_pid_in_the_classic_inline_comm_layout() {
        assert_eq!(field_offset(CLASSIC, "child_pid"), Some(44));
        assert_eq!(field_offset(CLASSIC, "parent_comm"), Some(8));
    }

    #[test]
    fn finds_child_pid_when_comms_are_data_loc_strings() {
        assert_eq!(field_offset(DATA_LOC, "child_pid"), Some(20));
        assert_eq!(field_offset(DATA_LOC, "child_comm"), Some(16));
    }

    #[test]
    fn a_missing_field_or_garbage_is_none() {
        assert_eq!(field_offset(CLASSIC, "nope"), None);
        assert_eq!(field_offset("garbage", "child_pid"), None);
        // `pid` must not match `parent_pid` or `child_pid`.
        assert_eq!(field_offset(CLASSIC, "pid"), None);
    }
}
