# Privileges, privacy and threat model

## Least privilege

Loading and attaching the BPF program is the only privileged act. Run the
daemon as root or with `CAP_BPF` + `CAP_PERFMON`. Reading PSI and generating
reports need no capabilities.

## What is recorded

Only what the kernel puts in the scheduler tracepoints:

- the 15-character `comm` of switching and exiting tasks
- pids, the previous task state, a timestamp and a CPU id
- on `fork`, the child's `comm`; on `exec`, the **executed path** (up to 15
  characters, e.g. `/usr/bin/psql`)

Blackbox does **not** capture command lines, arguments, environment variables
or memory contents.

## No network

The daemon neither listens on nor dials a network socket. It speaks
line-delimited JSON over a local Unix socket, one request per connection.

## The control socket is local, not private

- The socket is mode `0666`, so any local user can run `blackbox status`.
- `blackbox dump` and `blackbox stop` are restricted to the daemon's owner and
  root via `SO_PEERCRED` (the kernel-reported peer identity, which cannot be
  spoofed). Set `[ipc].restrict_mutations = false` to open them to every
  local user.
- Choosing a dump path with `-o` is always restricted to root or the daemon's
  owner, because the daemon writes that file with its own privileges.
- To restrict even `status`, pre-create `/run/blackbox` with a stricter mode.
  The daemon never loosens a directory it did not create.

## Dumps at rest

Dumps in the dump directory are mode `0600`. Writes use a fresh `O_EXCL`
temporary file followed by a rename or hard link, so a symlink planted in a
shared directory such as `/tmp` is replaced, never followed.

## Honest output

Dumps carry their own completeness counters (evictions and kernel drops), so a
trace that lost events says so rather than looking authoritative.
