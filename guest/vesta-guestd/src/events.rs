// SPDX-License-Identifier: Apache-2.0
//! Ring buffer records -> `vesta.event.v1.Event`, and the bounded replay
//! buffer behind the EVT stream (events.proto).
//!
//! Sequence numbers are monotonic per guest boot (events.proto): guestd
//! reserves blocks of them in a pinned map (`SeqStore`) before use, so a
//! restarted guestd continues above anything its predecessor may have sent.
//! Seqs reserved but never used show up as a gap, which is accurate: the
//! previous guestd's unacked replay buffer is lost with it.
//! Unacked events stay buffered for replay; when the buffer is full,
//! AUDITED/ALLOWED events are evicted (oldest first) before DENIED ones, and
//! every eviction is counted.

use std::collections::{HashMap, VecDeque};

use prost::Message;

use crate::abi::{self, evf, Record};
use crate::proto::event as ev;

pub const MAX_BATCH_EVENTS: usize = 512;
/// Room left in a 1 MiB frame for the EventStreamMessage/EventBatch wrapping.
pub const MAX_BATCH_BYTES: usize = crate::codec::MAX_FRAME - 1024;
const MAX_ARGV_ENTRIES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
/// Seqs reserved per SeqStore write.
pub const SEQ_BLOCK: u64 = 1024;

/// Persists the highest reserved event seq across guestd restarts.
pub trait SeqStore {
    fn load(&self) -> anyhow::Result<u64>;
    fn store(&self, reserved: u64) -> anyhow::Result<()>;
}

/// NUL-terminated bytes as UTF-8 (lossy), cut to `max` bytes on a char boundary.
fn cstr(b: &[u8], max: usize) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let mut s = String::from_utf8_lossy(&b[..end]).into_owned();
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

fn flags(bits: u32) -> Vec<i32> {
    (0..evf::COUNT)
        .filter(|i| bits & (1 << i) != 0)
        .map(|i| i as i32 + 1)
        .collect()
}

/// Splits NUL-separated argv; `len` is untrusted and clamped to the buffer.
fn split_argv(buf: &[u8], len: u16, truncated: bool) -> (Vec<String>, bool) {
    let mut data = &buf[..usize::from(len).min(buf.len())];
    // Every argument is NUL-terminated; drop the last terminator.
    if let Some(d) = data.strip_suffix(&[0]) {
        data = d;
    }
    let mut out = Vec::new();
    let mut truncated = truncated;
    if data.is_empty() {
        return (out, truncated);
    }
    for a in data.split(|&c| c == 0) {
        if out.len() == MAX_ARGV_ENTRIES {
            truncated = true;
            break;
        }
        out.push(String::from_utf8_lossy(a).into_owned());
    }
    (out, truncated)
}

/// Converts a validated record. `container_id` comes from guestd's bindings.
pub fn to_event(
    rec: &Record,
    seq: u64,
    wall_offset_ns: i64,
    container_id: Option<&str>,
) -> ev::Event {
    let hdr = match rec {
        Record::Exec(e) => &e.hdr,
        Record::Connect(c) => &c.hdr,
    };
    let mut process = ev::Process {
        pid: hdr.pid,
        tgid: hdr.tgid,
        ppid: hdr.ppid,
        ns_pid: hdr.ns_tgid,
        uid: hdr.uid,
        gid: hdr.gid,
        comm: cstr(&hdr.comm, abi::COMM_LEN),
        ..Default::default()
    };
    let detail = match rec {
        Record::Exec(e) => {
            let p = &e.exec;
            let path_len = usize::from(p.path_len).min(abi::PATH_MAX - 1);
            process.exe_path = cstr(&p.path[..path_len], MAX_PATH_BYTES);
            process.exe = Some(ev::FileId {
                dev: u64::from(p.exe_dev),
                ino: p.exe_ino,
            });
            let (argv, truncated) =
                split_argv(&p.argv, p.argv_len, hdr.flags & evf::ARGV_TRUNCATED != 0);
            process.argv = argv;
            process.argv_truncated = truncated;
            ev::event::Detail::Exec(ev::Exec {
                argc: p.argc,
                path_truncated: hdr.flags & evf::PATH_TRUNCATED != 0,
            })
        }
        Record::Connect(c) => {
            let p = &c.connect;
            let (family, addr) = if p.family == abi::AF_INET6 {
                (ev::AddressFamily::Inet6, p.daddr.to_vec())
            } else {
                (ev::AddressFamily::Inet, p.daddr[..4].to_vec())
            };
            ev::event::Detail::Net(ev::Net {
                direction: ev::Direction::Egress as i32,
                family: family as i32,
                protocol: u32::from(p.protocol),
                remote_addr: addr,
                remote_port: u32::from(u16::from_be_bytes(p.dport)),
                socket_cookie: p.sock_cookie,
                matched_verdict: i32::from(p.verdict.min(abi::verdict::DENY)),
            })
        }
    };
    let ktime = hdr.ktime_boot_ns;
    ev::Event {
        seq,
        ktime_boot_ns: ktime,
        guest_wall_unix_ns: wall_offset_ns.saturating_add(i64::try_from(ktime).unwrap_or(i64::MAX)),
        r#type: i32::from(hdr.r#type),
        action: i32::from(hdr.action),
        policy: Some(ev::PolicyRef {
            policy_id: hdr.policy_id,
            generation: hdr.policy_generation,
            rule_id: hdr.rule_id,
            ..Default::default()
        }),
        process: Some(process),
        chain: Vec::new(),
        cgroup_id: hdr.cgroup_id,
        container_id: container_id.unwrap_or_default().to_string(),
        flags: flags(hdr.flags),
        hook: i32::from(hdr.hook),
        detail: Some(detail),
        host: None,
    }
}

#[derive(Debug)]
struct Entry {
    seq: u64,
    /// Approximate heap footprint, counted against `max_bytes`.
    size: usize,
    /// Encoded size, used for batch framing limits.
    wire: usize,
    event: ev::Event,
}

/// Heap bytes held by a buffered event: the structs, every String header and
/// its bytes. Encoded size alone undercounts argv full of empty strings.
fn heap_size(e: &ev::Event, wire: usize) -> usize {
    use std::mem::size_of;
    let mut n = size_of::<Entry>() + wire;
    if let Some(p) = &e.process {
        n += size_of::<ev::Process>() + p.argv.len() * size_of::<String>();
    }
    n += e.chain.len() * size_of::<ev::Process>() + e.flags.len() * size_of::<i32>();
    n
}

/// Bounded buffer of unacked events, two priority classes.
#[derive(Debug)]
pub struct ReplayBuffer {
    low: VecDeque<Entry>,
    high: VecDeque<Entry>,
    max_events: usize,
    max_bytes: usize,
    bytes: usize,
    next_seq: u64,
    evicted: u64,
}

impl ReplayBuffer {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            low: VecDeque::new(),
            high: VecDeque::new(),
            max_events: max_events.max(1),
            max_bytes: max_bytes.max(1),
            bytes: 0,
            next_seq: 1,
            evicted: 0,
        }
    }

    /// Assigns the next seq and buffers the event, evicting if needed.
    pub fn push(&mut self, mut event: ev::Event) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        event.seq = seq;
        let wire = event.encoded_len();
        let size = heap_size(&event, wire);
        let high = event.action == ev::Action::Denied as i32;
        let q = if high { &mut self.high } else { &mut self.low };
        q.push_back(Entry {
            seq,
            size,
            wire,
            event,
        });
        self.bytes += size;
        while self.len() > self.max_events || self.bytes > self.max_bytes {
            let victim = self.low.pop_front().or_else(|| self.high.pop_front());
            match victim {
                Some(e) => {
                    self.bytes -= e.size;
                    self.evicted += 1;
                }
                None => break,
            }
        }
        seq
    }

    fn len(&self) -> usize {
        self.low.len() + self.high.len()
    }

    /// Continues numbering after `last` (a seq a previous guestd may have used).
    pub fn resume_after(&mut self, last: u64) {
        if last >= self.next_seq {
            self.next_seq = last.saturating_add(1);
        }
    }

    /// The seq the next pushed event gets.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Highest seq assigned so far (0 if none).
    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// Events dropped from the buffer before being acked.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Oldest buffered seq, if any.
    pub fn oldest_seq(&self) -> Option<u64> {
        match (self.low.front(), self.high.front()) {
            (Some(a), Some(b)) => Some(a.seq.min(b.seq)),
            (a, b) => a.or(b).map(|e| e.seq),
        }
    }

    /// Drops everything with seq <= `acked`. Acks beyond what was assigned are clamped.
    pub fn ack(&mut self, acked: u64) {
        let acked = acked.min(self.last_seq());
        for q in [&mut self.low, &mut self.high] {
            while q.front().is_some_and(|e| e.seq <= acked) {
                if let Some(e) = q.pop_front() {
                    self.bytes -= e.size;
                }
            }
        }
    }

    /// Up to `MAX_BATCH_EVENTS` buffered events with seq >= `from`, in seq
    /// order, within `MAX_BATCH_BYTES`. Always returns at least one event if any is available.
    pub fn batch_from(&self, from: u64) -> Vec<ev::Event> {
        let mut li = self.low.partition_point(|e| e.seq < from);
        let mut hi = self.high.partition_point(|e| e.seq < from);
        let mut out = Vec::new();
        let mut bytes = 0usize;
        while out.len() < MAX_BATCH_EVENTS {
            let next = match (self.low.get(li), self.high.get(hi)) {
                (Some(l), Some(h)) if l.seq < h.seq => {
                    li += 1;
                    l
                }
                (_, Some(h)) => {
                    hi += 1;
                    h
                }
                (Some(l), None) => {
                    li += 1;
                    l
                }
                (None, None) => break,
            };
            // Per-event framing overhead in the repeated field: tag + length varint.
            let cost = next.wire + 6;
            if !out.is_empty() && bytes + cost > MAX_BATCH_BYTES {
                break;
            }
            bytes += cost;
            out.push(next.event.clone());
        }
        out
    }
}

/// Everything the EVT side needs from the ring buffer consumer.
pub struct EventHub {
    pub replay: ReplayBuffer,
    pub containers: HashMap<u64, String>,
    pub decode_errors: u64,
    wall_offset_ns: i64,
    seq_store: Option<Box<dyn SeqStore>>,
    /// Highest seq persisted as reserved; `replay` may assign up to this.
    reserved: u64,
    seq_store_errors: u64,
}

impl std::fmt::Debug for EventHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventHub")
            .field("replay", &self.replay)
            .field("decode_errors", &self.decode_errors)
            .field("reserved", &self.reserved)
            .finish_non_exhaustive()
    }
}

impl EventHub {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            replay: ReplayBuffer::new(max_events, max_bytes),
            containers: HashMap::new(),
            decode_errors: 0,
            wall_offset_ns: 0,
            seq_store: None,
            reserved: u64::MAX,
            seq_store_errors: 0,
        }
    }

    /// Continues the seq numbering persisted in `store` and reserves ahead in it.
    pub fn with_seq_store(mut self, store: Box<dyn SeqStore>) -> anyhow::Result<Self> {
        let last = store.load()?;
        self.replay.resume_after(last);
        self.reserved = last;
        self.seq_store = Some(store);
        self.reserve();
        Ok(self)
    }

    /// Makes sure the next seq is covered by a persisted reservation. If the
    /// store fails, numbering continues in memory (still monotonic for this
    /// process) and the failure is logged.
    fn reserve(&mut self) {
        let next = self.replay.next_seq();
        let Some(store) = &self.seq_store else {
            return;
        };
        if next <= self.reserved {
            return;
        }
        let want = next.saturating_add(SEQ_BLOCK - 1);
        match store.store(want) {
            Ok(()) => self.reserved = want,
            Err(e) => {
                self.seq_store_errors += 1;
                if self.seq_store_errors.is_power_of_two() {
                    tracing::warn!(error = %format!("{e:#}"), total = self.seq_store_errors, "persisting the event seq failed; a guestd restart may reuse seqs");
                }
            }
        }
    }

    /// Records the exact last seq (clean shutdown), so a restart shows no gap.
    pub fn persist_last_seq(&mut self) {
        if let Some(store) = &self.seq_store {
            let last = self.replay.last_seq();
            if let Err(e) = store.store(last) {
                tracing::warn!(error = %format!("{e:#}"), "persisting the event seq at shutdown failed");
            } else {
                self.reserved = last;
            }
        }
    }

    /// Re-reads CLOCK_REALTIME - CLOCK_BOOTTIME (call before each consume batch).
    pub fn refresh_clock(&mut self) {
        let rt = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let bt = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let ns = |t: rustix::time::Timespec| {
            t.tv_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(t.tv_nsec)
        };
        self.wall_offset_ns = ns(rt).saturating_sub(ns(bt));
    }

    /// Handles one ring buffer sample. Malformed records are counted, never fatal.
    pub fn ingest(&mut self, sample: &[u8]) {
        match Record::decode(sample) {
            Ok(rec) => {
                let cg = match &rec {
                    Record::Exec(e) => e.hdr.cgroup_id,
                    Record::Connect(c) => c.hdr.cgroup_id,
                };
                let event = to_event(
                    &rec,
                    0,
                    self.wall_offset_ns,
                    self.containers.get(&cg).map(String::as_str),
                );
                self.reserve();
                self.replay.push(event);
            }
            Err(e) => {
                self.decode_errors += 1;
                if self.decode_errors.is_power_of_two() {
                    tracing::warn!(error = %e, total = self.decode_errors, "dropping malformed ring buffer record");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{ConnectEvent, ConnectPayload, EventHeader, ExecEvent, ExecPayload};

    fn exec_record(argv: &[u8], argv_len: u16, flags: u32) -> Record {
        let mut a = [0u8; abi::ARGV_MAX];
        a[..argv.len()].copy_from_slice(argv);
        let mut path = [0u8; abi::PATH_MAX];
        path[..8].copy_from_slice(b"/bin/ls\0");
        let mut comm = [0u8; 16];
        comm[..2].copy_from_slice(b"ls");
        Record::Exec(Box::new(ExecEvent {
            hdr: EventHeader {
                abi_version: 1,
                r#type: abi::event_type::EXEC,
                size: 1392,
                action: abi::action::AUDITED,
                hook: abi::hook::SCHED_PROCESS_EXEC,
                ktime_boot_ns: 1_000,
                cgroup_id: 9,
                policy_id: 3,
                policy_generation: 2,
                rule_id: 4,
                flags,
                comm,
                ..Default::default()
            },
            exec: ExecPayload {
                exe_dev: 1,
                argc: 2,
                exe_ino: 2,
                path_len: 7,
                argv_len,
                _pad0: 0,
                path,
                argv: a,
            },
        }))
    }

    #[test]
    fn exec_conversion() {
        let rec = exec_record(b"ls\0-l\0", 6, evf::POLICY_PENDING | evf::WOULD_DENY);
        let e = to_event(&rec, 5, 10, Some("c1"));
        let p = e.process.as_ref().unwrap();
        assert_eq!(p.exe_path, "/bin/ls");
        assert_eq!(p.comm, "ls");
        assert_eq!(p.argv, vec!["ls", "-l"]);
        assert_eq!(
            e.flags,
            vec![
                ev::EventFlag::PolicyPending as i32,
                ev::EventFlag::WouldDeny as i32
            ]
        );
        assert_eq!(e.guest_wall_unix_ns, 1_010);
        assert_eq!(e.container_id, "c1");
        assert_eq!(e.policy.as_ref().unwrap().rule_id, 4);
        assert!(matches!(
            e.detail,
            Some(ev::event::Detail::Exec(ev::Exec {
                argc: 2,
                path_truncated: false
            }))
        ));
    }

    #[test]
    fn untrusted_lengths_are_clamped() {
        let rec = exec_record(b"a\0b", 60_000, 0);
        let e = to_event(&rec, 1, 0, None);
        let p = e.process.unwrap();
        // argv_len beyond the buffer is clamped to ARGV_MAX; zero tail splits into empties.
        assert_eq!(&p.argv[..2], &["a", "b"]);
        assert!(p.argv.len() <= MAX_ARGV_ENTRIES);
        let mut many = Vec::new();
        for _ in 0..400 {
            many.extend_from_slice(b"x\0");
        }
        let (argv, truncated) = split_argv(&many, 800, false);
        assert_eq!(argv.len(), MAX_ARGV_ENTRIES);
        assert!(truncated);
    }

    #[test]
    fn argv_with_inner_empty_argument() {
        let (argv, t) = split_argv(b"a\0\0b\0", 5, false);
        assert_eq!(argv, vec!["a", "", "b"]);
        assert!(!t);
        let (argv, t) = split_argv(b"abc", 3, true);
        assert_eq!(argv, vec!["abc"]);
        assert!(t);
    }

    #[test]
    fn connect_conversion() {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&[10, 1, 2, 3]);
        let rec = Record::Connect(ConnectEvent {
            hdr: EventHeader {
                abi_version: 1,
                r#type: 2,
                size: 120,
                action: 2,
                hook: 3,
                ..Default::default()
            },
            connect: ConnectPayload {
                family: abi::AF_INET,
                protocol: 6,
                verdict: 2,
                dport: 443u16.to_be_bytes(),
                daddr,
                ..Default::default()
            },
        });
        let e = to_event(&rec, 1, 0, None);
        let Some(ev::event::Detail::Net(n)) = e.detail else {
            panic!("not net")
        };
        assert_eq!(
            (n.remote_addr, n.remote_port, n.protocol, n.matched_verdict),
            (vec![10, 1, 2, 3], 443, 6, 2)
        );
        assert_eq!(n.family, ev::AddressFamily::Inet as i32);
    }

    fn event(action: ev::Action) -> ev::Event {
        ev::Event {
            action: action as i32,
            ..Default::default()
        }
    }

    #[test]
    fn replay_evicts_low_priority_first() {
        let mut rb = ReplayBuffer::new(3, usize::MAX);
        rb.push(event(ev::Action::Denied)); // 1
        rb.push(event(ev::Action::Audited)); // 2
        rb.push(event(ev::Action::Allowed)); // 3
        rb.push(event(ev::Action::Denied)); // 4 -> evicts 2
        rb.push(event(ev::Action::Audited)); // 5 -> evicts 3
        let seqs: Vec<u64> = rb.batch_from(0).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 4, 5]);
        assert_eq!(rb.evicted(), 2);
        rb.push(event(ev::Action::Denied)); // 6 -> evicts 5 (last low)
        rb.push(event(ev::Action::Denied)); // 7 -> no low left, evicts 1
        let seqs: Vec<u64> = rb.batch_from(0).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![4, 6, 7]);
        assert_eq!(rb.oldest_seq(), Some(4));
    }

    #[test]
    fn replay_ack_and_resume() {
        let mut rb = ReplayBuffer::new(100, usize::MAX);
        for i in 0..10 {
            rb.push(event(if i % 3 == 0 {
                ev::Action::Denied
            } else {
                ev::Action::Audited
            }));
        }
        rb.ack(4);
        assert_eq!(rb.oldest_seq(), Some(5));
        assert_eq!(
            rb.batch_from(8).iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![8, 9, 10]
        );
        rb.ack(u64::MAX);
        assert_eq!(rb.oldest_seq(), None);
        assert_eq!(rb.last_seq(), 10);
        assert_eq!(rb.push(event(ev::Action::Audited)), 11);
    }

    #[test]
    fn replay_byte_bound_and_batch_limits() {
        let mut rb = ReplayBuffer::new(10_000, 10_000);
        let big = ev::Event {
            process: Some(ev::Process {
                exe_path: "x".repeat(900),
                ..Default::default()
            }),
            ..Default::default()
        };
        for _ in 0..50 {
            rb.push(big.clone());
        }
        assert!(rb.len() <= 11, "byte bound keeps ~10 KB: {}", rb.len());
        let mut rb = ReplayBuffer::new(10_000, usize::MAX);
        for _ in 0..1000 {
            rb.push(event(ev::Action::Audited));
        }
        assert_eq!(rb.batch_from(0).len(), MAX_BATCH_EVENTS);
    }

    #[test]
    fn hub_counts_bad_records() {
        let mut hub = EventHub::new(10, 1 << 20);
        hub.ingest(&[1, 2, 3]);
        assert_eq!(hub.decode_errors, 1);
        let rec = exec_record(b"ls\0", 3, 0);
        let Record::Exec(e) = rec else { unreachable!() };
        hub.containers.insert(9, "c9".into());
        hub.ingest(&e.to_bytes());
        let b = hub.replay.batch_from(0);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].container_id, "c9");
        assert_eq!(b[0].seq, 1);
    }

    #[derive(Debug, Default, Clone)]
    struct MemSeq(std::rc::Rc<std::cell::Cell<u64>>);

    impl SeqStore for MemSeq {
        fn load(&self) -> anyhow::Result<u64> {
            Ok(self.0.get())
        }
        fn store(&self, reserved: u64) -> anyhow::Result<()> {
            self.0.set(reserved);
            Ok(())
        }
    }

    fn exec_bytes() -> Vec<u8> {
        let Record::Exec(e) = exec_record(b"ls\0", 3, 0) else {
            unreachable!()
        };
        e.to_bytes()
    }

    #[test]
    fn seq_continues_across_restarts() {
        let store = MemSeq::default();
        let mut hub = EventHub::new(100, 1 << 20)
            .with_seq_store(Box::new(store.clone()))
            .unwrap();
        for _ in 0..3 {
            hub.ingest(&exec_bytes());
        }
        assert_eq!(hub.replay.last_seq(), 3);
        assert_eq!(store.0.get(), SEQ_BLOCK, "a block is reserved ahead");

        // Crash: the next guestd starts above the reservation.
        let mut hub2 = EventHub::new(100, 1 << 20)
            .with_seq_store(Box::new(store.clone()))
            .unwrap();
        hub2.ingest(&exec_bytes());
        assert_eq!(hub2.replay.last_seq(), SEQ_BLOCK + 1);
        for _ in 0..SEQ_BLOCK {
            hub2.ingest(&exec_bytes());
        }
        assert!(store.0.get() >= hub2.replay.last_seq());

        // Clean shutdown: no gap.
        hub2.persist_last_seq();
        let last = hub2.replay.last_seq();
        let mut hub3 = EventHub::new(100, 1 << 20)
            .with_seq_store(Box::new(store))
            .unwrap();
        hub3.ingest(&exec_bytes());
        assert_eq!(hub3.replay.last_seq(), last + 1);
    }

    #[test]
    fn replay_bound_counts_heap_not_wire_size() {
        // 256 empty argv strings encode small but occupy ~6 KiB of headers.
        let ev = ev::Event {
            process: Some(ev::Process {
                argv: vec![String::new(); MAX_ARGV_ENTRIES],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(ev.encoded_len() < 1024);
        let mut rb = ReplayBuffer::new(1_000_000, 64 << 10);
        for _ in 0..100 {
            rb.push(ev.clone());
        }
        assert!(
            rb.len() <= 10,
            "kept {} events in a 64 KiB budget",
            rb.len()
        );
    }
}
