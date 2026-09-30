// SPDX-License-Identifier: Apache-2.0
//! CTRL connection (control.proto): Hello first, then ApplyPolicy,
//! BindContainer, Unbind, SetMode, GetStatus. Requests are handled in order;
//! BindContainer waits for its cgroup in a separate task and is acked when
//! bound, so responses can arrive out of order.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::codec::{read_message, write_message, FrameError};
use crate::daemon::Shared;
use crate::policy::{self, Rejection};
use crate::proto::channel::{
    self as pb, control_request::Body as Req, control_response::Body as Resp, ErrorCode,
};
use crate::proto::{PROTO_MAJOR, PROTO_MINOR};
use crate::state::{BindTicket, EngineError};

const MAX_AGENT_VERSION: usize = 64;
const MAX_SANDBOX_ID: usize = 128;
const MAX_ERROR_LEN: usize = 1024;
const MAX_PENDING_BINDS: usize = 256;
const RESPONSE_QUEUE: usize = 256;

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

fn error(request_id: u64, code: ErrorCode, message: impl Into<String>) -> pb::ControlResponse {
    pb::ControlResponse {
        request_id,
        body: Some(Resp::Error(pb::Error {
            code: code as i32,
            message: truncate(message.into(), MAX_ERROR_LEN),
        })),
    }
}

fn ack(
    request_id: u64,
    generation: u64,
    result: Result<Vec<String>, String>,
) -> pb::ControlResponse {
    let (ok, error, warnings) = match result {
        Ok(w) => (true, String::new(), w),
        Err(e) => (false, truncate(e, MAX_ERROR_LEN), Vec::new()),
    };
    pb::ControlResponse {
        request_id,
        body: Some(Resp::Ack(pb::Ack {
            generation,
            ok,
            error,
            verifier_log: Vec::new(),
            warnings,
        })),
    }
}

fn engine_result(
    request_id: u64,
    d: &Shared,
    res: Result<crate::state::Outcome, EngineError>,
) -> pb::ControlResponse {
    match res {
        Ok(o) => ack(request_id, o.generation, Ok(o.warnings)),
        Err(EngineError::Rejected(r)) => error(request_id, r.code, r.message),
        Err(EngineError::Failed(e)) => {
            let generation = d.borrow().engine.applied_generation();
            ack(request_id, generation, Err(format!("{e:#}")))
        }
    }
}

/// What to do with the connection after a request.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Continue,
    Close,
}

pub fn hello_reply(d: &Shared) -> pb::HelloReply {
    let d = d.borrow();
    let mut features = d.bpf.features();
    if d.info.bpf_lsm {
        features.push("bpf_lsm".into());
    }
    if d.engine.enforce_supported() {
        features.push("enforce".into());
    }
    pb::HelloReply {
        proto_major: PROTO_MAJOR,
        proto_minor: PROTO_MINOR,
        guest_image_version: d.info.guest_image_version.clone(),
        kernel_release: d.info.kernel_release.clone(),
        active_lsms: d.info.active_lsms.clone(),
        cgroup_v2: d.info.cgroup_v2,
        features,
        guestd_version: d.info.guestd_version.clone(),
        abi_version: crate::abi::ABI_VERSION,
        progs: d.bpf.prog_status(true),
        global_mode: policy::global_mode_to_proto(d.engine.global_mode()) as i32,
        applied_generation: d.engine.applied_generation(),
        adopted_generation: d.engine.adopted_generation(),
    }
}

pub fn status(d: &Shared) -> pb::Status {
    let d = d.borrow();
    pb::Status {
        progs: d.bpf.prog_status(true),
        applied_generation: d.engine.applied_generation(),
        policy_hash: d.engine.policy_hash().to_vec(),
        drops: d.bpf.drop_counts(),
        global_mode: policy::global_mode_to_proto(d.engine.global_mode()) as i32,
        containers: d.engine.bound_containers().into_iter().take(1024).collect(),
        adopted: d.engine.adopted_cgroups().into_iter().take(1024).collect(),
        sandbox_default_cgroup_id: d.engine.sandbox_default().map_or(0, |s| s.cgroup_id),
    }
}

/// The pod cgroup exists by the time the host sends this (the pause
/// container runs before NRI RunPodSandbox), so there is no wait.
fn set_sandbox_default(
    d: &Shared,
    request_id: u64,
    s: &pb::SetSandboxDefault,
) -> pb::ControlResponse {
    let mut dm = d.borrow_mut();
    let prepared = match dm.engine.sandbox_default_prepare(s) {
        Ok(p) => p,
        Err(Rejection { code, message }) => return error(request_id, code, message),
    };
    let default = match prepared {
        None => None,
        Some((path, mode, failure)) => match dm.cgroups.lookup(&path) {
            Ok(Some(cgroup_id)) => Some(crate::state::SandboxDefault {
                path,
                cgroup_id,
                mode,
                failure,
            }),
            Ok(None) => {
                return error(
                    request_id,
                    ErrorCode::NotFound,
                    format!("pod cgroup {} does not exist", path.display()),
                )
            }
            Err(e) => {
                return error(
                    request_id,
                    ErrorCode::InvalidArgument,
                    format!("pod cgroup {}: {e}", path.display()),
                )
            }
        },
    };
    let set = default.is_some();
    let res = dm.engine.set_sandbox_default(default);
    drop(dm);
    tracing::info!(closed = set, ok = res.is_ok(), "sandbox default updated");
    engine_result(request_id, d, res)
}

fn set_mode(d: &Shared, request_id: u64, m: &pb::SetMode) -> pb::ControlResponse {
    let mode = match policy::global_mode_from_proto(m.mode) {
        Ok(m) => m,
        Err(r) => return error(request_id, r.code, r.message),
    };
    let mut dm = d.borrow_mut();
    let dm = &mut *dm;
    let generation = dm.engine.applied_generation();
    // Detach after programs are told to stand down; re-attach before normal operation resumes.
    let res = if mode == crate::abi::global_mode::DETACHED {
        dm.engine
            .set_global_mode(mode)
            .and_then(|()| dm.bpf.set_attached(false))
    } else {
        dm.bpf
            .set_attached(true)
            .and_then(|()| dm.engine.set_global_mode(mode))
    };
    tracing::info!(mode, ok = res.is_ok(), "SetMode");
    ack(
        request_id,
        generation,
        res.map(|()| Vec::new()).map_err(|e| format!("{e:#}")),
    )
}

async fn wait_for_cgroup(
    d: Shared,
    ticket: BindTicket,
    request_id: u64,
    tx: mpsc::Sender<pb::ControlResponse>,
) {
    let (timeout, poll, wake) = {
        let mut dm = d.borrow_mut();
        dm.cgroup_waits.register(&ticket.cgroup_path);
        (
            Duration::from_millis(dm.cfg.bind_timeout_ms.into()),
            Duration::from_millis(dm.cfg.bind_poll_ms.into()),
            dm.cgroup_waits.wake.clone(),
        )
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let resp = loop {
        // Enabled before the lookup, so a creation in between is not missed.
        let created = wake.notified();
        tokio::pin!(created);
        created.as_mut().enable();
        let found = {
            let dm = d.borrow();
            if !dm.engine.ticket_is_current(&ticket) {
                break ack(
                    request_id,
                    0,
                    Err("superseded by a newer BindContainer".into()),
                );
            }
            dm.cgroups.lookup(&ticket.cgroup_path)
        };
        match found {
            Ok(Some(cgroup_id)) => {
                let res = {
                    let mut dm = d.borrow_mut();
                    let res = dm.engine.bind_complete(&ticket, cgroup_id);
                    dm.sync_container_names();
                    res
                };
                tracing::info!(container = %ticket.container_id, cgroup_id, ok = res.is_ok(), "container bound");
                break engine_result(request_id, &d, res);
            }
            Ok(None) if tokio::time::Instant::now() < deadline => {
                // inotify wake-up (cgwatch), with a slow poll as the fallback.
                tokio::select! {
                    () = &mut created => {}
                    () = tokio::time::sleep(poll) => {}
                }
            }
            Ok(None) => {
                d.borrow_mut().engine.bind_abort(&ticket);
                break ack(
                    request_id,
                    0,
                    Err(format!(
                        "cgroup {} did not appear within {timeout:?}",
                        ticket.cgroup_path.display()
                    )),
                );
            }
            Err(e) => {
                d.borrow_mut().engine.bind_abort(&ticket);
                break ack(
                    request_id,
                    0,
                    Err(format!("cgroup {}: {e}", ticket.cgroup_path.display())),
                );
            }
        }
    };
    {
        let mut dm = d.borrow_mut();
        dm.pending_binds -= 1;
        dm.cgroup_waits.unregister(&ticket.cgroup_path);
    }
    // The connection may be gone; the binding itself stays in effect.
    let _ = tx.send(resp).await;
}

fn handle(
    d: &Shared,
    req: pb::ControlRequest,
    tx: &mpsc::Sender<pb::ControlResponse>,
) -> (Option<pb::ControlResponse>, Next) {
    let id = req.request_id;
    let Some(body) = req.body else {
        return (
            Some(error(id, ErrorCode::Malformed, "request has no body")),
            Next::Continue,
        );
    };
    if id == 0 {
        return (
            Some(error(
                0,
                ErrorCode::InvalidArgument,
                "request_id must be non-zero",
            )),
            Next::Continue,
        );
    }
    let resp = match body {
        Req::Hello(_) => error(id, ErrorCode::Malformed, "duplicate Hello"),
        Req::ApplyPolicy(p) => {
            let res = {
                let mut dm = d.borrow_mut();
                let res = dm.engine.apply(&p);
                dm.sync_container_names();
                res
            };
            match &res {
                Ok(o) => tracing::info!(
                    generation = o.generation,
                    warnings = o.warnings.len(),
                    "policy applied"
                ),
                Err(e) => {
                    tracing::warn!(generation = p.generation, error = %e, "ApplyPolicy failed")
                }
            }
            engine_result(id, d, res)
        }
        Req::BindContainer(b) => {
            let mut dm = d.borrow_mut();
            if dm.pending_binds >= MAX_PENDING_BINDS {
                error(
                    id,
                    ErrorCode::LimitExceeded,
                    format!("more than {MAX_PENDING_BINDS} binds pending"),
                )
            } else {
                let prepared = dm.engine.bind_prepare(&b);
                match prepared {
                    Ok(ticket) => {
                        dm.pending_binds += 1;
                        drop(dm);
                        tokio::task::spawn_local(wait_for_cgroup(
                            d.clone(),
                            ticket,
                            id,
                            tx.clone(),
                        ));
                        return (None, Next::Continue);
                    }
                    Err(Rejection { code, message }) => error(id, code, message),
                }
            }
        }
        Req::Unbind(u) => {
            let res = {
                let mut dm = d.borrow_mut();
                let res = dm.engine.unbind(&u.container_id);
                dm.sync_container_names();
                res
            };
            engine_result(id, d, res)
        }
        Req::SetMode(m) => set_mode(d, id, &m),
        Req::SetSandboxDefault(s) => set_sandbox_default(d, id, &s),
        Req::GetStatus(_) => pb::ControlResponse {
            request_id: id,
            body: Some(Resp::Status(status(d))),
        },
    };
    (Some(resp), Next::Continue)
}

fn handle_hello(d: &Shared, req: &pb::ControlRequest) -> (pb::ControlResponse, Next) {
    let id = req.request_id;
    let Some(Req::Hello(h)) = &req.body else {
        return (
            error(id, ErrorCode::Malformed, "first request must be Hello"),
            Next::Close,
        );
    };
    if h.proto_major != PROTO_MAJOR {
        return (
            error(
                id,
                ErrorCode::UnsupportedVersion,
                format!(
                    "protocol {}.x not supported (guest speaks {PROTO_MAJOR}.{PROTO_MINOR})",
                    h.proto_major
                ),
            ),
            Next::Close,
        );
    }
    if h.agent_version.len() > MAX_AGENT_VERSION || h.sandbox_id.len() > MAX_SANDBOX_ID || id == 0 {
        return (
            error(id, ErrorCode::InvalidArgument, "invalid Hello"),
            Next::Close,
        );
    }
    tracing::info!(agent_version = %h.agent_version, sandbox_id = %h.sandbox_id, proto_minor = h.proto_minor, "host connected");
    (
        pb::ControlResponse {
            request_id: id,
            body: Some(Resp::HelloReply(hello_reply(d))),
        },
        Next::Continue,
    )
}

/// Serves one CTRL connection until EOF, a protocol error, or cancellation.
pub async fn serve<S: AsyncRead + AsyncWrite + 'static>(d: Shared, stream: S) {
    let (frame_timeout, write_timeout) = {
        let dm = d.borrow();
        (
            Duration::from_millis(dm.cfg.frame_timeout_ms.into()),
            Duration::from_millis(dm.cfg.write_timeout_ms.into()),
        )
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<pb::ControlResponse>(RESPONSE_QUEUE);
    let writer = tokio::task::spawn_local(async move {
        while let Some(m) = rx.recv().await {
            if let Err(e) = write_message(&mut wr, &m, write_timeout).await {
                tracing::warn!(error = %e, "CTRL write failed");
                break;
            }
        }
    });

    let mut greeted = false;
    loop {
        let req = match read_message::<pb::ControlRequest, _>(&mut rd, frame_timeout).await {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "CTRL protocol error, closing");
                let code = if matches!(e, FrameError::Io(_)) {
                    ErrorCode::Internal
                } else {
                    ErrorCode::Malformed
                };
                let _ = tx.send(error(0, code, e.to_string())).await;
                break;
            }
        };
        let (resp, next) = if greeted {
            handle(&d, req, &tx)
        } else {
            let (r, n) = handle_hello(&d, &req);
            greeted = n == Next::Continue;
            (Some(r), n)
        };
        if let Some(r) = resp {
            if tx.send(r).await.is_err() {
                break;
            }
        }
        if next == Next::Close {
            break;
        }
    }
    drop(tx);
    // Flush queued responses; pending bind tasks hold their own sender and finish independently.
    let _ = tokio::time::timeout(write_timeout, writer).await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::daemon::fake::{FakeBpf, FakeCgroups};
    use crate::daemon::Daemon;
    use crate::resolve::fake::FakeResolver;
    use crate::state::fake::FakeMaps;
    use crate::state::{Baseline, Engine, PolicyMaps};
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use tokio::io::DuplexStream;

    fn daemon(cgroups: FakeCgroups) -> Shared {
        let cfg = crate::config::Config {
            bind_timeout_ms: 200,
            bind_poll_ms: 5,
            ..Default::default()
        };
        let maps: Box<dyn PolicyMaps> = Box::new(FakeMaps::default());
        Rc::new(RefCell::new(Daemon {
            cfg,
            info: crate::sysinfo::GuestInfo {
                bpf_lsm: true,
                cgroup_v2: true,
                guest_image_version: "1.0.0".into(),
                ..Default::default()
            },
            engine: Engine::new(
                maps,
                Box::new(FakeResolver::default()),
                Baseline {
                    mode: 0,
                    failure: 0,
                },
                true,
            ),
            bpf: Box::new(FakeBpf {
                attached: true,
                drops: vec![(1, 3)],
            }),
            cgroups: Box::new(cgroups),
            cgroup_waits: crate::cgwatch::CgroupWaits::default(),
            hub: crate::events::EventHub::new(100, 1 << 20),
            events_ready: Rc::new(tokio::sync::Notify::new()),
            heartbeat_seq: 0,
            pending_binds: 0,
        }))
    }

    /// A daemon whose cgroup root is `root` (for the cgwatch tests).
    pub(crate) fn daemon_with_root(root: &std::path::Path) -> Shared {
        let d = daemon(FakeCgroups::default());
        d.borrow_mut().cfg.cgroup_root = root.to_path_buf();
        d
    }

    struct Client {
        io: DuplexStream,
    }

    impl Client {
        async fn send(&mut self, request_id: u64, body: Req) {
            let m = pb::ControlRequest {
                request_id,
                body: Some(body),
            };
            write_message(&mut self.io, &m, Duration::from_secs(1))
                .await
                .unwrap();
        }
        async fn recv(&mut self) -> Option<pb::ControlResponse> {
            read_message(&mut self.io, Duration::from_secs(2))
                .await
                .unwrap()
        }
    }

    fn start(d: &Shared) -> Client {
        let (a, b) = tokio::io::duplex(1 << 16);
        tokio::task::spawn_local(serve(d.clone(), b));
        Client { io: a }
    }

    fn hello() -> Req {
        Req::Hello(pb::Hello {
            proto_major: 1,
            proto_minor: 0,
            agent_version: "0.1.0".into(),
            sandbox_id: "sb".into(),
        })
    }

    async fn local<F: std::future::Future<Output = ()>>(f: F) {
        tokio::task::LocalSet::new().run_until(f).await;
    }

    #[tokio::test]
    async fn hello_first_then_requests() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(1, hello()).await;
            let Some(Resp::HelloReply(h)) = c.recv().await.unwrap().body else {
                panic!("no HelloReply")
            };
            assert_eq!((h.proto_major, h.abi_version, h.cgroup_v2), (1, 1, true));
            assert!(h.features.contains(&"exec_audit".to_string()));
            assert!(h.features.contains(&"bpf_lsm".to_string()));
            assert!(h.features.contains(&"enforce".to_string()));

            c.send(2, Req::GetStatus(pb::GetStatus {})).await;
            let r = c.recv().await.unwrap();
            assert_eq!(r.request_id, 2);
            let Some(Resp::Status(s)) = r.body else {
                panic!("no Status")
            };
            assert_eq!(
                s.drops,
                vec![pb::DropCount {
                    event_type: 1,
                    count: 3
                }]
            );

            c.send(3, hello()).await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::Malformed as i32);
        })
        .await;
    }

    #[tokio::test]
    async fn sandbox_default_over_the_channel() {
        local(async {
            let cgroups = FakeCgroups::default();
            let d = daemon(cgroups.clone());
            let mut c = start(&d);
            c.send(1, hello()).await;
            c.recv().await.unwrap();
            let req = |parent: &str, failure: pb::FailurePolicy| {
                Req::SetSandboxDefault(pb::SetSandboxDefault {
                    cgroup_parent: parent.into(),
                    mode: pb::Mode::Enforce as i32,
                    failure: failure as i32,
                })
            };

            c.send(2, req("kubepods-pod9.slice", pb::FailurePolicy::Closed))
                .await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!("missing pod cgroup must be an error")
            };
            assert_eq!(e.code, ErrorCode::NotFound as i32);

            cgroups
                .0
                .borrow_mut()
                .insert(PathBuf::from("kubepods.slice/kubepods-pod9.slice"), 4242);
            c.send(3, req("kubepods-pod9.slice", pb::FailurePolicy::Closed))
                .await;
            let Some(Resp::Ack(a)) = c.recv().await.unwrap().body else {
                panic!("no Ack")
            };
            assert!(a.ok, "{}", a.error);

            c.send(4, Req::GetStatus(pb::GetStatus {})).await;
            let Some(Resp::Status(s)) = c.recv().await.unwrap().body else {
                panic!("no Status")
            };
            assert_eq!(s.sandbox_default_cgroup_id, 4242);

            c.send(5, req("../x", pb::FailurePolicy::Closed)).await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!("escape must be rejected")
            };
            assert_eq!(e.code, ErrorCode::InvalidArgument as i32);

            c.send(6, req("kubepods-pod9.slice", pb::FailurePolicy::Open))
                .await;
            let Some(Resp::Ack(a)) = c.recv().await.unwrap().body else {
                panic!("no Ack")
            };
            assert!(a.ok);
            assert!(d.borrow().engine.sandbox_default().is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn non_hello_first_closes() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(1, Req::GetStatus(pb::GetStatus {})).await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::Malformed as i32);
            assert!(c.recv().await.is_none(), "connection closed");
        })
        .await;
    }

    #[tokio::test]
    async fn wrong_major_is_unsupported() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(
                1,
                Req::Hello(pb::Hello {
                    proto_major: 2,
                    ..Default::default()
                }),
            )
            .await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::UnsupportedVersion as i32);
            assert!(c.recv().await.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn oversize_frame_closes_with_error() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            use tokio::io::AsyncWriteExt;
            c.io.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::Malformed as i32);
            assert!(c.recv().await.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn apply_and_bind_acks_when_cgroup_appears() {
        local(async {
            let cgroups = FakeCgroups::default();
            let d = daemon(cgroups.clone());
            let mut c = start(&d);
            c.send(1, hello()).await;
            c.recv().await.unwrap();

            let bundle = pb::PolicyBundle {
                policy_id: 4,
                schema_version: 1,
                ..Default::default()
            };
            c.send(
                2,
                Req::ApplyPolicy(pb::ApplyPolicy {
                    generation: 1,
                    bundles: vec![bundle],
                }),
            )
            .await;
            let Some(Resp::Ack(a)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert!(a.ok, "{a:?}");
            assert_eq!(a.generation, 1);

            // Rejected generation is a typed Error.
            c.send(
                3,
                Req::ApplyPolicy(pb::ApplyPolicy {
                    generation: 0,
                    bundles: vec![],
                }),
            )
            .await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::InvalidArgument as i32);

            let bind = pb::BindContainer {
                container_id: "c1".into(),
                cgroup_path: "/kubepods/c1".into(),
                policy_id: 4,
                rootfs: 0,
                generation: 1,
            };
            c.send(4, Req::BindContainer(bind)).await;
            // A later request is answered while the bind is still waiting.
            c.send(5, Req::GetStatus(pb::GetStatus {})).await;
            let r = c.recv().await.unwrap();
            assert_eq!(r.request_id, 5);
            let Some(Resp::Status(s)) = r.body else {
                panic!()
            };
            assert!(s.containers[0].pending);

            cgroups
                .0
                .borrow_mut()
                .insert(PathBuf::from("kubepods/c1"), 777);
            let r = c.recv().await.unwrap();
            assert_eq!(r.request_id, 4);
            let Some(Resp::Ack(a)) = r.body else { panic!() };
            assert!(a.ok, "{a:?}");
            assert_eq!(
                d.borrow().hub.containers.get(&777).map(String::as_str),
                Some("c1")
            );
            assert_eq!(d.borrow().pending_binds, 0);
        })
        .await;
    }

    #[tokio::test]
    async fn bind_times_out() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(1, hello()).await;
            c.recv().await.unwrap();
            let bind = pb::BindContainer {
                container_id: "c1".into(),
                cgroup_path: "/x".into(),
                ..Default::default()
            };
            c.send(2, Req::BindContainer(bind)).await;
            let Some(Resp::Ack(a)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert!(!a.ok);
            assert!(a.error.contains("did not appear"));
            assert!(d.borrow().engine.bound_containers().is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn set_mode_detaches_and_reattaches() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(1, hello()).await;
            c.recv().await.unwrap();
            c.send(
                2,
                Req::SetMode(pb::SetMode {
                    mode: pb::GlobalMode::Detached as i32,
                }),
            )
            .await;
            let Some(Resp::Ack(a)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert!(a.ok);
            assert!(d.borrow().bpf.features().is_empty());
            assert_eq!(
                d.borrow().engine.global_mode(),
                crate::abi::global_mode::DETACHED
            );
            c.send(
                3,
                Req::SetMode(pb::SetMode {
                    mode: pb::GlobalMode::AuditOnly as i32,
                }),
            )
            .await;
            c.recv().await.unwrap();
            assert!(!d.borrow().bpf.features().is_empty());
            c.send(4, Req::SetMode(pb::SetMode { mode: 42 })).await;
            let Some(Resp::Error(e)) = c.recv().await.unwrap().body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::InvalidArgument as i32);
        })
        .await;
    }

    #[tokio::test]
    async fn zero_request_id_rejected() {
        local(async {
            let d = daemon(FakeCgroups::default());
            let mut c = start(&d);
            c.send(1, hello()).await;
            c.recv().await.unwrap();
            c.send(0, Req::GetStatus(pb::GetStatus {})).await;
            let r = c.recv().await.unwrap();
            let Some(Resp::Error(e)) = r.body else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::InvalidArgument as i32);
        })
        .await;
    }
}
