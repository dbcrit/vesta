// SPDX-License-Identifier: Apache-2.0
//! EVT connection (events.proto): the host sends Subscribe{from_seq} once,
//! then cumulative EventAcks; guestd streams EventBatches from the replay
//! buffer and a Heartbeat every interval. Heartbeats are built fresh and
//! never buffered.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::codec::{read_message, write_message, FrameError};
use crate::daemon::Shared;
use crate::policy;
use crate::proto::channel::{self as pb, event_stream_message::Msg, ErrorCode};
use crate::proto::PROTO_MAJOR;

const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Batches sent before acks and heartbeats get a turn again.
const MAX_BATCHES_PER_TURN: usize = 8;

fn msg(m: Msg) -> pb::EventStreamMessage {
    pb::EventStreamMessage { msg: Some(m) }
}

fn err(code: ErrorCode, message: &str) -> pb::EventStreamMessage {
    msg(Msg::Error(pb::Error {
        code: code as i32,
        message: message.into(),
    }))
}

pub fn heartbeat(d: &Shared) -> pb::Heartbeat {
    let mut dm = d.borrow_mut();
    dm.heartbeat_seq += 1;
    let (rss, cpu) = crate::sysinfo::process_usage();
    pb::Heartbeat {
        seq: dm.heartbeat_seq,
        last_event_seq: dm.hub.replay.last_seq(),
        applied_generation: dm.engine.applied_generation(),
        policy_hash: dm.engine.policy_hash().to_vec(),
        progs: dm.bpf.prog_status(false),
        ringbuf_drops: dm.bpf.drop_counts(),
        channel_drops: dm.hub.replay.evicted(),
        guestd_rss_bytes: rss,
        guestd_cpu_ns: cpu,
        global_mode: policy::global_mode_to_proto(dm.engine.global_mode()) as i32,
        interval_ms: dm.cfg.heartbeat_interval_ms,
    }
}

enum Inbound {
    Ack(u64),
    Close(Option<pb::EventStreamMessage>),
}

/// Serves one EVT connection until EOF, a protocol error, or cancellation.
pub async fn serve<S: AsyncRead + AsyncWrite + 'static>(d: Shared, stream: S) {
    let (frame_timeout, write_timeout, interval, notify) = {
        let dm = d.borrow();
        (
            Duration::from_millis(dm.cfg.frame_timeout_ms.into()),
            Duration::from_millis(dm.cfg.write_timeout_ms.into()),
            Duration::from_millis(dm.cfg.heartbeat_interval_ms.into()),
            dm.events_ready.clone(),
        )
    };
    let (mut rd, mut wr) = tokio::io::split(stream);

    let first = tokio::time::timeout(
        SUBSCRIBE_TIMEOUT,
        read_message::<pb::EventStreamMessage, _>(&mut rd, frame_timeout),
    )
    .await;
    let sub = match first {
        Ok(Ok(Some(pb::EventStreamMessage {
            msg: Some(Msg::Subscribe(s)),
        }))) => s,
        Ok(Ok(None)) => return,
        other => {
            tracing::warn!(?other, "EVT: expected Subscribe");
            let _ = write_message(
                &mut wr,
                &err(ErrorCode::Malformed, "first message must be Subscribe"),
                write_timeout,
            )
            .await;
            return;
        }
    };
    if sub.proto_major != PROTO_MAJOR {
        let _ = write_message(
            &mut wr,
            &err(ErrorCode::UnsupportedVersion, "unsupported protocol major"),
            write_timeout,
        )
        .await;
        return;
    }
    let mut cursor = {
        let dm = d.borrow();
        let last = dm.hub.replay.last_seq();
        let oldest = dm.hub.replay.oldest_seq().unwrap_or(last + 1);
        if sub.from_seq > last + 1 {
            // The host is ahead of anything assigned here: it saw a stream
            // this guestd does not continue. Start over from what is buffered.
            tracing::warn!(
                from_seq = sub.from_seq,
                last_seq = last,
                "subscribe from beyond the last event; sending from the oldest buffered"
            );
            oldest
        } else {
            sub.from_seq.max(oldest)
        }
    };
    tracing::info!(from_seq = sub.from_seq, cursor, "EVT subscribed");

    // Reads run in their own task: frame reads are not cancel-safe inside select!.
    let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(16);
    let reader = tokio::task::spawn_local(async move {
        loop {
            // Stop reading (and release the socket) once the session is gone.
            let read = tokio::select! {
                r = read_message::<pb::EventStreamMessage, _>(&mut rd, frame_timeout) => r,
                _ = in_tx.closed() => return,
            };
            let m = match read {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) => {
                    let code = if matches!(e, FrameError::Io(_)) {
                        ErrorCode::Internal
                    } else {
                        ErrorCode::Malformed
                    };
                    let _ = in_tx
                        .send(Inbound::Close(Some(err(code, &e.to_string()))))
                        .await;
                    return;
                }
            };
            let next = match m.msg {
                Some(Msg::EventAck(a)) => Inbound::Ack(a.acked_seq),
                // A second Subscribe or a guest-side variant from the host closes the stream.
                _ => Inbound::Close(Some(err(ErrorCode::Malformed, "unexpected message on EVT"))),
            };
            let close = matches!(next, Inbound::Close(_));
            if in_tx.send(next).await.is_err() || close {
                return;
            }
        }
        let _ = in_tx.send(Inbound::Close(None)).await;
    });

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result: Result<(), FrameError> = async {
        loop {
            // Drain a bounded number of batches, then let acks and the
            // heartbeat in, so a sustained flood cannot starve them.
            let mut more = false;
            for turn in 0..=MAX_BATCHES_PER_TURN {
                if turn == MAX_BATCHES_PER_TURN {
                    more = cursor <= d.borrow().hub.replay.last_seq();
                    break;
                }
                let batch = {
                    let dm = d.borrow();
                    if cursor > dm.hub.replay.last_seq() {
                        break;
                    }
                    dm.hub.replay.batch_from(cursor)
                };
                let Some(last) = batch.last().map(|e| e.seq) else {
                    // Everything from the cursor was evicted; resume after the last assigned seq.
                    cursor = d.borrow().hub.replay.last_seq() + 1;
                    break;
                };
                let first_seq = batch[0].seq;
                write_message(
                    &mut wr,
                    &msg(Msg::EventBatch(pb::EventBatch {
                        first_seq,
                        events: batch,
                    })),
                    write_timeout,
                )
                .await?;
                cursor = last + 1;
            }
            tokio::select! {
                biased;
                inbound = in_rx.recv() => match inbound {
                    Some(Inbound::Ack(seq)) => d.borrow_mut().hub.replay.ack(seq),
                    Some(Inbound::Close(reply)) => {
                        if let Some(r) = reply {
                            let _ = write_message(&mut wr, &r, write_timeout).await;
                        }
                        return Ok(());
                    }
                    None => return Ok(()),
                },
                _ = ticker.tick() => {
                    let hb = heartbeat(&d);
                    write_message(&mut wr, &msg(Msg::Heartbeat(hb)), write_timeout).await?;
                }
                _ = notify.notified() => {}
                () = std::future::ready(()), if more => {}
            }
        }
    }
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "EVT write failed, closing");
    }
    reader.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::fake::{FakeBpf, FakeCgroups};
    use crate::daemon::Daemon;
    use crate::proto::event as ev;
    use crate::resolve::fake::FakeResolver;
    use crate::state::fake::FakeMaps;
    use crate::state::{Baseline, Engine, PolicyMaps};
    use std::cell::RefCell;
    use std::rc::Rc;
    use tokio::io::DuplexStream;

    fn daemon() -> Shared {
        let cfg = crate::config::Config {
            heartbeat_interval_ms: 50,
            ..Default::default()
        };
        let maps: Box<dyn PolicyMaps> = Box::new(FakeMaps::default());
        Rc::new(RefCell::new(Daemon {
            cfg,
            info: Default::default(),
            engine: Engine::new(
                maps,
                Box::new(FakeResolver::default()),
                Baseline {
                    mode: 0,
                    failure: 0,
                },
                false,
            ),
            bpf: Box::new(FakeBpf {
                attached: true,
                drops: vec![],
            }),
            cgroups: Box::new(FakeCgroups::default()),
            cgroup_waits: crate::cgwatch::CgroupWaits::default(),
            hub: crate::events::EventHub::new(4, 1 << 20),
            events_ready: Rc::new(tokio::sync::Notify::new()),
            heartbeat_seq: 0,
            pending_binds: 0,
        }))
    }

    fn push(d: &Shared, action: ev::Action) {
        d.borrow_mut().hub.replay.push(ev::Event {
            action: action as i32,
            ..Default::default()
        });
        d.borrow().events_ready.notify_one();
    }

    async fn send(io: &mut DuplexStream, m: Msg) {
        write_message(io, &msg(m), Duration::from_secs(1))
            .await
            .unwrap();
    }

    async fn recv(io: &mut DuplexStream) -> Option<Msg> {
        read_message::<pb::EventStreamMessage, _>(io, Duration::from_secs(2))
            .await
            .unwrap()
            .and_then(|m| m.msg)
    }

    /// Next non-heartbeat message.
    async fn recv_data(io: &mut DuplexStream) -> Option<Msg> {
        loop {
            match recv(io).await {
                Some(Msg::Heartbeat(_)) => continue,
                other => return other,
            }
        }
    }

    async fn local<F: std::future::Future<Output = ()>>(f: F) {
        tokio::task::LocalSet::new().run_until(f).await;
    }

    fn subscribe(from_seq: u64) -> Msg {
        Msg::Subscribe(pb::Subscribe {
            proto_major: 1,
            proto_minor: 0,
            from_seq,
        })
    }

    #[tokio::test]
    async fn replays_then_streams_and_acks() {
        local(async {
            let d = daemon();
            push(&d, ev::Action::Audited);
            push(&d, ev::Action::Denied);
            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, subscribe(0)).await;
            let Some(Msg::EventBatch(b)) = recv_data(&mut io).await else {
                panic!()
            };
            assert_eq!(b.first_seq, 1);
            assert_eq!(
                b.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
                vec![1, 2]
            );

            push(&d, ev::Action::Audited);
            let Some(Msg::EventBatch(b)) = recv_data(&mut io).await else {
                panic!()
            };
            assert_eq!(b.first_seq, 3);

            send(&mut io, Msg::EventAck(pb::EventAck { acked_seq: 2 })).await;
            // Heartbeats keep flowing and reflect the buffer.
            let hb = loop {
                if let Some(Msg::Heartbeat(h)) = recv(&mut io).await {
                    if h.seq >= 2 {
                        break h;
                    }
                }
            };
            assert_eq!(hb.last_event_seq, 3);
            assert_eq!(hb.interval_ms, 50);
            assert_eq!(d.borrow().hub.replay.oldest_seq(), Some(3));
        })
        .await;
    }

    #[tokio::test]
    async fn resubscribe_resumes_and_shows_gaps() {
        local(async {
            let d = daemon();
            for _ in 0..6 {
                push(&d, ev::Action::Audited); // buffer holds 4: seqs 3..=6
            }
            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, subscribe(2)).await;
            let Some(Msg::EventBatch(b)) = recv_data(&mut io).await else {
                panic!()
            };
            assert_eq!(
                b.first_seq, 3,
                "seq 2 was evicted: the gap is visible to the host"
            );
            assert_eq!(d.borrow().hub.replay.evicted(), 2);
        })
        .await;
    }

    #[tokio::test]
    async fn subscribe_beyond_last_seq_restarts_from_oldest() {
        local(async {
            let d = daemon();
            push(&d, ev::Action::Audited);
            push(&d, ev::Action::Audited);
            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, subscribe(50_000)).await;
            let Some(Msg::EventBatch(b)) = recv_data(&mut io).await else {
                panic!()
            };
            assert_eq!(b.first_seq, 1);
        })
        .await;
    }

    #[tokio::test]
    async fn flood_does_not_starve_heartbeats() {
        local(async {
            let d = daemon();
            d.borrow_mut().hub = crate::events::EventHub::new(1_000_000, 64 << 20);
            for _ in 0..(crate::events::MAX_BATCH_EVENTS * MAX_BATCHES_PER_TURN * 3) {
                push(&d, ev::Action::Audited);
            }
            let (mut io, srv) = tokio::io::duplex(1 << 20);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, subscribe(0)).await;
            let mut batches = 0;
            loop {
                match recv(&mut io).await {
                    Some(Msg::EventBatch(_)) => {
                        batches += 1;
                        // Keep the backlog non-empty.
                        for _ in 0..crate::events::MAX_BATCH_EVENTS {
                            push(&d, ev::Action::Audited);
                        }
                    }
                    Some(Msg::Heartbeat(_)) => break,
                    other => panic!("{other:?}"),
                }
                assert!(batches < 10_000, "no heartbeat while flooding");
            }
        })
        .await;
    }

    #[tokio::test]
    async fn protocol_violations_close() {
        local(async {
            let d = daemon();
            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, Msg::EventAck(pb::EventAck { acked_seq: 1 })).await;
            let Some(Msg::Error(e)) = recv(&mut io).await else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::Malformed as i32);
            assert!(recv(&mut io).await.is_none());

            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(&mut io, subscribe(0)).await;
            send(&mut io, subscribe(0)).await;
            let Some(Msg::Error(e)) = recv_data(&mut io).await else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::Malformed as i32);

            let (mut io, srv) = tokio::io::duplex(1 << 16);
            tokio::task::spawn_local(serve(d.clone(), srv));
            send(
                &mut io,
                Msg::Subscribe(pb::Subscribe {
                    proto_major: 9,
                    ..Default::default()
                }),
            )
            .await;
            let Some(Msg::Error(e)) = recv(&mut io).await else {
                panic!()
            };
            assert_eq!(e.code, ErrorCode::UnsupportedVersion as i32);
        })
        .await;
    }
}
