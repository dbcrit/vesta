// SPDX-License-Identifier: Apache-2.0
//! Channel framing (control.proto): u32 big-endian length N, 1 <= N <= 1 MiB,
//! followed by one protobuf message. The length is validated before any
//! allocation, and once a frame has started it must complete within a deadline.

use std::io;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HEADER_LEN: usize = 4;
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("frame length {0} outside 1..={MAX_FRAME}")]
    BadLength(u64),
    #[error("timed out reading a frame")]
    Timeout,
    #[error("connection closed mid-frame")]
    Truncated,
    #[error("undecodable message: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Validates a frame header and returns the body length.
pub fn body_len(header: [u8; HEADER_LEN]) -> Result<usize, FrameError> {
    let n = u32::from_be_bytes(header);
    match usize::try_from(n) {
        Ok(n) if (1..=MAX_FRAME).contains(&n) => Ok(n),
        _ => Err(FrameError::BadLength(u64::from(n))),
    }
}

async fn read_exact_or_truncated<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> Result<(), FrameError> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(e) => Err(e.into()),
    }
}

/// Reads one frame body. Waiting for the first header byte has no deadline
/// (an idle connection is fine); the rest of the frame must arrive within
/// `frame_timeout`. Returns `Ok(None)` on a clean EOF between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    frame_timeout: Duration,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_LEN];
    let n = r.read(&mut header[..1]).await?;
    if n == 0 {
        return Ok(None);
    }
    let rest = async {
        read_exact_or_truncated(r, &mut header[1..]).await?;
        let len = body_len(header)?;
        let mut body = vec![0u8; len];
        read_exact_or_truncated(r, &mut body).await?;
        Ok::<_, FrameError>(body)
    };
    match tokio::time::timeout(frame_timeout, rest).await {
        Ok(res) => res.map(Some),
        Err(_) => Err(FrameError::Timeout),
    }
}

/// Reads and decodes one message; `Ok(None)` on clean EOF.
pub async fn read_message<M: Message + Default, R: AsyncRead + Unpin>(
    r: &mut R,
    frame_timeout: Duration,
) -> Result<Option<M>, FrameError> {
    match read_frame(r, frame_timeout).await? {
        Some(body) => Ok(Some(M::decode(body.as_slice())?)),
        None => Ok(None),
    }
}

/// Encodes a message as one frame. Fails (without truncating) if the encoded
/// message is empty or larger than `MAX_FRAME`.
pub fn encode_frame<M: Message>(m: &M) -> Result<Vec<u8>, FrameError> {
    let len = m.encoded_len();
    if len == 0 || len > MAX_FRAME {
        return Err(FrameError::BadLength(len as u64));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + len);
    // len <= MAX_FRAME, so it fits in u32.
    out.extend_from_slice(&(len as u32).to_be_bytes());
    m.encode_raw(&mut out);
    Ok(out)
}

/// Writes a message as one frame within `timeout`.
pub async fn write_message<M: Message, W: AsyncWrite + Unpin>(
    w: &mut W,
    m: &M,
    timeout: Duration,
) -> Result<(), FrameError> {
    let frame = encode_frame(m)?;
    match tokio::time::timeout(timeout, async {
        w.write_all(&frame).await?;
        w.flush().await
    })
    .await
    {
        Ok(res) => Ok(res?),
        Err(_) => Err(FrameError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::channel::{control_request, ControlRequest, GetStatus};

    const T: Duration = Duration::from_secs(1);

    fn req() -> ControlRequest {
        ControlRequest {
            request_id: 7,
            body: Some(control_request::Body::GetStatus(GetStatus {})),
        }
    }

    #[tokio::test]
    async fn roundtrip() {
        let frame = encode_frame(&req()).unwrap();
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        let mut r = frame.as_slice();
        let got: ControlRequest = read_message(&mut r, T).await.unwrap().unwrap();
        assert_eq!(got, req());
        assert!(read_message::<ControlRequest, _>(&mut r, T)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rejects_zero_and_oversize_lengths_without_allocating() {
        for n in [0u32, (MAX_FRAME as u32) + 1, u32::MAX] {
            let bytes = n.to_be_bytes();
            let mut r = bytes.as_slice();
            assert!(
                matches!(read_frame(&mut r, T).await, Err(FrameError::BadLength(_))),
                "len {n}"
            );
        }
    }

    #[tokio::test]
    async fn max_frame_is_accepted() {
        let mut data = (MAX_FRAME as u32).to_be_bytes().to_vec();
        data.resize(4 + MAX_FRAME, 0);
        let mut r = data.as_slice();
        assert_eq!(
            read_frame(&mut r, T).await.unwrap().unwrap().len(),
            MAX_FRAME
        );
    }

    #[tokio::test]
    async fn truncated_frames() {
        let frame = encode_frame(&req()).unwrap();
        for cut in 1..frame.len() {
            let mut r = &frame[..cut];
            assert!(
                matches!(read_frame(&mut r, T).await, Err(FrameError::Truncated)),
                "cut {cut}"
            );
        }
    }

    #[tokio::test]
    async fn stalled_frame_times_out() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0, 0, 0, 10, 1, 2]).await.unwrap();
        let res = read_frame(&mut server, Duration::from_millis(50)).await;
        assert!(matches!(res, Err(FrameError::Timeout)));
        drop(client);
    }

    #[tokio::test]
    async fn garbage_body_is_a_decode_error() {
        let mut data = 3u32.to_be_bytes().to_vec();
        data.extend_from_slice(&[0xff, 0xff, 0xff]);
        let mut r = data.as_slice();
        assert!(matches!(
            read_message::<ControlRequest, _>(&mut r, T).await,
            Err(FrameError::Decode(_))
        ));
    }

    #[tokio::test]
    async fn random_bytes_never_panic() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for i in 0..5_000usize {
            let len = i % 300;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf.push(x as u8);
            }
            if i % 2 == 0 && len >= 4 {
                // Plausible small length so bodies get decoded.
                buf[..4].copy_from_slice(&((len as u32 - 4).max(1)).to_be_bytes());
            }
            let mut r = buf.as_slice();
            while let Ok(Some(_)) = read_message::<ControlRequest, _>(&mut r, T).await {}
        }
    }

    #[test]
    fn encode_rejects_empty() {
        assert!(matches!(
            encode_frame(&ControlRequest::default()),
            Err(FrameError::BadLength(0))
        ));
    }
}
