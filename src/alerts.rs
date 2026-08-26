//! Operator-only event-driven iLert alert follower.

use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, RETRY_AFTER};
use serde::Deserialize;
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::{credentials, llm::secure_http_client_async, login};

const ALERT_STREAM_PATH: &str = "/api/operator/alerts/stream";
const ALERT_STREAM_MAX_PENDING_BYTES: usize = 512 * 1024;
const ALERT_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ALERT_STREAM_PROBE_TIMEOUT: Duration = Duration::from_secs(75);
const ALERT_STREAM_SILENCE_TIMEOUT: Duration = Duration::from_secs(45);
const ALERT_STREAM_RECONNECT_BASE: Duration = Duration::from_secs(3);
const ALERT_STREAM_RECONNECT_MAX: Duration = Duration::from_secs(60);
const ALERT_STREAM_RETRY_AFTER_MAX: Duration = Duration::from_secs(60 * 60);
const ALERT_STREAM_DEGRADED_AFTER_FAILURES: u32 = 3;
const POSTGRES_MAX_SEQUENCE: u64 = i64::MAX as u64;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct OperatorAlert {
    sequence: String,
    alert_id: String,
    event_type: String,
    status: String,
    priority: String,
    summary: String,
}

pub async fn run_watch(once: bool, probe: bool) -> Result<i32> {
    let credentials_path = credentials::default_path()?;
    let _watch_lock = credentials::AlertWatchLock::acquire(&credentials_path)?;
    let interrupted_exit = if once || probe { 130 } else { 0 };
    if probe {
        tokio::select! {
            result = timeout(ALERT_STREAM_PROBE_TIMEOUT, watch(&credentials_path, once, probe)) => {
                result.context("operator alert notification probe timed out")?
            },
            signal = tokio::signal::ctrl_c() => {
                signal.context("waiting for alert watcher shutdown")?;
                Ok(interrupted_exit)
            }
        }
    } else {
        tokio::select! {
            result = watch(&credentials_path, once, probe) => result,
            signal = tokio::signal::ctrl_c() => {
                signal.context("waiting for alert watcher shutdown")?;
                Ok(interrupted_exit)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorState {
    issuer: String,
    sequence: u64,
}

fn cursor_state(issuer: &str, sequence: Option<u64>) -> Option<CursorState> {
    sequence.map(|sequence| CursorState {
        issuer: issuer.to_string(),
        sequence,
    })
}

async fn watch(credentials_path: &Path, once: bool, probe: bool) -> Result<i32> {
    let mut cursor: Option<CursorState> = None;
    let mut consecutive_failures = 0_u32;
    let mut degraded = false;
    loop {
        let outcome =
            watch_connection(credentials_path, cursor.as_ref(), once, probe, degraded).await?;
        if once && outcome.notification_received {
            return Ok(0);
        }
        if probe && outcome.probe_validated {
            return Ok(0);
        }

        if update_watch_health(&mut consecutive_failures, &mut degraded, &outcome) {
            eprintln!("postil: operator alert notifications unavailable; reconnecting");
        }
        let reconnect_delay = reconnect_delay(consecutive_failures, outcome.retry_after);
        cursor = outcome.last_cursor;
        sleep(reconnect_delay).await;
    }
}

struct ConnectionOutcome {
    last_cursor: Option<CursorState>,
    notification_received: bool,
    probe_validated: bool,
    stable_connection: bool,
    healthy_reconnect: bool,
    retry_after: Option<Duration>,
}

impl ConnectionOutcome {
    fn retry(
        last_cursor: Option<CursorState>,
        retry_after: Option<Duration>,
        healthy_reconnect: bool,
    ) -> Self {
        Self {
            last_cursor,
            notification_received: false,
            probe_validated: false,
            stable_connection: false,
            healthy_reconnect,
            retry_after,
        }
    }
}

fn update_watch_health(
    consecutive_failures: &mut u32,
    degraded: &mut bool,
    outcome: &ConnectionOutcome,
) -> bool {
    if outcome.stable_connection && *degraded {
        *degraded = false;
    }
    if outcome.healthy_reconnect {
        *consecutive_failures = 0;
    } else if outcome.stable_connection {
        *consecutive_failures = 1;
    } else {
        *consecutive_failures = consecutive_failures.saturating_add(1);
    }
    let became_degraded =
        !*degraded && *consecutive_failures >= ALERT_STREAM_DEGRADED_AFTER_FAILURES;
    if became_degraded {
        *degraded = true;
    }
    became_degraded
}

fn mark_connection_stable(stable_connection: &mut bool, frame_stable: bool) -> bool {
    if frame_stable && !*stable_connection {
        *stable_connection = true;
        true
    } else {
        false
    }
}

async fn watch_connection(
    credentials_path: &Path,
    last_cursor: Option<&CursorState>,
    once: bool,
    probe: bool,
    announce_recovery: bool,
) -> Result<ConnectionOutcome> {
    let session = match timeout(
        ALERT_STREAM_CONNECT_TIMEOUT,
        login::resolve_stored_alert_session(credentials_path),
    )
    .await
    {
        Ok(Ok(Some(session))) => session,
        Ok(Ok(None)) => anyhow::bail!("postil login required for operator alert notifications"),
        Ok(Err(error)) => match login::token_resolution_retry_delay(&error) {
            Some(delay) => {
                return Ok(ConnectionOutcome::retry(
                    last_cursor.cloned(),
                    (!delay.is_zero()).then_some(delay),
                    false,
                ));
            }
            None => return Err(error),
        },
        Err(_) => {
            return Ok(ConnectionOutcome::retry(last_cursor.cloned(), None, false));
        }
    };
    let issuer = session.issuer;
    let token = session.token;
    let mut cursor = match last_cursor.filter(|cursor| cursor.issuer == issuer) {
        Some(cursor) => Some(cursor.sequence),
        None => credentials::read_alert_cursor(credentials_path, &issuer)?,
    };
    let endpoint = format!("{}{ALERT_STREAM_PATH}", issuer.trim_end_matches('/'));
    let client = match timeout(
        ALERT_STREAM_CONNECT_TIMEOUT,
        secure_http_client_async(&issuer),
    )
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(_)) | Err(_) => {
            return Ok(ConnectionOutcome::retry(
                cursor_state(&issuer, cursor),
                None,
                false,
            ));
        }
    };
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("stored postil login contains an invalid access credential")?;
    authorization.set_sensitive(true);
    let mut request = client
        .get(&endpoint)
        .header(ACCEPT, "text/event-stream")
        .header(AUTHORIZATION, authorization);
    if let Some(last_event_id) = cursor {
        request = request.header("last-event-id", last_event_id.to_string());
    }
    let mut response = match timeout(ALERT_STREAM_CONNECT_TIMEOUT, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => {
            return Ok(ConnectionOutcome::retry(
                cursor_state(&issuer, cursor),
                None,
                false,
            ));
        }
    };
    let requested_delay = retry_after_delay(&response);
    match response.status().as_u16() {
        200 => {}
        401 => {
            let current = timeout(
                ALERT_STREAM_CONNECT_TIMEOUT,
                login::resolve_stored_alert_session(credentials_path),
            )
            .await;
            match current {
                Ok(Ok(Some(current))) if current.issuer != issuer || current.token != token => {
                    return Ok(ConnectionOutcome::retry(
                        cursor_state(&issuer, cursor),
                        Some(Duration::ZERO),
                        true,
                    ));
                }
                Ok(Err(error)) if login::token_resolution_retry_delay(&error).is_some() => {
                    return Ok(ConnectionOutcome::retry(
                        cursor_state(&issuer, cursor),
                        login::token_resolution_retry_delay(&error)
                            .filter(|delay| !delay.is_zero()),
                        false,
                    ));
                }
                Err(_) => {
                    return Ok(ConnectionOutcome::retry(
                        cursor_state(&issuer, cursor),
                        None,
                        false,
                    ));
                }
                _ => anyhow::bail!(
                    "operator alert authorization was rejected; run `postil login` again"
                ),
            }
        }
        404 => anyhow::bail!("operator alert notifications are unavailable for this login"),
        408 | 425 | 429 | 500 | 502 | 503 | 504 => {
            return Ok(ConnectionOutcome::retry(
                cursor_state(&issuer, cursor),
                requested_delay,
                false,
            ));
        }
        status => anyhow::bail!("operator alert notification stream returned HTTP {status}"),
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    anyhow::ensure!(
        content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream")),
        "operator alert notification stream returned an invalid content type"
    );

    let mut decoder = SseDecoder::default();
    let mut frame_deadline = Instant::now() + ALERT_STREAM_SILENCE_TIMEOUT;
    let mut stable_connection = false;
    let mut routine_close = false;
    let mut stream_retry_after = None;
    loop {
        let chunk = match timeout_at(frame_deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => {
                return Ok(ConnectionOutcome {
                    last_cursor: cursor_state(&issuer, cursor),
                    notification_received: false,
                    probe_validated: false,
                    stable_connection,
                    healthy_reconnect: routine_close,
                    retry_after: stream_retry_after,
                });
            }
            Ok(Err(_)) | Err(_) => {
                return Ok(ConnectionOutcome {
                    last_cursor: cursor_state(&issuer, cursor),
                    notification_received: false,
                    probe_validated: false,
                    stable_connection,
                    healthy_reconnect: false,
                    retry_after: stream_retry_after,
                });
            }
        };
        let frames = decoder.push(&chunk)?;
        if !frames.is_empty() {
            frame_deadline = Instant::now() + ALERT_STREAM_SILENCE_TIMEOUT;
        }
        for frame in frames {
            let (event, requested_retry, frame_stable, frame_routine_close) = match frame {
                SseFrame::Control {
                    retry_after,
                    stable,
                    routine_reconnect,
                } => (None, retry_after, stable, routine_reconnect),
                SseFrame::Event { event, retry_after } => (Some(event), retry_after, true, false),
            };
            if requested_retry.is_some() {
                stream_retry_after = requested_retry;
            }
            routine_close |= frame_routine_close;
            if mark_connection_stable(&mut stable_connection, frame_stable) && announce_recovery {
                eprintln!("postil: operator alert notifications recovered");
            }
            if probe {
                return Ok(ConnectionOutcome {
                    last_cursor: cursor_state(&issuer, cursor),
                    notification_received: false,
                    probe_validated: true,
                    stable_connection,
                    healthy_reconnect: true,
                    retry_after: stream_retry_after,
                });
            }
            let Some(event) = event else {
                continue;
            };
            let alert: OperatorAlert = serde_json::from_str(&event.data)
                .context("operator alert notification contained invalid JSON")?;
            let alert_sequence = parse_sequence(&alert.sequence)?;
            anyhow::ensure!(
                alert_sequence == event.id,
                "operator alert notification sequence did not match its SSE cursor"
            );
            if let Some(previous) = cursor {
                anyhow::ensure!(
                    event.id > previous,
                    "operator alert notification sequence was not increasing"
                );
            }
            let delivery = credentials::deliver_alert_with_cursor(
                credentials_path,
                &issuer,
                &token,
                event.id,
                || {
                    let mut output = io::stdout().lock();
                    writeln!(
                        output,
                        "iLert {} alert {} {}: {} ({})",
                        terminal_text(&alert.priority),
                        terminal_text(&alert.alert_id),
                        terminal_text(&alert.event_type),
                        terminal_text(&alert.summary),
                        terminal_text(&alert.status)
                    )?;
                    output.flush()?;
                    Ok(())
                },
            )
            .await?;
            match delivery {
                credentials::AlertCursorDelivery::Delivered(sequence) => {
                    cursor = Some(sequence);
                    if once {
                        return Ok(ConnectionOutcome {
                            last_cursor: cursor_state(&issuer, cursor),
                            notification_received: true,
                            probe_validated: false,
                            stable_connection: true,
                            healthy_reconnect: true,
                            retry_after: stream_retry_after,
                        });
                    }
                }
                credentials::AlertCursorDelivery::AlreadyRecorded(sequence) => {
                    cursor = Some(sequence);
                }
                credentials::AlertCursorDelivery::SessionChanged => {
                    return Ok(ConnectionOutcome {
                        last_cursor: cursor_state(&issuer, cursor),
                        notification_received: false,
                        probe_validated: false,
                        stable_connection: true,
                        healthy_reconnect: true,
                        retry_after: Some(Duration::ZERO),
                    });
                }
            }
        }
    }
}

fn retry_after_delay(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|delay| delay.min(ALERT_STREAM_RETRY_AFTER_MAX))
}

fn reconnect_delay(failures: u32, requested: Option<Duration>) -> Duration {
    if let Some(requested) = requested {
        return requested.min(ALERT_STREAM_RETRY_AFTER_MAX);
    }
    let exponent = failures.saturating_sub(1).min(4);
    let multiplier = 1_u32 << exponent;
    let base = ALERT_STREAM_RECONNECT_BASE
        .saturating_mul(multiplier)
        .min(ALERT_STREAM_RECONNECT_MAX);
    let jitter_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis() as u64;
    base.saturating_add(Duration::from_millis(jitter_millis))
        .min(ALERT_STREAM_RECONNECT_MAX)
}

fn parse_sequence(value: &str) -> Result<u64> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 19
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value == "0" || !value.starts_with('0')),
        "operator alert notification contained an invalid sequence"
    );
    let sequence = value
        .parse::<u64>()
        .context("operator alert notification sequence was out of range")?;
    anyhow::ensure!(
        sequence <= POSTGRES_MAX_SEQUENCE,
        "operator alert notification sequence was out of range"
    );
    Ok(sequence)
}

fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if unsafe_terminal_character(character) {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

fn unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

#[derive(Debug, PartialEq, Eq)]
enum SseFrame {
    Control {
        retry_after: Option<Duration>,
        stable: bool,
        routine_reconnect: bool,
    },
    Event {
        event: SseEvent,
        retry_after: Option<Duration>,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct SseEvent {
    id: u64,
    data: String,
}

#[derive(Default)]
struct SseDecoder {
    pending: Vec<u8>,
}

impl SseDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseFrame>> {
        self.pending.extend_from_slice(bytes);
        anyhow::ensure!(
            self.pending.len() <= ALERT_STREAM_MAX_PENDING_BYTES,
            "operator alert notification exceeded the stream buffer limit"
        );
        let mut frames = Vec::new();
        while let Some((end, consumed)) = event_boundary(&self.pending) {
            let block = self.pending.drain(..consumed).collect::<Vec<_>>();
            let mut id = None;
            let mut data = Vec::new();
            let mut control = false;
            let mut retry_after = None;
            let mut stable = false;
            let mut routine_reconnect = false;
            for line in sse_lines(&block[..end])? {
                if let Some(comment) = line.strip_prefix(':') {
                    control = true;
                    match comment.trim_start() {
                        "keepalive" => stable = true,
                        "replay batch" | "rotate" => {
                            stable = true;
                            routine_reconnect = true;
                        }
                        _ => {}
                    }
                    continue;
                }
                if let Some(value) = line.strip_prefix("retry:") {
                    control = true;
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    retry_after = value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit())
                        .then(|| value.parse::<u64>().ok())
                        .flatten()
                        .map(Duration::from_millis)
                        .map(|delay| delay.min(ALERT_STREAM_RETRY_AFTER_MAX));
                    continue;
                }
                if let Some(value) = line.strip_prefix("id:") {
                    id = Some(parse_sequence(value.strip_prefix(' ').unwrap_or(value))?);
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value));
                }
            }
            if data.is_empty() {
                if control {
                    frames.push(SseFrame::Control {
                        retry_after,
                        stable,
                        routine_reconnect,
                    });
                }
                continue;
            }
            frames.push(SseFrame::Event {
                event: SseEvent {
                    id: id.ok_or_else(|| {
                        anyhow::anyhow!("operator alert notification omitted its SSE cursor")
                    })?,
                    data: data.join("\n"),
                },
                retry_after,
            });
        }
        Ok(frames)
    }
}

fn sse_lines(bytes: &[u8]) -> Result<Vec<&str>> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .map(|offset| start + offset)
            .unwrap_or(bytes.len());
        lines.push(
            std::str::from_utf8(&bytes[start..end])
                .context("operator alert notification was not UTF-8")?,
        );
        if end == bytes.len() {
            break;
        }
        start = end + 1;
        if bytes[end] == b'\r' && bytes.get(start) == Some(&b'\n') {
            start += 1;
        }
    }
    Ok(lines)
}

fn event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut start = 0;
    loop {
        let end = bytes[start..]
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .map(|offset| start + offset)?;
        let mut next = end + 1;
        if bytes[end] == b'\r' && bytes.get(next) == Some(&b'\n') {
            next += 1;
        }
        if end == start {
            return Some((start, next));
        }
        start = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_fragmented_events_and_exposes_keepalives() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"retry: 3000\n: con").unwrap().is_empty());
        assert_eq!(
            decoder
                .push(b"nected\n\nid: 12\nevent: alert-created\ndata: {\"sequence\":\"12\"}\n\n")
                .unwrap(),
            vec![
                SseFrame::Control {
                    retry_after: Some(Duration::from_secs(3)),
                    stable: false,
                    routine_reconnect: false,
                },
                SseFrame::Event {
                    event: SseEvent {
                        id: 12,
                        data: "{\"sequence\":\"12\"}".into(),
                    },
                    retry_after: None,
                },
            ]
        );
    }

    #[test]
    fn distinguishes_service_rotation_and_replay_from_initial_connection() {
        let mut decoder = SseDecoder::default();
        assert_eq!(
            decoder
                .push(b": keepalive\n\n: rotate\n\nretry: 100\n: replay batch\n\n")
                .unwrap(),
            vec![
                SseFrame::Control {
                    retry_after: None,
                    stable: true,
                    routine_reconnect: false,
                },
                SseFrame::Control {
                    retry_after: None,
                    stable: true,
                    routine_reconnect: true,
                },
                SseFrame::Control {
                    retry_after: Some(Duration::from_millis(100)),
                    stable: true,
                    routine_reconnect: true,
                },
            ]
        );
    }

    #[test]
    fn degraded_health_latches_until_one_stable_connection() {
        let unstable = ConnectionOutcome::retry(None, None, false);
        let mut consecutive_failures = 0;
        let mut degraded = false;

        assert!(!update_watch_health(
            &mut consecutive_failures,
            &mut degraded,
            &unstable
        ));
        assert!(!update_watch_health(
            &mut consecutive_failures,
            &mut degraded,
            &unstable
        ));
        assert!(update_watch_health(
            &mut consecutive_failures,
            &mut degraded,
            &unstable
        ));
        assert!(degraded);
        assert!(!update_watch_health(
            &mut consecutive_failures,
            &mut degraded,
            &unstable
        ));

        let stable = ConnectionOutcome {
            last_cursor: None,
            notification_received: false,
            probe_validated: false,
            stable_connection: true,
            healthy_reconnect: false,
            retry_after: None,
        };
        assert!(!update_watch_health(
            &mut consecutive_failures,
            &mut degraded,
            &stable
        ));
        assert!(!degraded);
        assert_eq!(consecutive_failures, 1);

        let mut connection_stable = false;
        assert!(!mark_connection_stable(&mut connection_stable, false));
        assert!(mark_connection_stable(&mut connection_stable, true));
        assert!(!mark_connection_stable(&mut connection_stable, true));
    }

    #[test]
    fn decodes_crlf_cr_only_and_mixed_line_endings() {
        for bytes in [
            b"id: 13\r\ndata: {\"sequence\":\"13\"}\r\n\r\n".as_slice(),
            b"id: 13\rdata: {\"sequence\":\"13\"}\r\r".as_slice(),
            b"id: 13\ndata: {\"sequence\":\"13\"}\r\n\n".as_slice(),
        ] {
            let mut decoder = SseDecoder::default();
            assert_eq!(
                decoder.push(bytes).unwrap(),
                vec![SseFrame::Event {
                    event: SseEvent {
                        id: 13,
                        data: "{\"sequence\":\"13\"}".into(),
                    },
                    retry_after: None,
                }]
            );
        }
    }

    #[test]
    fn rejects_unbounded_cursorless_or_noncanonical_data() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: {}\n\n").is_err());
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"id: 01\ndata: {}\n\n").is_err());
        let mut decoder = SseDecoder::default();
        assert!(
            decoder
                .push(&vec![b'x'; ALERT_STREAM_MAX_PENDING_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn parses_the_service_notification_contract() {
        let alert: OperatorAlert = serde_json::from_str(
            r#"{"sequence":"42","alertId":"1533","eventType":"alert-created","status":"PENDING","priority":"HIGH","summary":"Review failed"}"#,
        )
        .unwrap();
        assert_eq!(parse_sequence(&alert.sequence).unwrap(), 42);
        assert_eq!(alert.alert_id, "1533");
    }

    #[test]
    fn strips_terminal_controls_and_directional_formatting() {
        assert_eq!(
            terminal_text("HIGH\u{1b}[31m\n\u{202e}alert\u{2066}"),
            "HIGH [31m  alert "
        );
    }

    #[test]
    fn backoff_honors_bounded_retry_after() {
        assert_eq!(
            reconnect_delay(1, Some(Duration::from_millis(100))),
            Duration::from_millis(100)
        );
        assert_eq!(
            reconnect_delay(1, Some(Duration::from_secs(120))),
            Duration::from_secs(120)
        );
        assert_eq!(
            reconnect_delay(10, Some(Duration::from_secs(7200))),
            ALERT_STREAM_RETRY_AFTER_MAX
        );
        assert!(reconnect_delay(1, None) >= ALERT_STREAM_RECONNECT_BASE);
    }
}
