use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
};

const MAX_BRIDGE_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_BRIDGE_INPUT_BYTES: usize = 64 * 1024;
const BRIDGE_FAILURE: &str = "Local Core is unavailable";

type SharedTerminalBridge = Arc<Mutex<Option<BridgeProcess>>>;
struct LatencyBridge(SharedTerminalBridge);

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoreStatus {
    api_version: String,
    signed_in: bool,
    device_id: String,
    device_name: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeviceSummary {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransportSummary {
    name: String,
    available: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoreInventory {
    devices: Vec<DeviceSummary>,
    transports: Vec<TransportSummary>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConnectionSummary {
    id: String,
    device_id: String,
    state: String,
    path: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConnectionLatencySummary {
    rtt_micros: u64,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TerminalReadSummary {
    #[serde(default)]
    data: String,
    closed: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OkResponse {
    ok: bool,
}

#[derive(Serialize)]
struct IdRequest {
    id: String,
}

#[derive(Serialize)]
struct TerminalWriteRequest {
    id: String,
    data: String,
}

#[derive(Serialize)]
struct TerminalResizeRequest {
    id: String,
    cols: u16,
    rows: u16,
}

#[derive(Serialize)]
struct PersistentRequest<R> {
    op: &'static str,
    request: R,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentResponse {
    ok: bool,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

struct BridgeProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl BridgeProcess {
    fn spawn() -> Result<Self, ()> {
        let current_exe = env::current_exe().map_err(|_| ())?;
        let bridge = sibling_bridge_path(&current_exe).map_err(|_| ())?;
        let mut child = Command::new(bridge)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ())?;

        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                terminate_child(&mut child);
                return Err(());
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_child(&mut child);
                return Err(());
            }
        };

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn request<R: Serialize, T: DeserializeOwned>(
        &mut self,
        op: &'static str,
        request: R,
    ) -> Result<T, ()> {
        let mut encoded = serde_json::to_vec(&PersistentRequest { op, request }).map_err(|_| ())?;
        if encoded.is_empty() || encoded.len() >= MAX_BRIDGE_INPUT_BYTES {
            return Err(());
        }
        encoded.push(b'\n');

        self.stdin.write_all(&encoded).map_err(|_| ())?;
        self.stdin.flush().map_err(|_| ())?;

        let mut output = Vec::new();
        let bytes_read = {
            let mut limited = (&mut self.stdout).take(MAX_BRIDGE_OUTPUT_BYTES + 1);
            limited.read_until(b'\n', &mut output).map_err(|_| ())?
        };
        if bytes_read == 0
            || output.len() > MAX_BRIDGE_OUTPUT_BYTES as usize
            || !output.ends_with(b"\n")
        {
            return Err(());
        }
        decode_persistent_response(&output)
    }
}

impl Drop for BridgeProcess {
    fn drop(&mut self) {
        terminate_child(&mut self.child);
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn bridge_executable_name() -> &'static str {
    if cfg!(windows) {
        "wd-desktop-bridge.exe"
    } else {
        "wd-desktop-bridge"
    }
}

fn sibling_bridge_path(current_exe: &Path) -> io::Result<PathBuf> {
    let current_exe = fs::canonicalize(current_exe)?;
    let parent = current_exe.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "desktop executable has no parent",
        )
    })?;
    let bridge = parent.join(bridge_executable_name());
    let metadata = fs::symlink_metadata(&bridge)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "desktop bridge is not a regular file",
        ));
    }
    Ok(bridge)
}

fn parse_bridge_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ()> {
    if bytes.len() > MAX_BRIDGE_OUTPUT_BYTES as usize {
        return Err(());
    }
    serde_json::from_slice(bytes).map_err(|_| ())
}

fn decode_persistent_response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ()> {
    let response: PersistentResponse = parse_bridge_json(bytes)?;
    if !response.ok || response.error.is_some() {
        return Err(());
    }
    let result = response.result.ok_or(())?;
    serde_json::from_value(result).map_err(|_| ())
}

fn read_bridge_output<T: DeserializeOwned>(mut child: Child) -> Result<T, ()> {
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_child(&mut child);
            return Err(());
        }
    };
    let mut output = Vec::new();
    if stdout
        .by_ref()
        .take(MAX_BRIDGE_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)
        .is_err()
    {
        terminate_child(&mut child);
        return Err(());
    }
    if output.len() > MAX_BRIDGE_OUTPUT_BYTES as usize {
        terminate_child(&mut child);
        return Err(());
    }

    let status = child.wait().map_err(|_| ())?;
    if !status.success() {
        return Err(());
    }
    parse_bridge_json(&output)
}

fn load_bridge_json<T: DeserializeOwned>(command: &'static str) -> Result<T, ()> {
    let current_exe = env::current_exe().map_err(|_| ())?;
    let bridge = sibling_bridge_path(&current_exe).map_err(|_| ())?;
    let child = Command::new(bridge)
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    read_bridge_output(child)
}

fn with_terminal_bridge<R: Serialize, T: DeserializeOwned>(
    bridge: &SharedTerminalBridge,
    op: &'static str,
    request: R,
) -> Result<T, ()> {
    let mut guard = bridge.lock().map_err(|_| ())?;
    if guard.is_none() {
        *guard = Some(BridgeProcess::spawn()?);
    }

    let result = guard.as_mut().ok_or(())?.request(op, request);
    if result.is_err() {
        guard.take();
    }
    result
}

async fn terminal_bridge_request<R, T>(
    bridge: SharedTerminalBridge,
    op: &'static str,
    request: R,
) -> Result<T, String>
where
    R: Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || with_terminal_bridge(&bridge, op, request))
        .await
        .map_err(|_| BRIDGE_FAILURE.to_string())?
        .map_err(|_| BRIDGE_FAILURE.to_string())
}

#[tauri::command]
fn core_status() -> Result<CoreStatus, String> {
    load_bridge_json("status").map_err(|_| BRIDGE_FAILURE.to_string())
}

#[tauri::command]
fn core_inventory() -> Result<CoreInventory, String> {
    load_bridge_json("inventory").map_err(|_| BRIDGE_FAILURE.to_string())
}

#[tauri::command]
async fn core_connect(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    device_id: String,
) -> Result<ConnectionSummary, String> {
    terminal_bridge_request(
        bridge.inner().clone(),
        "connect",
        IdRequest { id: device_id },
    )
    .await
}

#[tauri::command]
async fn core_disconnect(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
) -> Result<(), String> {
    let response: OkResponse = terminal_bridge_request(
        bridge.inner().clone(),
        "disconnect",
        IdRequest { id: connection_id },
    )
    .await?;
    if response.ok {
        Ok(())
    } else {
        Err(BRIDGE_FAILURE.to_string())
    }
}

#[tauri::command]
async fn connection_latency(
    bridge: tauri::State<'_, LatencyBridge>,
    connection_id: String,
) -> Result<ConnectionLatencySummary, String> {
    terminal_bridge_request(
        bridge.inner().0.clone(),
        "connection-latency",
        IdRequest { id: connection_id },
    )
    .await
}

#[tauri::command]
async fn terminal_read(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
) -> Result<TerminalReadSummary, String> {
    terminal_bridge_request(
        bridge.inner().clone(),
        "terminal-read",
        IdRequest { id: connection_id },
    )
    .await
}

#[tauri::command]
async fn terminal_write(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
    data_base64: String,
) -> Result<(), String> {
    let response: OkResponse = terminal_bridge_request(
        bridge.inner().clone(),
        "terminal-write",
        TerminalWriteRequest {
            id: connection_id,
            data: data_base64,
        },
    )
    .await?;
    if response.ok {
        Ok(())
    } else {
        Err(BRIDGE_FAILURE.to_string())
    }
}

#[tauri::command]
async fn terminal_resize(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let response: OkResponse = terminal_bridge_request(
        bridge.inner().clone(),
        "terminal-resize",
        TerminalResizeRequest {
            id: connection_id,
            cols,
            rows,
        },
    )
    .await?;
    if response.ok {
        Ok(())
    } else {
        Err(BRIDGE_FAILURE.to_string())
    }
}

fn main() {
    let terminal_bridge: SharedTerminalBridge = Arc::new(Mutex::new(None));
    let latency_bridge = LatencyBridge(Arc::new(Mutex::new(None)));
    tauri::Builder::default()
        .manage(terminal_bridge)
        .manage(latency_bridge)
        .invoke_handler(tauri::generate_handler![
            core_status,
            core_inventory,
            core_connect,
            core_disconnect,
            connection_latency,
            terminal_read,
            terminal_write,
            terminal_resize
        ])
        .run(tauri::generate_context!())
        .expect("failed to run WeDecent desktop shell");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_accepts_only_expected_fields() {
        let got: CoreStatus = parse_bridge_json(
            br#"{"api_version":"v1","signed_in":true,"device_id":"wd_0123456789abcdef","device_name":"laptop"}"#,
        )
        .expect("valid status");
        assert_eq!(
            got,
            CoreStatus {
                api_version: "v1".into(),
                signed_in: true,
                device_id: "wd_0123456789abcdef".into(),
                device_name: "laptop".into(),
            }
        );

        let incomplete: Result<CoreStatus, ()> = parse_bridge_json(br#"{"api_version":"v1"}"#);
        assert!(incomplete.is_err());
        let unknown: Result<CoreStatus, ()> = parse_bridge_json(
            br#"{"api_version":"v1","signed_in":true,"device_id":"wd_0123456789abcdef","device_name":"laptop","email":"person@example.com"}"#,
        );
        assert!(unknown.is_err());
    }

    #[test]
    fn parse_inventory_rejects_trust_and_routing_fields() {
        let got: CoreInventory = parse_bridge_json(
            br#"{"devices":[{"id":"wd_0123456789abcdef","name":"laptop"}],"transports":[{"name":"lan","available":true}]}"#,
        )
        .expect("valid inventory");
        assert_eq!(got.devices.len(), 1);
        assert_eq!(got.transports.len(), 1);

        let fingerprint: Result<CoreInventory, ()> = parse_bridge_json(
            br#"{"devices":[{"id":"wd_0123456789abcdef","name":"laptop","fingerprint":"SHA256:nope"}],"transports":[]}"#,
        );
        assert!(fingerprint.is_err());
        let detail: Result<CoreInventory, ()> = parse_bridge_json(
            br#"{"devices":[],"transports":[{"name":"lan","available":true,"detail":"nope"}]}"#,
        );
        assert!(detail.is_err());
    }

    #[test]
    fn parse_terminal_responses_accept_only_public_fields() {
        let connection: ConnectionSummary = parse_bridge_json(
            br#"{"id":"conn_abc","device_id":"wd_0123456789abcdef","state":"connected","path":"direct"}"#,
        )
        .expect("valid connection");
        assert_eq!(connection.id, "conn_abc");

        let leaked: Result<ConnectionSummary, ()> = parse_bridge_json(
            br#"{"id":"conn_abc","device_id":"wd_0123456789abcdef","state":"connected","path":"direct","endpoint":"tcp://192.0.2.1:22"}"#,
        );
        assert!(leaked.is_err());

        let latency: ConnectionLatencySummary =
            parse_bridge_json(br#"{"rtt_micros":2450}"#).expect("valid latency");
        assert_eq!(latency.rtt_micros, 2450);
        let leaked_latency: Result<ConnectionLatencySummary, ()> =
            parse_bridge_json(br#"{"rtt_micros":2450,"endpoint":"tcp://192.0.2.1:22"}"#);
        assert!(leaked_latency.is_err());

        let read: TerminalReadSummary =
            parse_bridge_json(br#"{"data":"aGVsbG8=","closed":false}"#).expect("valid read");
        assert_eq!(read.data, "aGVsbG8=");
    }

    #[test]
    fn persistent_response_requires_success_result() {
        let ok: OkResponse = decode_persistent_response(br#"{"ok":true,"result":{"ok":true}}"#)
            .expect("valid persistent response");
        assert!(ok.ok);

        let error: Result<OkResponse, ()> = decode_persistent_response(
            br#"{"ok":false,"error":"Local Core rejected the desktop request"}"#,
        );
        assert!(error.is_err());

        let leaked: Result<OkResponse, ()> = decode_persistent_response(
            br#"{"ok":true,"result":{"ok":true},"endpoint":"tcp://192.0.2.1:22"}"#,
        );
        assert!(leaked.is_err());
    }

    #[test]
    fn bridge_request_size_is_bounded() {
        let oversized = "x".repeat(MAX_BRIDGE_INPUT_BYTES + 1);
        let encoded = serde_json::to_vec(&PersistentRequest {
            op: "terminal-write",
            request: TerminalWriteRequest {
                id: "conn_abc".into(),
                data: oversized,
            },
        })
        .expect("serialize request");
        assert!(encoded.len() > MAX_BRIDGE_INPUT_BYTES);
    }

    #[test]
    fn parse_bridge_json_rejects_malformed_and_oversized_output() {
        let malformed: Result<CoreStatus, ()> = parse_bridge_json(b"not json");
        assert!(malformed.is_err());
        let oversized = vec![b'x'; MAX_BRIDGE_OUTPUT_BYTES as usize + 1];
        let result: Result<CoreStatus, ()> = parse_bridge_json(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn bridge_name_is_fixed_for_platform() {
        if cfg!(windows) {
            assert_eq!(bridge_executable_name(), "wd-desktop-bridge.exe");
        } else {
            assert_eq!(bridge_executable_name(), "wd-desktop-bridge");
        }
    }
}
