use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_BRIDGE_OUTPUT_BYTES: u64 = 64 * 1024;
const BRIDGE_FAILURE: &str = "Local Core is unavailable";

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

fn load_bridge_json<T: DeserializeOwned>(command: &'static str) -> Result<T, ()> {
    let current_exe = env::current_exe().map_err(|_| ())?;
    let bridge = sibling_bridge_path(&current_exe).map_err(|_| ())?;
    let mut child = Command::new(bridge)
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;

    let mut stdout = child.stdout.take().ok_or(())?;
    let mut output = Vec::new();
    stdout
        .by_ref()
        .take(MAX_BRIDGE_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| ())?;
    if output.len() > MAX_BRIDGE_OUTPUT_BYTES as usize {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    }

    let status = child.wait().map_err(|_| ())?;
    if !status.success() {
        return Err(());
    }
    parse_bridge_json(&output)
}

#[tauri::command]
fn core_status() -> Result<CoreStatus, String> {
    load_bridge_json("status").map_err(|_| BRIDGE_FAILURE.to_string())
}

#[tauri::command]
fn core_inventory() -> Result<CoreInventory, String> {
    load_bridge_json("inventory").map_err(|_| BRIDGE_FAILURE.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![core_status, core_inventory])
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
