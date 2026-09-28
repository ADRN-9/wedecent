use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tauri_plugin_dialog::DialogExt;

use super::{with_terminal_bridge, OkResponse, SharedTerminalBridge, BRIDGE_FAILURE};

const FILE_CHUNK_BYTES: usize = 24 * 1024;
const FILE_FAILURE: &str = "Desktop file transfer failed";
const DESTINATION_EXISTS: &str = "Destination already exists";
const MAX_REMOTE_PATH_BYTES: usize = 4096;
const MAX_PUBLIC_ID_BYTES: usize = 128;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct FileTransferStatus {
    available: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct NativeFileTransferResult {
    cancelled: bool,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileOperation {
    id: String,
    connection_id: String,
    direction: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDownloadRead {
    #[serde(default)]
    data: String,
    done: bool,
}

#[derive(Serialize)]
struct FileConnectionRequest {
    connection_id: String,
}

#[derive(Serialize)]
struct FileUploadOpenRequest {
    connection_id: String,
    path: String,
    expected_size: u64,
}

#[derive(Serialize)]
struct FileUploadWriteRequest {
    connection_id: String,
    operation_id: String,
    data: String,
}

#[derive(Serialize)]
struct FileOperationRequest {
    connection_id: String,
    operation_id: String,
}

#[derive(Serialize)]
struct FileDownloadOpenRequest {
    connection_id: String,
    path: String,
}

#[derive(Serialize)]
struct FileDownloadReadRequest {
    connection_id: String,
    operation_id: String,
    max_bytes: usize,
}

#[tauri::command]
pub(super) async fn file_transfer_status(
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
) -> Result<FileTransferStatus, String> {
    validate_public_id(&connection_id)?;
    super::terminal_bridge_request(
        bridge.inner().clone(),
        "file-status",
        FileConnectionRequest { connection_id },
    )
    .await
}

#[tauri::command]
pub(super) async fn file_upload_pick(
    app: tauri::AppHandle,
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
    remote_path: String,
) -> Result<NativeFileTransferResult, String> {
    validate_file_request(&connection_id, &remote_path)?;
    let bridge = bridge.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        upload_selected_file(&app, &bridge, connection_id, remote_path)
    })
    .await
    .map_err(|_| FILE_FAILURE.to_string())?
}

#[tauri::command]
pub(super) async fn file_download_pick(
    app: tauri::AppHandle,
    bridge: tauri::State<'_, SharedTerminalBridge>,
    connection_id: String,
    remote_path: String,
) -> Result<NativeFileTransferResult, String> {
    validate_file_request(&connection_id, &remote_path)?;
    let suggested_name = safe_remote_basename(&remote_path)?;
    let bridge = bridge.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        download_selected_file(&app, &bridge, connection_id, remote_path, suggested_name)
    })
    .await
    .map_err(|_| FILE_FAILURE.to_string())?
}

fn upload_selected_file(
    app: &tauri::AppHandle,
    bridge: &SharedTerminalBridge,
    connection_id: String,
    remote_path: String,
) -> Result<NativeFileTransferResult, String> {
    let selected = match app.dialog().file().blocking_pick_file() {
        Some(path) => path,
        None => {
            return Ok(NativeFileTransferResult {
                cancelled: true,
                bytes: 0,
            })
        }
    };
    let local_path = selected.as_path().ok_or_else(|| FILE_FAILURE.to_string())?;
    let mut source = File::open(local_path).map_err(|_| FILE_FAILURE.to_string())?;
    let metadata = source.metadata().map_err(|_| FILE_FAILURE.to_string())?;
    if !metadata.is_file() {
        return Err(FILE_FAILURE.to_string());
    }

    let operation: FileOperation = with_terminal_bridge(
        bridge,
        "file-upload-open",
        FileUploadOpenRequest {
            connection_id: connection_id.clone(),
            path: remote_path,
            expected_size: metadata.len(),
        },
    )
    .map_err(|_| BRIDGE_FAILURE.to_string())?;
    validate_operation(&operation, &connection_id, "upload")?;

    let mut buffer = vec![0u8; FILE_CHUNK_BYTES];
    let mut transferred = 0u64;
    loop {
        let n = match source.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => {
                cancel_operation(bridge, &connection_id, &operation.id);
                buffer.fill(0);
                return Err(FILE_FAILURE.to_string());
            }
        };
        if n == 0 {
            break;
        }
        let data = STANDARD.encode(&buffer[..n]);
        buffer[..n].fill(0);
        let response: OkResponse = match with_terminal_bridge(
            bridge,
            "file-upload-write",
            FileUploadWriteRequest {
                connection_id: connection_id.clone(),
                operation_id: operation.id.clone(),
                data,
            },
        ) {
            Ok(response) => response,
            Err(_) => {
                cancel_operation(bridge, &connection_id, &operation.id);
                buffer.fill(0);
                return Err(BRIDGE_FAILURE.to_string());
            }
        };
        if !response.ok {
            cancel_operation(bridge, &connection_id, &operation.id);
            buffer.fill(0);
            return Err(BRIDGE_FAILURE.to_string());
        }
        transferred = transferred
            .checked_add(n as u64)
            .ok_or_else(|| FILE_FAILURE.to_string())?;
    }
    buffer.fill(0);

    let response: OkResponse = with_terminal_bridge(
        bridge,
        "file-upload-commit",
        FileOperationRequest {
            connection_id,
            operation_id: operation.id,
        },
    )
    .map_err(|_| BRIDGE_FAILURE.to_string())?;
    if !response.ok {
        return Err(BRIDGE_FAILURE.to_string());
    }
    Ok(NativeFileTransferResult {
        cancelled: false,
        bytes: transferred,
    })
}

fn download_selected_file(
    app: &tauri::AppHandle,
    bridge: &SharedTerminalBridge,
    connection_id: String,
    remote_path: String,
    suggested_name: String,
) -> Result<NativeFileTransferResult, String> {
    let selected = match app
        .dialog()
        .file()
        .set_file_name(suggested_name)
        .blocking_save_file()
    {
        Some(path) => path,
        None => {
            return Ok(NativeFileTransferResult {
                cancelled: true,
                bytes: 0,
            })
        }
    };
    let destination = selected
        .as_path()
        .ok_or_else(|| FILE_FAILURE.to_string())?
        .to_path_buf();
    if destination.exists() {
        return Err(DESTINATION_EXISTS.to_string());
    }
    let (mut output, temp_path) =
        create_private_temp(&destination).map_err(|_| FILE_FAILURE.to_string())?;
    let mut cleanup = TempCleanup::new(temp_path.clone());

    let operation: FileOperation = match with_terminal_bridge(
        bridge,
        "file-download-open",
        FileDownloadOpenRequest {
            connection_id: connection_id.clone(),
            path: remote_path,
        },
    ) {
        Ok(operation) => operation,
        Err(_) => return Err(BRIDGE_FAILURE.to_string()),
    };
    if let Err(err) = validate_operation(&operation, &connection_id, "download") {
        cancel_operation(bridge, &connection_id, &operation.id);
        return Err(err);
    }

    let mut transferred = 0u64;
    loop {
        let read: FileDownloadRead = match with_terminal_bridge(
            bridge,
            "file-download-read",
            FileDownloadReadRequest {
                connection_id: connection_id.clone(),
                operation_id: operation.id.clone(),
                max_bytes: FILE_CHUNK_BYTES,
            },
        ) {
            Ok(read) => read,
            Err(_) => {
                cancel_operation(bridge, &connection_id, &operation.id);
                return Err(BRIDGE_FAILURE.to_string());
            }
        };
        let mut decoded = STANDARD
            .decode(read.data.as_bytes())
            .map_err(|_| FILE_FAILURE.to_string())?;
        if decoded.len() > FILE_CHUNK_BYTES || (!read.done && decoded.is_empty()) {
            decoded.fill(0);
            cancel_operation(bridge, &connection_id, &operation.id);
            return Err(FILE_FAILURE.to_string());
        }
        if output.write_all(&decoded).is_err() {
            decoded.fill(0);
            cancel_operation(bridge, &connection_id, &operation.id);
            return Err(FILE_FAILURE.to_string());
        }
        transferred = match transferred.checked_add(decoded.len() as u64) {
            Some(total) => total,
            None => {
                decoded.fill(0);
                cancel_operation(bridge, &connection_id, &operation.id);
                return Err(FILE_FAILURE.to_string());
            }
        };
        decoded.fill(0);
        if read.done {
            break;
        }
    }

    output.sync_all().map_err(|_| FILE_FAILURE.to_string())?;
    drop(output);
    publish_no_clobber(&temp_path, &destination).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            DESTINATION_EXISTS.to_string()
        } else {
            FILE_FAILURE.to_string()
        }
    })?;
    cleanup.disarm();

    Ok(NativeFileTransferResult {
        cancelled: false,
        bytes: transferred,
    })
}

fn cancel_operation(bridge: &SharedTerminalBridge, connection_id: &str, operation_id: &str) {
    let _: Result<OkResponse, ()> = with_terminal_bridge(
        bridge,
        "file-cancel",
        FileOperationRequest {
            connection_id: connection_id.to_string(),
            operation_id: operation_id.to_string(),
        },
    );
}

fn validate_operation(
    operation: &FileOperation,
    connection_id: &str,
    direction: &str,
) -> Result<(), String> {
    validate_public_id(&operation.id)?;
    if operation.connection_id != connection_id || operation.direction != direction {
        return Err(FILE_FAILURE.to_string());
    }
    Ok(())
}

fn validate_file_request(connection_id: &str, remote_path: &str) -> Result<(), String> {
    validate_public_id(connection_id)?;
    if remote_path.is_empty()
        || remote_path.len() > MAX_REMOTE_PATH_BYTES
        || remote_path
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b'\\')
    {
        return Err(FILE_FAILURE.to_string());
    }
    Ok(())
}

fn validate_public_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_PUBLIC_ID_BYTES
        || value.bytes().any(|b| !(0x21..=0x7e).contains(&b))
    {
        return Err(FILE_FAILURE.to_string());
    }
    Ok(())
}

fn safe_remote_basename(remote_path: &str) -> Result<String, String> {
    let name = remote_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| FILE_FAILURE.to_string())?;
    if name.len() > 255 || name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(FILE_FAILURE.to_string());
    }
    Ok(name.to_string())
}

fn create_private_temp(destination: &Path) -> io::Result<(File, PathBuf)> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    for _ in 0..32 {
        let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".wedecent-download-{}-{serial}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp_path) {
            Ok(file) => return Ok((file, temp_path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate private download temp file",
    ))
}

fn publish_no_clobber(temp_path: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(temp_path, destination)?;
    let _ = fs::remove_file(temp_path);
    Ok(())
}

struct TempCleanup {
    path: Option<PathBuf>,
}

impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_result_serialization_never_exposes_paths_or_bytes() {
        let encoded = serde_json::to_value(NativeFileTransferResult {
            cancelled: false,
            bytes: 123,
        })
        .expect("serialize result");
        assert_eq!(encoded["cancelled"], false);
        assert_eq!(encoded["bytes"], 123);
        assert_eq!(encoded.as_object().expect("object").len(), 2);
        assert!(encoded.get("path").is_none());
        assert!(encoded.get("data").is_none());
        assert!(encoded.get("endpoint").is_none());
    }

    #[test]
    fn remote_basename_is_strict() {
        assert_eq!(safe_remote_basename("dir/file.txt").unwrap(), "file.txt");
        for invalid in ["", "dir/", ".", "..", "dir/..", "bad\nname"] {
            assert!(
                safe_remote_basename(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn publish_is_no_clobber_and_cleans_temp() {
        let root = std::env::temp_dir().join(format!(
            "wedecent-native-file-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create temp root");
        let destination = root.join("result.bin");
        let (mut file, temp_path) = create_private_temp(&destination).expect("create private temp");
        file.write_all(b"payload").expect("write payload");
        file.sync_all().expect("sync payload");
        drop(file);
        publish_no_clobber(&temp_path, &destination).expect("publish");
        assert_eq!(fs::read(&destination).unwrap(), b"payload");
        assert!(!temp_path.exists());

        let (mut second, second_temp) = create_private_temp(&destination).expect("second temp");
        second.write_all(b"replace").unwrap();
        drop(second);
        let err = publish_no_clobber(&second_temp, &destination).expect_err("must not overwrite");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"payload");
        let _ = fs::remove_file(second_temp);
        let _ = fs::remove_file(destination);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn file_requests_contain_only_core_opaque_and_remote_fields() {
        let encoded = serde_json::to_value(FileUploadOpenRequest {
            connection_id: "conn_abc".into(),
            path: "dir/file.txt".into(),
            expected_size: 12,
        })
        .unwrap();
        assert_eq!(encoded["connection_id"], "conn_abc");
        assert_eq!(encoded["path"], "dir/file.txt");
        assert_eq!(encoded["expected_size"], 12);
        assert!(encoded.get("local_path").is_none());
        assert!(encoded.get("endpoint").is_none());
        assert!(encoded.get("fingerprint").is_none());
        assert!(encoded.get("grant").is_none());
    }
}
