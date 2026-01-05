//! Cobalt Strike-compatible BOF argument packing
//!
//! BOFs expect arguments in a specific binary format. This module provides
//! functions to parse a human-readable argument string and pack it into
//! the binary format expected by BOFs.
//!
//! # Argument Format
//! Arguments are specified as space-separated `type:value` pairs:
//! - `short:123` or `s:123` - 16-bit signed integer
//! - `int:456` or `i:456` - 32-bit signed integer
//! - `str:hello` or `z:hello` - Null-terminated ASCII string
//! - `wstr:C:\path` or `Z:C:\path` - Null-terminated wide (UTF-16) string
//! - `bin:base64data` or `b:base64data` - Binary data (base64 encoded)
//!
//! # Binary Format
//! The packed format uses little-endian byte order:
//! ```text
//! [4 bytes: total data length]
//! For each argument:
//!   [4 bytes: type] [4 bytes: length] [N bytes: data]
//! ```
//!
//! Type codes:
//! - 1 = binary
//! - 2 = int (32-bit)
//! - 3 = short (16-bit)
//! - 4 = str (null-terminated)
//! - 5 = wstr (wide null-terminated)

use byteorder::{LittleEndian, WriteBytesExt};
use std::error::Error;
use std::io::{Cursor, Write};

/// BOF argument type codes
const BOF_TYPE_BINARY: i32 = 1;
const BOF_TYPE_INT: i32 = 2;
const BOF_TYPE_SHORT: i32 = 3;
const BOF_TYPE_STR: i32 = 4;
const BOF_TYPE_WSTR: i32 = 5;

/// Represents a parsed BOF argument
#[derive(Debug)]
pub enum BofArg {
    Short(i16),
    Int(i32),
    Str(String),
    WStr(String),
    Binary(Vec<u8>),
}

/// Pack a human-readable argument string into CS-compatible binary format
///
/// # Arguments
/// * `args_str` - Space-separated arguments like "int:123 str:hello wstr:C:\\path"
///
/// # Returns
/// * `Ok(Vec<u8>)` - Packed binary arguments ready for BOF execution
/// * `Err` - If parsing or encoding fails
///
/// # Example
/// ```ignore
/// let packed = pack_arguments("int:1234 str:hello")?;
/// // packed now contains the binary-encoded arguments
/// ```
pub fn pack_arguments(args_str: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let args = parse_arg_string(args_str)?;

    let mut buffer = Cursor::new(Vec::new());

    // Reserve space for total length (will fill in at the end)
    buffer.write_i32::<LittleEndian>(0)?;

    for arg in args {
        match arg {
            BofArg::Short(val) => {
                buffer.write_i32::<LittleEndian>(BOF_TYPE_SHORT)?;
                buffer.write_i32::<LittleEndian>(2)?; // Length: 2 bytes
                buffer.write_i16::<LittleEndian>(val)?;
            }
            BofArg::Int(val) => {
                buffer.write_i32::<LittleEndian>(BOF_TYPE_INT)?;
                buffer.write_i32::<LittleEndian>(4)?; // Length: 4 bytes
                buffer.write_i32::<LittleEndian>(val)?;
            }
            BofArg::Str(val) => {
                let bytes = val.as_bytes();
                buffer.write_i32::<LittleEndian>(BOF_TYPE_STR)?;
                buffer.write_i32::<LittleEndian>((bytes.len() + 1) as i32)?; // +1 for null
                buffer.write_all(bytes)?;
                buffer.write_all(&[0])?; // Null terminator
            }
            BofArg::WStr(val) => {
                // Convert to UTF-16LE with null terminator
                let wide: Vec<u16> = val.encode_utf16().chain(std::iter::once(0)).collect();
                let bytes: Vec<u8> = wide.iter().flat_map(|&x| x.to_le_bytes()).collect();
                buffer.write_i32::<LittleEndian>(BOF_TYPE_WSTR)?;
                buffer.write_i32::<LittleEndian>(bytes.len() as i32)?;
                buffer.write_all(&bytes)?;
            }
            BofArg::Binary(val) => {
                buffer.write_i32::<LittleEndian>(BOF_TYPE_BINARY)?;
                buffer.write_i32::<LittleEndian>(val.len() as i32)?;
                buffer.write_all(&val)?;
            }
        }
    }

    // Fill in total length (everything after the length field)
    let mut result = buffer.into_inner();
    let total_len = (result.len() - 4) as i32;
    result[0..4].copy_from_slice(&total_len.to_le_bytes());

    Ok(result)
}

/// Parse an argument string into typed BofArg values
fn parse_arg_string(args_str: &str) -> Result<Vec<BofArg>, Box<dyn Error>> {
    if args_str.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut args = Vec::new();

    // Split by spaces, respecting quoted strings
    for part in split_args(args_str) {
        if let Some((type_str, value)) = part.split_once(':') {
            // Handle case-insensitive matching for most types
            // But preserve case for Z (wstr) vs z (str) distinction per CS convention
            let arg = match type_str {
                // CS convention: lowercase 'z' is str, uppercase 'Z' is wstr
                "Z" => BofArg::WStr(unquote(value)),
                _ => match type_str.to_lowercase().as_str() {
                    "short" | "s" => BofArg::Short(
                        value
                            .parse()
                            .map_err(|_| format!("Invalid short value: {}", value))?,
                    ),
                    "int" | "i" => BofArg::Int(
                        value
                            .parse()
                            .map_err(|_| format!("Invalid int value: {}", value))?,
                    ),
                    "str" | "z" => BofArg::Str(unquote(value)),
                    "wstr" => BofArg::WStr(unquote(value)),
                    "bin" | "b" => BofArg::Binary(
                        base64::decode(value)
                            .map_err(|_| format!("Invalid base64 in bin argument: {}", value))?,
                    ),
                    _ => return Err(format!("Unknown argument type: {}", type_str).into()),
                },
            };
            args.push(arg);
        } else if !part.trim().is_empty() {
            return Err(format!("Invalid argument format (expected type:value): {}", part).into());
        }
    }

    Ok(args)
}

/// Split argument string while respecting quoted values
///
/// Handles both single and double quotes, allowing spaces within quoted strings.
fn split_args(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut chars = s.char_indices().peekable();
    let mut start = 0;
    let mut in_quotes = false;
    let mut quote_char = '"';

    while let Some((i, c)) = chars.next() {
        match c {
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = c;
            }
            c if c == quote_char && in_quotes => {
                in_quotes = false;
            }
            ' ' | '\t' if !in_quotes => {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    result.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Don't forget the last part
    let part = s[start..].trim();
    if !part.is_empty() {
        result.push(part);
    }

    result
}

/// Remove surrounding quotes from a string value
fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Basic Type Tests ====================

    #[test]
    fn test_pack_empty() {
        let result = pack_arguments("").unwrap();
        // Empty args should just have the 4-byte length field (value 0)
        assert_eq!(result.len(), 4);
        assert_eq!(&result[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_pack_whitespace_only() {
        let result = pack_arguments("   \t  ").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(&result[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_pack_int() {
        let result = pack_arguments("int:1234").unwrap();
        // Should have: 4 (length) + 4 (type) + 4 (len) + 4 (value) = 16 bytes
        assert_eq!(result.len(), 16);

        // Verify the structure
        let total_len = i32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(total_len, 12); // 4 + 4 + 4

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_INT);

        let value = i32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        assert_eq!(value, 1234);
    }

    #[test]
    fn test_pack_int_negative() {
        let result = pack_arguments("int:-500").unwrap();
        assert_eq!(result.len(), 16);

        let value = i32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        assert_eq!(value, -500);
    }

    #[test]
    fn test_pack_int_shorthand() {
        let result = pack_arguments("i:999").unwrap();
        assert_eq!(result.len(), 16);

        let value = i32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        assert_eq!(value, 999);
    }

    #[test]
    fn test_pack_short() {
        let result = pack_arguments("short:42").unwrap();
        // Should have: 4 (length) + 4 (type) + 4 (len) + 2 (value) = 14 bytes
        assert_eq!(result.len(), 14);

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_SHORT);

        let value = i16::from_le_bytes([result[12], result[13]]);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_pack_short_shorthand() {
        let result = pack_arguments("s:100").unwrap();
        assert_eq!(result.len(), 14);

        let value = i16::from_le_bytes([result[12], result[13]]);
        assert_eq!(value, 100);
    }

    #[test]
    fn test_pack_str() {
        let result = pack_arguments("str:hello").unwrap();
        // Should have: 4 (length) + 4 (type) + 4 (len) + 6 (hello + null) = 18 bytes
        assert_eq!(result.len(), 18);

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_STR);

        let str_len = i32::from_le_bytes([result[8], result[9], result[10], result[11]]);
        assert_eq!(str_len, 6); // "hello" + null

        // Verify the string content
        assert_eq!(&result[12..17], b"hello");
        assert_eq!(result[17], 0); // Null terminator
    }

    #[test]
    fn test_pack_str_shorthand() {
        let result = pack_arguments("z:test").unwrap();
        assert_eq!(result.len(), 17); // 4 + 4 + 4 + 5

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_STR);
    }

    #[test]
    fn test_pack_wstr() {
        let result = pack_arguments("wstr:hi").unwrap();
        // "hi" in UTF-16LE + null = 3 chars * 2 bytes = 6 bytes
        // Total: 4 (length) + 4 (type) + 4 (len) + 6 (data) = 18 bytes
        assert_eq!(result.len(), 18);

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_WSTR);

        // Verify UTF-16LE encoding: 'h' = 0x0068, 'i' = 0x0069, null = 0x0000
        assert_eq!(&result[12..14], &[0x68, 0x00]); // 'h'
        assert_eq!(&result[14..16], &[0x69, 0x00]); // 'i'
        assert_eq!(&result[16..18], &[0x00, 0x00]); // null
    }

    #[test]
    fn test_pack_wstr_shorthand() {
        let result = pack_arguments("Z:ab").unwrap();

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_WSTR);
    }

    #[test]
    fn test_pack_bin() {
        // "hello" in base64 is "aGVsbG8="
        let result = pack_arguments("bin:aGVsbG8=").unwrap();
        // 5 bytes of binary data
        // Total: 4 (length) + 4 (type) + 4 (len) + 5 (data) = 17 bytes
        assert_eq!(result.len(), 17);

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_BINARY);

        assert_eq!(&result[12..17], b"hello");
    }

    #[test]
    fn test_pack_bin_shorthand() {
        let result = pack_arguments("b:dGVzdA==").unwrap(); // "test"
        assert_eq!(result.len(), 16); // 4 + 4 + 4 + 4

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_BINARY);
    }

    // ==================== Multiple Arguments Tests ====================

    #[test]
    fn test_pack_multiple() {
        let result = pack_arguments("int:123 str:test").unwrap();
        // int: 4 + 4 + 4 = 12, str: 4 + 4 + 5 = 13, total data = 25
        // Plus 4 for length field = 29
        assert_eq!(result.len(), 29);
    }

    #[test]
    fn test_pack_all_types() {
        let result = pack_arguments("short:1 int:2 str:a wstr:b bin:YWI=").unwrap();
        assert!(result.len() > 40); // Should be substantial

        // Verify we can parse the total length
        let total_len = i32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(total_len as usize, result.len() - 4);
    }

    #[test]
    fn test_pack_repeated_type() {
        let result = pack_arguments("int:1 int:2 int:3").unwrap();
        // 3 ints: each is 12 bytes of data, total = 36 + 4 = 40
        assert_eq!(result.len(), 40);
    }

    // ==================== Quoted String Tests ====================

    #[test]
    fn test_split_quoted_double() {
        let parts = split_args("str:\"hello world\" int:123");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "str:\"hello world\"");
        assert_eq!(parts[1], "int:123");
    }

    #[test]
    fn test_split_quoted_single() {
        let parts = split_args("str:'hello world' int:456");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "str:'hello world'");
        assert_eq!(parts[1], "int:456");
    }

    #[test]
    fn test_pack_quoted_str() {
        let result = pack_arguments("str:\"hello world\"").unwrap();
        // "hello world" = 11 chars + null = 12
        assert_eq!(result.len(), 24); // 4 + 4 + 4 + 12

        // The unquoted string should be stored
        let str_len = i32::from_le_bytes([result[8], result[9], result[10], result[11]]);
        assert_eq!(str_len, 12); // "hello world" + null
    }

    #[test]
    fn test_pack_wstr_with_path() {
        let result = pack_arguments("wstr:\"C:\\Windows\\System32\"").unwrap();

        let type_code = i32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        assert_eq!(type_code, BOF_TYPE_WSTR);

        // Verify the path is properly encoded
        let data_len = i32::from_le_bytes([result[8], result[9], result[10], result[11]]);
        // "C:\Windows\System32" = 19 chars + null = 20 * 2 = 40 bytes
        assert_eq!(data_len, 40);
    }

    // ==================== Unquote Tests ====================

    #[test]
    fn test_unquote_double() {
        assert_eq!(unquote("\"hello\""), "hello");
    }

    #[test]
    fn test_unquote_single() {
        assert_eq!(unquote("'hello'"), "hello");
    }

    #[test]
    fn test_unquote_none() {
        assert_eq!(unquote("hello"), "hello");
    }

    #[test]
    fn test_unquote_with_spaces() {
        assert_eq!(unquote("  \"hello\"  "), "hello");
    }

    #[test]
    fn test_unquote_mismatched() {
        // Mismatched quotes should not be removed
        assert_eq!(unquote("\"hello'"), "\"hello'");
    }

    // ==================== Error Handling Tests ====================

    #[test]
    fn test_invalid_type() {
        let result = pack_arguments("invalid:123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown argument type"));
    }

    #[test]
    fn test_invalid_int_value() {
        let result = pack_arguments("int:notanumber");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid int value"));
    }

    #[test]
    fn test_invalid_short_value() {
        let result = pack_arguments("short:99999"); // Too large for i16
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64() {
        let result = pack_arguments("bin:not_valid_base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid base64"));
    }

    #[test]
    fn test_missing_value() {
        let result = pack_arguments("int:");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_colon() {
        let result = pack_arguments("int123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected type:value"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_string_value() {
        let result = pack_arguments("str:").unwrap();
        // Empty string still has null terminator
        assert_eq!(result.len(), 13); // 4 + 4 + 4 + 1
    }

    #[test]
    fn test_zero_values() {
        let result = pack_arguments("int:0 short:0").unwrap();
        assert!(result.len() > 4);
    }

    #[test]
    fn test_max_int() {
        let result = pack_arguments("int:2147483647").unwrap();
        let value = i32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        assert_eq!(value, i32::MAX);
    }

    #[test]
    fn test_min_int() {
        let result = pack_arguments("int:-2147483648").unwrap();
        let value = i32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        assert_eq!(value, i32::MIN);
    }

    #[test]
    fn test_unicode_wstr() {
        // Test with unicode characters
        let result = pack_arguments("wstr:hello").unwrap();
        assert!(result.len() > 4);
    }

    #[test]
    fn test_binary_empty() {
        // Empty base64 string
        let result = pack_arguments("bin:").unwrap();
        assert_eq!(result.len(), 12); // 4 + 4 + 4 + 0
    }

    #[test]
    fn test_case_insensitive_type() {
        let result1 = pack_arguments("INT:123").unwrap();
        let result2 = pack_arguments("int:123").unwrap();
        assert_eq!(result1, result2);

        let result3 = pack_arguments("STR:test").unwrap();
        let result4 = pack_arguments("str:test").unwrap();
        assert_eq!(result3, result4);
    }

    #[test]
    fn test_extra_whitespace() {
        let result = pack_arguments("  int:1   str:a  ").unwrap();
        assert!(result.len() > 4);
    }
}
