//! Locate the passkey security-domain secret (SDS) in a Chrome process memory dump.
//!
//! Context-anchored strategy (no brute force):
//!   1. Find known anchor byte sequences in the dump (HKDF info string, AAD string,
//!      sync_id / credential_id from an exported record, PKCS#8 P-256 prefix).
//!   2. Collect aligned 32-byte candidates from a window around each anchor.
//!   3. Verify each candidate against a known WebauthnCredentialSpecifics
//!      `encrypted` ciphertext (field 12) by trial AES-256-GCM decryption, both
//!      directly (candidate = derived key) and via HKDF (candidate = SDS).
//!      The GCM tag check is decisive; a successful open is cross-checked by
//!      parsing the inner `Encrypted` proto and matching the known credential_id.
//!
//! Rust port of find_sds_in_dump.py — single static binary, no runtime needed.

use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use clap::Parser;
use hkdf::Hkdf;
use memchr::memmem;
use memmap2::Mmap;
use rayon::prelude::*;
use sha2::Sha256;

const HKDF_INFO: &[u8] = b"KeychainApplicationKey:gmscore_module:com.google.android.gms.fido";
const AAD: &[u8] = b"WebauthnCredentialSpecifics.Encrypted";
const NONCE_LEN: usize = 12;
/// PKCS#8 (RFC 5958) wrapper for a P-256 private key; the 32-byte scalar
/// follows the trailing 04 20.
const PKCS8_P256_PREFIX: [u8; 36] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20,
];
const MAX_ANCHOR_HITS: usize = 10000;

#[derive(Parser)]
#[command(about = "在 Chrome 进程内存 dump 中通过锚点定位 passkey 安全域密钥（SDS），并用已知密文试解密验证")]
struct Args {
    /// chrome.exe 主进程内存 dump 文件
    dump: PathBuf,
    /// read_leveldb.py 的输出，提供密文与锚点
    #[arg(long, default_value = "passkeys.jsonl")]
    jsonl: PathBuf,
    /// 直接指定 field 12 密文 hex，覆盖 --jsonl 中的取值
    #[arg(long)]
    ciphertext_hex: Option<String>,
    /// 额外的自定义锚点（hex），可重复使用
    #[arg(long = "anchor-hex")]
    anchor_hex: Vec<String>,
    /// 锚点两侧的扫描窗口大小（字节）
    #[arg(long, default_value_t = 8192)]
    window: usize,
    /// 候选密钥的对齐步长
    #[arg(long, default_value_t = 16)]
    align: usize,
    /// 忽略锚点，按对齐步长扫描整个 dump（仅建议小 dump）
    #[arg(long)]
    full_scan: bool,
}

struct Reference {
    ciphertext: Vec<u8>,
    anchors: Vec<Vec<u8>>,
    credential_id: Option<Vec<u8>>,
}

struct Hit {
    offset: usize,
    mode: &'static str,
    candidate: [u8; 32],
    plaintext: Vec<u8>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err("hex 长度为奇数".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal extraction from read_leveldb.py JSONL output (no full JSON model).
fn load_reference_material(jsonl_path: &PathBuf) -> Result<Reference, String> {
    let text = std::fs::read_to_string(jsonl_path)
        .map_err(|e| format!("读取 {jsonl_path:?} 失败: {e}"))?;
    let mut ciphertext = None;
    let mut anchors = Vec::new();
    let mut credential_id = None;

    for line in text.lines() {
        let record: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("JSONL 解析失败: {e}"))?;
        let decoded = &record["decoded_passkey"];
        if let Some(payloads) = decoded["encrypted_payloads"].as_array() {
            for payload in payloads {
                if payload["kind"] == "encrypted" && ciphertext.is_none() {
                    ciphertext = Some(hex_decode(
                        payload["ciphertext"]["hex"]
                            .as_str()
                            .ok_or("ciphertext.hex 缺失")?,
                    )?);
                }
            }
        }
        for key_name in ["sync_id", "credential_id"] {
            if let Some(hex) = decoded[key_name]["hex"].as_str() {
                let blob = hex_decode(hex)?;
                if key_name == "credential_id" {
                    credential_id = Some(blob.clone());
                }
                anchors.push(blob);
            }
        }
        if let Some(rp_id) = decoded["rp_id"].as_str() {
            anchors.push(rp_id.as_bytes().to_vec());
        }
    }
    let ciphertext = ciphertext.ok_or_else(|| format!("{jsonl_path:?} 中找不到 field 12 加密载荷"))?;
    Ok(Reference {
        ciphertext,
        anchors,
        credential_id,
    })
}

fn derive_key(sds: &[u8; 32]) -> [u8; 32] {
    // RFC 5869 HKDF-SHA256, salt 缺省 = 全零，与 Chromium crypto::kdf::Hkdf 一致
    let hk = Hkdf::<Sha256>::new(None, sds);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).expect("HKDF expand 32B");
    okm
}

/// ciphertext = nonce(12) || ct || tag(16)
fn try_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() <= NONCE_LEN + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..NONCE_LEN]),
            Payload {
                msg: &ciphertext[NONCE_LEN..],
                aad: AAD,
            },
        )
        .ok()
}

/// Minimal protobuf wire parser: returns length-delimited (wire type 2) values
/// for the requested field numbers.
fn parse_proto_bytes_fields(data: &[u8], wanted: &[u64]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let read_varint = |data: &[u8], pos: &mut usize| -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *data.get(*pos)?;
            *pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    };
    while pos < data.len() {
        let Some(tag) = read_varint(data, &mut pos) else { break };
        let field = tag >> 3;
        match tag & 7 {
            0 => {
                if read_varint(data, &mut pos).is_none() {
                    break;
                }
            }
            1 => pos = pos.checked_add(8).filter(|&p| p <= data.len()).unwrap_or(usize::MAX),
            5 => pos = pos.checked_add(4).filter(|&p| p <= data.len()).unwrap_or(usize::MAX),
            2 => {
                let Some(len) = read_varint(data, &mut pos) else { break };
                let len = len as usize;
                let Some(end) = pos.checked_add(len).filter(|&e| e <= data.len()) else {
                    break;
                };
                if wanted.contains(&field) {
                    out.push((field, data[pos..end].to_vec()));
                }
                pos = end;
            }
            _ => break,
        }
    }
    out
}

fn collect_candidates(
    data: &[u8],
    anchors: &[Vec<u8>],
    window: usize,
    align: usize,
    full_scan: bool,
) -> (Vec<(usize, String)>, Vec<(String, usize)>) {
    let mut stats = Vec::new();
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    if full_scan {
        let n = data.len().saturating_sub(31);
        out.extend((0..n).step_by(align).map(|pos| (pos, "full-scan".to_string())));
        return (out, stats);
    }

    let mut regions: Vec<(usize, usize)> = Vec::new();
    for anchor in anchors {
        let hits: Vec<usize> = memmem::find_iter(data, anchor)
            .take(MAX_ANCHOR_HITS)
            .collect();
        let label = if anchor.len() > 24 {
            format!("{}...", hex_encode(&anchor[..24]))
        } else {
            hex_encode(anchor)
        };
        stats.push((label, hits.len()));
        for hit in hits {
            let lo = hit.saturating_sub(window);
            let hi = (hit + anchor.len() + window).min(data.len());
            if regions.iter().any(|&(rlo, rhi)| lo >= rlo && hi <= rhi) {
                continue;
            }
            regions.push((lo, hi));
            let first = lo + (align - lo % align) % align;
            let mut pos = first;
            while pos + 32 <= hi {
                if seen.insert(pos) {
                    out.push((pos, format!("anchor@{hit:#x}")));
                }
                pos += align;
            }
        }
    }
    (out, stats)
}

fn main() {
    let args = Args::parse();
    if ![1, 4, 8, 16, 32].contains(&args.align) {
        eprintln!("错误: --align 只能是 1/4/8/16/32");
        std::process::exit(2);
    }

    let reference = if let Some(hex) = &args.ciphertext_hex {
        let ciphertext = hex_decode(hex).unwrap_or_else(|e| {
            eprintln!("错误: --ciphertext-hex 无效: {e}");
            std::process::exit(2);
        });
        Reference {
            ciphertext,
            anchors: Vec::new(),
            credential_id: None,
        }
    } else {
        let reference = load_reference_material(&args.jsonl).unwrap_or_else(|e| {
            eprintln!("错误: {e}");
            std::process::exit(2);
        });
        eprintln!(
            "已从 {:?} 载入密文 {} 字节",
            args.jsonl,
            reference.ciphertext.len()
        );
        reference
    };

    let mut anchors = vec![
        HKDF_INFO.to_vec(),
        AAD.to_vec(),
        PKCS8_P256_PREFIX.to_vec(),
    ];
    anchors.extend(reference.anchors.iter().cloned());
    for hex in &args.anchor_hex {
        match hex_decode(hex) {
            Ok(a) => anchors.push(a),
            Err(e) => {
                eprintln!("错误: --anchor-hex 无效: {e}");
                std::process::exit(2);
            }
        }
    }

    let file = File::open(&args.dump).unwrap_or_else(|e| {
        eprintln!("错误: 无法打开 dump 文件 {:?}: {e}", args.dump);
        std::process::exit(2);
    });
    let mmap = unsafe { Mmap::map(&file) }.unwrap_or_else(|e| {
        eprintln!("错误: mmap 失败: {e}");
        std::process::exit(2);
    });
    let data: &[u8] = &mmap;
    eprintln!("dump 大小: {:.1} MB", data.len() as f64 / 1e6);

    // PKCS#8 前缀锚点：解出的明文私钥可能还在内存里，可直接拿到
    let pkcs8_hits: Vec<usize> = memmem::find_iter(data, &PKCS8_P256_PREFIX).take(20).collect();
    if !pkcs8_hits.is_empty() {
        eprintln!(
            "[!] 命中 PKCS#8 P-256 前缀 {} 处，其后 32 字节疑似明文私钥（scalar）：",
            pkcs8_hits.len()
        );
        for &hit in &pkcs8_hits {
            let start = hit + PKCS8_P256_PREFIX.len();
            if start + 32 <= data.len() {
                eprintln!("    offset {hit:#x}: scalar={}", hex_encode(&data[start..start + 32]));
            }
        }
    }

    let (candidates, stats) =
        collect_candidates(data, &anchors, args.window, args.align, args.full_scan);
    for (label, count) in &stats {
        eprintln!("锚点 {label}: {count} 处");
    }
    eprintln!("候选 32 字节切片: {} 个", candidates.len());

    let ciphertext = &reference.ciphertext[..];
    let hits: Mutex<Vec<Hit>> = Mutex::new(Vec::new());
    candidates.par_iter().for_each(|&(pos, ref why)| {
        let candidate: [u8; 32] = data[pos..pos + 32].try_into().unwrap();

        let (plaintext, mode) = if let Some(pt) = try_decrypt(&candidate, ciphertext) {
            (pt, "direct-key")
        } else if let Some(pt) = try_decrypt(&derive_key(&candidate), ciphertext) {
            (pt, "sds+hkdf")
        } else {
            return;
        };
        hits.lock().unwrap().push(Hit {
            offset: pos,
            mode,
            candidate,
            plaintext,
        });
        let _ = why; // provenance 已在 offset 上体现
    });

    let mut hits = hits.into_inner().unwrap();
    hits.sort_by_key(|h| h.offset);
    for hit in &hits {
        println!("\n[+] 命中 @ offset {:#x}, 模式: {}", hit.offset, hit.mode);
        println!("    candidate: {}", hex_encode(&hit.candidate));
        for (field, value) in parse_proto_bytes_fields(&hit.plaintext, &[1, 2, 3]) {
            let name = match field {
                1 => "private_key_pkcs8",
                2 => "hmac_secret",
                _ => "cred_blob",
            };
            println!("    {name}: {}", hex_encode(&value));
        }
        if let Some(cred_id) = &reference.credential_id {
            println!(
                "    contains_known_credential_id: {}",
                memmem::find(&hit.plaintext, cred_id).is_some()
            );
        }
        match hit.mode {
            "sds+hkdf" => println!(
                "    => SDS (epoch 对应 key_version): {}",
                hex_encode(&hit.candidate)
            ),
            _ => println!("    => 派生后的 AES-256-GCM key（SDS 本身未直接命中）"),
        }
    }

    eprintln!("\n完成: 试解 {} 个候选, 命中 {} 个", candidates.len(), hits.len());
    std::process::exit(if hits.is_empty() { 1 } else { 0 });
}
