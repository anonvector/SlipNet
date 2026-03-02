use rand::Rng;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=CONFIG_ENCRYPTION_KEY");

    let key_hex = env::var("CONFIG_ENCRYPTION_KEY").unwrap_or_default();

    // Parse hex string into 32 bytes, or use zeros for dev builds
    let key_bytes: [u8; 32] = if key_hex.len() == 64 {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&key_hex[i * 2..i * 2 + 2], 16)
                .expect("CONFIG_ENCRYPTION_KEY must be valid hex");
        }
        bytes
    } else {
        if !key_hex.is_empty() {
            panic!("CONFIG_ENCRYPTION_KEY must be exactly 64 hex chars (32 bytes), got {}", key_hex.len());
        }
        [0u8; 32]
    };

    let mut rng = rand::thread_rng();

    // Generate 4 random 8-byte XOR masks
    let masks: [[u8; 8]; 4] = [
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ];

    // Split key into 4 segments and XOR each with its mask
    let mut segments: [[u8; 8]; 4] = [[0u8; 8]; 4];
    for seg in 0..4 {
        for i in 0..8 {
            segments[seg][i] = key_bytes[seg * 8 + i] ^ masks[seg][i];
        }
    }

    // Generate 2 random decoy arrays (red herrings for reverse engineers)
    let decoy0: [u8; 32] = rng.gen();
    let decoy1: [u8; 32] = rng.gen();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config_key.rs");

    let code = format!(
        r#"
const MASK_0: [u8; 8] = {masks_0:?};
const MASK_1: [u8; 8] = {masks_1:?};
const MASK_2: [u8; 8] = {masks_2:?};
const MASK_3: [u8; 8] = {masks_3:?};

const SEG_0: [u8; 8] = {seg_0:?};
const SEG_1: [u8; 8] = {seg_1:?};
const SEG_2: [u8; 8] = {seg_2:?};
const SEG_3: [u8; 8] = {seg_3:?};

#[allow(dead_code)]
const DECOY_SALT: [u8; 32] = {decoy_0:?};
#[allow(dead_code)]
const DECOY_IV: [u8; 32] = {decoy_1:?};

pub(super) fn reconstruct_config_key() -> [u8; 32] {{
    let mut key = [0u8; 32];
    let segments = [SEG_0, SEG_1, SEG_2, SEG_3];
    let masks = [MASK_0, MASK_1, MASK_2, MASK_3];
    for seg in 0..4 {{
        for i in 0..8 {{
            key[seg * 8 + i] = segments[seg][i] ^ masks[seg][i];
        }}
    }}
    key
}}
"#,
        masks_0 = masks[0],
        masks_1 = masks[1],
        masks_2 = masks[2],
        masks_3 = masks[3],
        seg_0 = segments[0],
        seg_1 = segments[1],
        seg_2 = segments[2],
        seg_3 = segments[3],
        decoy_0 = decoy0,
        decoy_1 = decoy1,
    );

    fs::write(&dest_path, code).expect("Failed to write config_key.rs");
}
