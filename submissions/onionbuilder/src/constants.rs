// Pre-computed constants
pub const KEY_TYPES: [(&str, &[u8]); 4] = [
    ("rho", &[0x72, 0x68, 0x6F]),
    ("mu", &[0x6d, 0x75]),
    ("um", &[0x75, 0x6d]),
    ("pad", &[0x70, 0x61, 0x64]),
];

pub const SECP256K1_ORDER: &str = 
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

pub const ZERO_NONCE: [u8; 12] = [0; 12];

pub const PACKET_SIZE: usize = 1300;
pub const HMAC_SIZE: usize = 32;