use std::env;
use std::fs::{self, File};
use std::path::Path;
use std::collections::HashMap;
use std::io::Write;

use serde::Deserialize;
use hex::{decode as hex_decode, encode as hex_encode};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use secp256k1::{SecretKey, PublicKey, Secp256k1, Scalar};


const PACKET_SIZE: usize = 1300;
const HMAC_SIZE: usize = 32;
const ZERO_NONCE: [u8; 12] = [0u8; 12];

const KEY_RHO: &[u8] = &[0x72, 0x68, 0x6F]; // "rho"
const KEY_MU: &[u8] = &[0x6d, 0x75];         // "mu"
const KEY_UM: &[u8] = &[0x75, 0x6d];         // "um"
const KEY_PAD: &[u8] = &[0x70, 0x61, 0x64];    // "pad"

#[derive(Debug, Clone)]
struct HopKeys {
    rho_key: Vec<u8>,
    mu_key: Vec<u8>,
    um_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Hop {
    id: usize,
    pubkey: Vec<u8>,
    payload: Vec<u8>,
    hmac: Option<Vec<u8>>,
    keys: Option<HopKeys>,
    shared_secret: Option<Vec<u8>>,
    filler_acc: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct RawOnionPayload {
    session_key: String,
    associated_data: String,
    hops: Vec<RawHop>,
}

#[derive(Debug, Deserialize)]
struct RawHop {
    pubkey: String,
    payload: String,
}

#[derive(Debug)]
struct OnionPayload {
    session_key: Vec<u8>,
    associated_data: Vec<u8>,
    hops: Vec<Hop>,
}

impl OnionPayload {
    fn from_json_file<P: AsRef<Path>>(path: P) -> Self {
        let data = fs::read_to_string(path).expect("Unable to read file");
        let raw: RawOnionPayload = serde_json::from_str(&data).expect("JSON parsing error");
        println!("Loaded JSON data: {:?}", raw);
        let session_key = hex_decode(raw.session_key).expect("Invalid hex in session_key");
        let associated_data = hex_decode(raw.associated_data).expect("Invalid hex in associated_data");
        let hops: Vec<Hop> = raw.hops.into_iter().enumerate().map(|(i, rh)| {
            Hop {
                id: i + 1,
                pubkey: hex_decode(rh.pubkey).expect("Invalid hex in hop pubkey"),
                payload: hex_decode(rh.payload).expect("Invalid hex in hop payload"),
                hmac: None,
                keys: None,
                shared_secret: None,
                filler_acc: None,
            }
        }).collect();
        OnionPayload {
            session_key,
            associated_data,
            hops,
        }
    }
}

struct SphinxCrypto {
    onion_payload: OnionPayload,
    private_key: SecretKey,
}

impl SphinxCrypto {
    fn new(onion_payload: OnionPayload) -> Self {
        let sk = SecretKey::from_slice(&onion_payload.session_key)
            .expect("Invalid session key");
        SphinxCrypto {
            onion_payload,
            private_key: sk,
        }
    }

    fn generate_hop_keys_secrets(&mut self) {
        let secp = Secp256k1::new();
        let mut ephemeral_key = self.private_key;

        for hop in &mut self.onion_payload.hops {
            let shared_secret = Self::generate_shared_secret(ephemeral_key, &hop.pubkey);
            hop.shared_secret = Some(shared_secret.clone());
            hop.keys = Some(generate_hop_keys(&shared_secret));

            println!("Hop {} shared_secret: {}", hop.id, hex_encode(&shared_secret));
            let keys = hop.keys.as_ref().unwrap();
            println!("Hop {} keys: rho={}, mu={}, um={}",
                     hop.id,
                     hex_encode(&keys.rho_key),
                     hex_encode(&keys.mu_key),
                     hex_encode(&keys.um_key)
            );

            // Compute blinding factor matching Python
            let ephemeral_pub = PublicKey::from_secret_key(&secp, &ephemeral_key);
            let mut hasher = Sha256::new();
            hasher.update(ephemeral_pub.serialize()); // Compressed, 33 bytes
            hasher.update(&shared_secret);
            let blind_factor_hash = hasher.finalize();
            let blind_factor = Scalar::from_be_bytes(blind_factor_hash.into())
                .expect("Invalid blind factor");
            ephemeral_key = ephemeral_key.mul_tweak(&blind_factor)
                .expect("Failed to apply blind factor");
        }
    }

    fn generate_shared_secret(eph_key: SecretKey, pubkey_bytes: &[u8]) -> Vec<u8> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_slice(pubkey_bytes)
            .expect("Invalid public key");
        // Compute shared point and serialize it compressed
        let shared_point = pubkey.mul_tweak(&secp, &Scalar::from(eph_key))
            .expect("Failed to compute shared point");
        let shared_bytes = shared_point.serialize(); // Compressed, 33 bytes
        Sha256::digest(shared_bytes).to_vec()
    }
}

fn generate_hop_keys(shared_secret: &[u8]) -> HopKeys {
    HopKeys {
        rho_key: compute_hmac(shared_secret, KEY_RHO),
        mu_key: compute_hmac(shared_secret, KEY_MU),
        um_key: compute_hmac(shared_secret, KEY_UM),
    }
}

fn compute_hmac(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

struct OnionPacketBuilder {
    onion_payload: OnionPayload,
    session_key: Vec<u8>,
    hops: Vec<Hop>,
    cached_rho_streams: HashMap<Vec<u8>, Vec<u8>>,
}

impl OnionPacketBuilder {
    fn new(onion_payload: OnionPayload) -> Self {
        let session_key = onion_payload.session_key.clone();
        let hops = onion_payload.hops.clone();
        OnionPacketBuilder {
            onion_payload,
            session_key,
            hops,
            cached_rho_streams: HashMap::new(),
        }
    }

    fn get_rho_stream(&mut self, hop_rho: &[u8]) -> Vec<u8> {
        if let Some(stream) = self.cached_rho_streams.get(hop_rho) {
            return stream.clone();
        }
        let mut cipher = ChaCha20::new_from_slices(hop_rho, &ZERO_NONCE)
            .expect("Error creating ChaCha20 cipher");
        let mut data = vec![0u8; 2600];
        cipher.apply_keystream(&mut data);
        self.cached_rho_streams.insert(hop_rho.to_vec(), data.clone());
        data
    }

    fn generate_filler(&mut self) -> Vec<u8> {
        if self.hops.len() <= 1 {
            return vec![];
        }
        let hop_sizes: Vec<usize> = self.hops.iter().map(|hop| hop.payload.len() + HMAC_SIZE).collect();
        let mut cumulative_sizes: Vec<usize> = Vec::with_capacity(self.hops.len());
        for i in 0..self.hops.len() {
            cumulative_sizes.push(hop_sizes.iter().take(i).sum());
        }
        let onion_payload_length = PACKET_SIZE;
        let mut final_filler: Option<Vec<u8>> = None;
        
        for i in 0..(self.hops.len() - 1) {
            let rho_key = self.hops[i].keys.as_ref().unwrap().rho_key.clone();
            let rho_stream = self.get_rho_stream(&rho_key);
            let filler_start = onion_payload_length - cumulative_sizes[i];
            let filler_end = onion_payload_length + self.hops[i].payload.len();
            let filler_length = filler_end + HMAC_SIZE - filler_start;
            let mut this_filler = vec![0u8; filler_length];
            for j in filler_start..(filler_end + HMAC_SIZE) {
                let idx = j - filler_start;
                this_filler[idx] ^= rho_stream[j];
            }
            
            if i == 0 {
                self.hops[i].filler_acc = Some(this_filler);
            } else {
                let (left, _) = self.hops.split_at_mut(i);
                let prev_hop = left.last().unwrap();
                let prev_filler = prev_hop.filler_acc.as_ref().unwrap();
                let mut filler_acc = this_filler;
                for j in 0..cumulative_sizes[i] {
                    filler_acc[j] ^= prev_filler[j];
                }
                self.hops[i].filler_acc = Some(filler_acc);
            }
            if i == self.hops.len() - 2 {
                final_filler = self.hops[i].filler_acc.clone();
            }
        }
        if let Some(ref filler) = final_filler {
            println!("Final filler: {}", hex_encode(filler));
            filler.clone()
        } else {
            vec![]
        }
    }

    fn construct_packet(&mut self) -> Vec<u8> {
        let secp = Secp256k1::new();
        let pad_key = compute_hmac(&self.session_key, KEY_PAD);
        let mut cipher = ChaCha20::new_from_slices(&pad_key, &ZERO_NONCE)
            .expect("Error creating ChaCha20 cipher");
        let mut packet = vec![0u8; PACKET_SIZE];
        cipher.apply_keystream(&mut packet);

        let filler = self.generate_filler();
        let mut next_hmac = vec![0u8; HMAC_SIZE];

        for i in (0..self.hops.len()).rev() {
            {
                let hop = &mut self.hops[i];
                let hop_size = hop.payload.len() + HMAC_SIZE;
                hop.hmac = Some(next_hmac.clone());

                packet.copy_within(0..(PACKET_SIZE - hop_size), hop_size);
                for j in 0..hop.payload.len() {
                    packet[j] = hop.payload[j];
                }
                let hmac_val = hop.hmac.as_ref().unwrap();
                for j in 0..HMAC_SIZE {
                    packet[hop.payload.len() + j] = hmac_val[j];
                }
                let rho_key = hop.keys.as_ref().unwrap().rho_key.clone();
                let rho_stream = self.get_rho_stream(&rho_key);
                for j in 0..PACKET_SIZE {
                    packet[j] ^= rho_stream[j];
                }
                if i == self.hops.len() - 1 {
                    let filler_len = filler.len();
                    packet[PACKET_SIZE - filler_len..].copy_from_slice(&filler);
                }
            }
            let mut hmac_data = packet.clone();
            if !self.onion_payload.associated_data.is_empty() {
                hmac_data.extend(&self.onion_payload.associated_data);
            }
            let mu_key = self.hops[i].keys.as_ref().unwrap().mu_key.clone();
            let mut mac = Hmac::<Sha256>::new_from_slice(&mu_key)
                .expect("HMAC can take key of any size");
            mac.update(&hmac_data);
            next_hmac = mac.finalize().into_bytes().to_vec();
        }

        // Fix: Convert session_key to SecretKey
        let session_key = SecretKey::from_slice(&self.session_key)
            .expect("Invalid session key");
        let session_pub = PublicKey::from_secret_key(&secp, &session_key);
        let mut final_packet = vec![0u8];
        final_packet.extend_from_slice(&session_pub.serialize());
        final_packet.extend_from_slice(&packet);
        final_packet.extend_from_slice(&next_hmac);

        println!("Final packet: {}", hex_encode(&final_packet));
        final_packet
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <output_directory> <input_file>", args[0]);
        std::process::exit(1);
    }
    let output_directory = &args[1];
    let input_file = &args[2];

    let full_path = Path::new(output_directory).join(input_file);
    println!("Attempting to read: {}", full_path.display());

    fs::create_dir_all(output_directory).expect("Failed to create output directory");

    let onion_payload = OnionPayload::from_json_file(full_path.to_str().unwrap());
    println!("OnionPayload loaded:");
    println!("Session key: {}", hex_encode(&onion_payload.session_key));
    println!("Associated data: {}", hex_encode(&onion_payload.associated_data));
    for hop in &onion_payload.hops {
        println!(
            "Hop {}: pubkey={}, payload={}",
            hop.id,
            hex_encode(&hop.pubkey),
            hex_encode(&hop.payload)
        );
    }

    let mut crypto = SphinxCrypto::new(onion_payload);
    crypto.generate_hop_keys_secrets();
    let mut builder = OnionPacketBuilder::new(crypto.onion_payload);
    let final_packet = builder.construct_packet();

    let output_path = Path::new(output_directory).join("output.txt");
    let mut file = File::create(&output_path).expect("Unable to create output file");
    file.write_all(hex_encode(&final_packet).as_bytes())
        .expect("Unable to write data");
    println!("Output written to: {}", output_path.display());
}