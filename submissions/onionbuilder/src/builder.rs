use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};

use crate::{
    Error,
    OnionPayload,
    constants::{ZERO_NONCE, KEY_TYPES, PACKET_SIZE, HMAC_SIZE},
};

type HmacSha256 = Hmac<Sha256>;

pub struct OnionPacketBuilder {
    onion_payload: OnionPayload,
    session_key: Vec<u8>,
    rho_streams: HashMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone)]
struct HopData {
    payload: Vec<u8>,
    rho_key: Vec<u8>,
    mu_key: Vec<u8>,
}

impl OnionPacketBuilder {
    pub fn new(onion_payload: OnionPayload) -> Self {
        Self {
            session_key: onion_payload.session_key.clone(),
            onion_payload,
            rho_streams: HashMap::new(),
        }
    }

    fn get_rho_stream(&mut self, hop_rho: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(stream) = self.rho_streams.get(hop_rho) {
            return Ok(stream.clone());
        }

        let cipher = ChaCha20::new(
            hop_rho.into(),
            (&ZERO_NONCE).into()
        );
        
        let mut stream = vec![0u8; 2600];
        let mut cipher = cipher;
        cipher.apply_keystream(&mut stream);
        
        self.rho_streams.insert(hop_rho.to_vec(), stream.clone());
        Ok(stream)
    }

    fn collect_hop_data(&self) -> Vec<HopData> {
        self.onion_payload.hops.iter()
            .filter_map(|hop| {
                hop.keys.as_ref().map(|keys| HopData {
                    payload: hop.payload.clone(),
                    rho_key: keys.rho_key.clone(),
                    mu_key: keys.mu_key.clone(),
                })
            })
            .collect()
    }

    pub fn generate_filler(&mut self) -> Result<Vec<u8>, Error> {
        if self.onion_payload.hops.len() <= 1 {
            return Ok(Vec::new());
        }

        let hop_data = self.collect_hop_data();
        let hop_sizes: Vec<usize> = hop_data.iter()
            .map(|h| h.payload.len() + HMAC_SIZE)
            .collect();

        let cumulative_sizes: Vec<usize> = hop_sizes.iter()
            .scan(0, |acc, &x| {
                *acc += x;
                Some(*acc)
            })
            .collect();

        let mut final_filler = None;
        let mut prev_filler: Option<Vec<u8>> = None;

        for (i, hop) in hop_data.iter().take(self.onion_payload.hops.len() - 1).enumerate() {
            let filler_start = PACKET_SIZE - cumulative_sizes[i];
            let filler_end = PACKET_SIZE + hop.payload.len();
            
            let rho_stream = self.get_rho_stream(&hop.rho_key)?;
            let mut this_filler = vec![0u8; filler_end - filler_start + HMAC_SIZE];
            
            for (j, filler_byte) in this_filler.iter_mut().enumerate() {
                *filler_byte ^= rho_stream[filler_start + j];
            }

            if let Some(prev) = prev_filler {
                for j in 0..cumulative_sizes[i] {
                    this_filler[j] ^= prev[j];
                }
            }

            if i == self.onion_payload.hops.len() - 2 {
                final_filler = Some(this_filler.clone());
            }

            prev_filler = Some(this_filler);
        }

        Ok(final_filler.unwrap_or_default())
    }

    pub fn construct_packet(&mut self) -> Result<Vec<u8>, Error> {
        let hop_data = self.collect_hop_data();
        
        // Initialize packet with random padding
        let pad_key = {
            let mut mac = HmacSha256::new_from_slice(KEY_TYPES[3].1)
                .map_err(|e| Error::Crypto(format!("Invalid HMAC key: {}", e)))?;
            mac.update(&self.session_key);
            mac.finalize().into_bytes().to_vec()
        };
        
        let cipher = ChaCha20::new(
            pad_key.as_slice().into(),
            (&ZERO_NONCE).into()
        );
        
        let mut packet = vec![0u8; PACKET_SIZE];
        let mut cipher = cipher;
        cipher.apply_keystream(&mut packet);
        
        let filler = self.generate_filler()?;
        let mut next_hmac = vec![0u8; HMAC_SIZE];
        
        // Process hops in reverse order
        for (i, hop) in hop_data.iter().enumerate().rev() {
            let hop_size = hop.payload.len() + HMAC_SIZE;
            
            // Create temporary buffer for the shift
            let mut new_packet = vec![0u8; PACKET_SIZE];
            new_packet[hop_size..].copy_from_slice(&packet[..PACKET_SIZE - hop_size]);
            
            // Insert hop payload and HMAC
            new_packet[..hop.payload.len()].copy_from_slice(&hop.payload);
            new_packet[hop.payload.len()..hop_size].copy_from_slice(&next_hmac);
            
            packet = new_packet;
            
            // XOR with stream bytes
            let stream_bytes = self.get_rho_stream(&hop.rho_key)?;
            for (j, packet_byte) in packet.iter_mut().enumerate() {
                *packet_byte ^= stream_bytes[j];
            }
            
            // Add filler for last hop
            if i == hop_data.len() - 1 {
                let start = packet.len() - filler.len();
                packet[start..].copy_from_slice(&filler);
            }
            
            // Calculate next HMAC
            let mut mac = HmacSha256::new_from_slice(&hop.mu_key)
                .map_err(|e| Error::Crypto(format!("Invalid HMAC key: {}", e)))?;
            
            mac.update(&packet);
            if !self.onion_payload.associated_data.is_empty() {
                mac.update(&self.onion_payload.associated_data);
            }
            
            next_hmac = mac.finalize().into_bytes().to_vec();
        }
        
        // Build final packet
        let mut final_packet = vec![0];  // Version byte
        
        // Add public key
        let pub_key = SecretKey::from_slice(&self.session_key)
            .map_err(|e| Error::Crypto(format!("Invalid session key: {}", e)))?
            .public_key()
            .as_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
            
        final_packet.extend_from_slice(&pub_key);
        final_packet.extend_from_slice(&packet);
        final_packet.extend_from_slice(&next_hmac);
        
        Ok(final_packet)
    }
}