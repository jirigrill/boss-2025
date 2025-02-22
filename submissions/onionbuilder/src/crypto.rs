use k256::{
    SecretKey,
    PublicKey,
    elliptic_curve::{
        sec1::ToEncodedPoint,
    },
};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::{
    Error,
    OnionPayload,
    HopKeys,
    constants::{KEY_TYPES},
};

type HmacSha256 = Hmac<Sha256>;

// Thread-safe cache for HMAC operations
static HMAC_CACHE: Lazy<Mutex<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>> = 
    Lazy::new(|| Mutex::new(HashMap::new()));

pub struct SphinxCrypto {
    pub onion_payload: OnionPayload,
    private_key: SecretKey,
}

impl SphinxCrypto {
    pub fn new(onion_payload: OnionPayload) -> Result<Self, Error> {
        let private_key = SecretKey::from_slice(&onion_payload.session_key)
            .map_err(|e| Error::Crypto(format!("Invalid session key: {}", e)))?;
        
        Ok(Self {
            onion_payload,
            private_key,
        })
    }

    pub fn generate_hop_keys_secrets(&mut self) -> Result<(), Error> {
        let mut ephemeral_key = self.private_key.to_bytes().as_slice().to_vec();
        let mut hops = std::mem::take(&mut self.onion_payload.hops);
        
        for hop in &mut hops {
            // Generate shared secret
            hop.shared_secret = Some(
                Self::generate_shared_secret(&ephemeral_key, &hop.pubkey)?
            );
            
            // Generate hop keys
            if let Some(ref shared_secret) = hop.shared_secret {
                let keys = HopKeys {
                    rho_key: self.compute_hmac(shared_secret, KEY_TYPES[0].1)?,
                    mu_key: self.compute_hmac(shared_secret, KEY_TYPES[1].1)?,
                    um_key: self.compute_hmac(shared_secret, KEY_TYPES[2].1)?,
                };
                hop.keys = Some(keys);
            }
            
            // Update ephemeral key for next hop
            let public_key = PublicKey::from_sec1_bytes(&hop.pubkey)
                .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;
            
            let encoded_point = public_key.as_affine().to_encoded_point(false);
            
            let blind_factor = {
                let mut hasher = Sha256::new();
                hasher.update(encoded_point.as_bytes());
                if let Some(ref secret) = hop.shared_secret {
                    hasher.update(secret);
                }
                hasher.finalize().to_vec()
            };
            
            // Update ephemeral key using SHA256
            let mut hasher = Sha256::new();
            hasher.update(&ephemeral_key);
            hasher.update(&blind_factor);
            ephemeral_key = hasher.finalize().to_vec();
        }
        
        self.onion_payload.hops = hops;
        Ok(())
    }

    fn generate_shared_secret(
        eph_key: &[u8],
        pubkey: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let secret_key = SecretKey::from_slice(eph_key)
            .map_err(|e| Error::Crypto(format!("Invalid ephemeral key: {}", e)))?;
            
        let public_key = PublicKey::from_sec1_bytes(pubkey)
            .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;
        
        // Perform ECDH
        let shared_point = public_key.as_affine();
        let encoded_point = shared_point.to_encoded_point(false);
        
        let mut hasher = Sha256::new();
        hasher.update(encoded_point.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    fn compute_hmac(&self, message: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        // Check cache first
        let cache_key = (message.to_vec(), key.to_vec());
        if let Some(cached_result) = HMAC_CACHE.lock()
            .map_err(|_| Error::Crypto("HMAC cache lock poisoned".to_string()))?
            .get(&cache_key) 
        {
            return Ok(cached_result.clone());
        }
        
        // Compute HMAC
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| Error::Crypto(format!("Invalid HMAC key: {}", e)))?;
        mac.update(message);
        let result = mac.finalize().into_bytes().to_vec();
        
        // Cache result
        HMAC_CACHE.lock()
            .map_err(|_| Error::Crypto("HMAC cache lock poisoned".to_string()))?
            .insert(cache_key, result.clone());
        
        Ok(result)
    }
}