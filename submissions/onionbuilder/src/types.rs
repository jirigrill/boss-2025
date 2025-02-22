use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::Error;

#[derive(Clone, Debug)]
pub struct HopKeys {
    pub rho_key: Vec<u8>,
    pub mu_key: Vec<u8>,
    pub um_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Hop {
    pub id: u32,
    pub name: String,
    pub pubkey: Vec<u8>,
    pub payload: Vec<u8>,
    pub hmac: Option<Vec<u8>>,
    pub keys: Option<HopKeys>,
    pub shared_secret: Option<Vec<u8>>,
    pub filler_acc: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HopJson {
    name: String,
    pubkey: String,
    payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OnionPayloadJson {
    session_key: String,
    associated_data: String,
    hops: Vec<HopJson>,
}

#[derive(Clone, Debug)]
pub struct OnionPayload {
    pub session_key: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub hops: Vec<Hop>,
}

impl OnionPayload {
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file_content = std::fs::read_to_string(path)?;
        let json_data: OnionPayloadJson = serde_json::from_str(&file_content)?;
        
        Ok(Self {
            session_key: hex::decode(&json_data.session_key)?,
            associated_data: hex::decode(&json_data.associated_data)?,
            hops: json_data
                .hops
                .into_iter()
                .enumerate()
                .map(|(i, hop)| Hop {
                    id: (i + 1) as u32,
                    name: hop.name,
                    pubkey: hex::decode(&hop.pubkey).unwrap_or_default(),
                    payload: hex::decode(&hop.payload).unwrap_or_default(),
                    hmac: None,
                    keys: None,
                    shared_secret: None,
                    filler_acc: None,
                })
                .collect(),
        })
    }
}