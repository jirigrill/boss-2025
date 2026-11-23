import json
import sys
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
from binascii import unhexlify
import hmac
import hashlib
from coincurve import PrivateKey, PublicKey
from Crypto.Cipher import ChaCha20
from functools import lru_cache

@dataclass(frozen=True)
class HopKeys:
    rho_key: bytes
    mu_key: bytes
    um_key: bytes

@dataclass
class Hop:
    id: int
    pubkey: bytes
    payload: bytes
    hmac: Optional[bytes] = None
    keys: Optional[HopKeys] = None
    shared_secret: Optional[bytes] = None
    filler_acc: Optional[bytes] = None

@dataclass
class OnionPayload:
    session_key: bytes
    associated_data: bytes
    hops: List[Hop]
    
    @classmethod
    def from_json_file(cls, file_path: str | Path) -> 'OnionPayload':
        with open(file_path, 'r') as f:
            data = json.load(f)
        # Debug: print loaded JSON data
        print("Loaded JSON data:", data)
        return cls(
            session_key=unhexlify(data['session_key']),
            associated_data=unhexlify(data['associated_data']),
            hops=[
                Hop(
                    id=i,
                    pubkey=unhexlify(hop_data['pubkey']),
                    payload=unhexlify(hop_data['payload'])
                )
                for i, hop_data in enumerate(data['hops'], 1)
            ]
        )

class SphinxCrypto:
    # Pre-computed constants
    KEY_TYPES = {
        'rho': bytes.fromhex('72686F'),
        'mu': bytes.fromhex('6d75'),
        'um': bytes.fromhex('756d'),
        'pad': bytes.fromhex('706164')
    }
    SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ZERO_NONCE = b'\x00' * 12

    def __init__(self, onion_payload: OnionPayload):
        self.onion_payload = onion_payload
        self.private_key = PrivateKey(onion_payload.session_key)

    def generate_hop_keys_secrets(self) -> None:
        ephemeral_key = self.private_key.secret
        for hop in self.onion_payload.hops:
            hop.shared_secret = self._generate_shared_secret(ephemeral_key, hop.pubkey)
            hop.keys = self._generate_hop_keys(hop.shared_secret)
            
            # Debug prints for shared secret and keys
            print(f"Hop {hop.id} shared_secret: {hop.shared_secret.hex()}")
            print(f"Hop {hop.id} keys: rho={hop.keys.rho_key.hex()}, mu={hop.keys.mu_key.hex()}, um={hop.keys.um_key.hex()}")

            # Update ephemeral key for next hop
            blind_factor = hashlib.sha256(
                PrivateKey(ephemeral_key).public_key.format() + hop.shared_secret
            ).digest()
            ephemeral_key = (
                (int.from_bytes(ephemeral_key, 'big') * 
                int.from_bytes(blind_factor, 'big')) % self.SECP256K1_ORDER
            ).to_bytes(32, 'big')

    @staticmethod
    @lru_cache(maxsize=32)
    def _generate_shared_secret(eph_key: bytes, pubkey: bytes) -> bytes:
        shared_point = PublicKey(pubkey).multiply(eph_key)
        return hashlib.sha256(shared_point.format()).digest()

    def _generate_hop_keys(self, shared_secret: bytes) -> HopKeys:
        return HopKeys(
            rho_key=self._compute_hmac(shared_secret, self.KEY_TYPES['rho']),
            mu_key=self._compute_hmac(shared_secret, self.KEY_TYPES['mu']),
            um_key=self._compute_hmac(shared_secret, self.KEY_TYPES['um'])
        )

    @staticmethod
    @lru_cache(maxsize=32)
    def _compute_hmac(message: bytes, key: bytes) -> bytes:
        return hmac.new(key, message, hashlib.sha256).digest()

class OnionPacketBuilder:
    PACKET_SIZE = 1300
    HMAC_SIZE = 32

    def __init__(self, onion_payload: OnionPayload):
        self.onion_payload = onion_payload
        self.session_key = onion_payload.session_key
        self.hops = onion_payload.hops
        self._cached_rho_streams = {}

    def _get_rho_stream(self, hop_rho: bytes) -> bytes:
        if hop_rho not in self._cached_rho_streams:
            cipher = ChaCha20.new(key=hop_rho, nonce=SphinxCrypto.ZERO_NONCE)
            self._cached_rho_streams[hop_rho] = cipher.encrypt(bytes(2600))
        return self._cached_rho_streams[hop_rho]

    def generate_filler(self) -> bytes:
        if len(self.hops) <= 1:
            return b''
            
        hop_sizes = [(len(hop.payload) + self.HMAC_SIZE) for hop in self.hops]
        cumulative_sizes = [sum(hop_sizes[:i]) for i in range(len(self.hops))]
        
        onion_payload_length = self.PACKET_SIZE
        final_filler = None
        
        for i in range(len(self.hops) - 1):
            hop = self.hops[i]
            filler_start = onion_payload_length - cumulative_sizes[i]
            filler_end = onion_payload_length + len(hop.payload)
            
            rho_stream = self._get_rho_stream(hop.keys.rho_key)
            this_filler = bytearray(filler_end - filler_start + self.HMAC_SIZE)
            
            for j in range(filler_start, filler_end + self.HMAC_SIZE):
                this_filler[j - filler_start] ^= rho_stream[j]
            
            if i == 0:
                hop.filler_acc = bytes(this_filler)
            else:
                filler_acc = bytearray(this_filler)
                prev_filler = self.hops[i - 1].filler_acc
                for j in range(cumulative_sizes[i]):
                    filler_acc[j] ^= prev_filler[j]
                hop.filler_acc = bytes(filler_acc)
            
            if i == len(self.hops) - 2:
                final_filler = hop.filler_acc

        # Debug print for filler
        print(f"Final filler: {final_filler.hex() if final_filler else ''}")
        return final_filler or b''

    def construct_packet(self) -> bytes:
        pad_key = SphinxCrypto._compute_hmac(
            self.session_key,
            SphinxCrypto.KEY_TYPES['pad']
        )
        packet = bytearray(
            ChaCha20.new(key=pad_key, nonce=SphinxCrypto.ZERO_NONCE).encrypt(
                bytes(self.PACKET_SIZE)
            )
        )
        
        filler = self.generate_filler()
        next_hmac = b'\x00' * self.HMAC_SIZE
        
        for i in range(len(self.hops) - 1, -1, -1):
            hop = self.hops[i]
            hop_size = len(hop.payload) + self.HMAC_SIZE
            
            hop.hmac = next_hmac
            
            # Shift packet contents
            packet[:] = packet[-hop_size:] + packet[:-hop_size]
            # Insert hop payload and hmac
            packet[:len(hop.payload)] = hop.payload
            packet[len(hop.payload):hop_size] = hop.hmac
            
            # XOR with stream bytes
            stream_bytes = self._get_rho_stream(hop.keys.rho_key)
            packet = bytearray(b ^ stream_bytes[i] for i, b in enumerate(packet))
            
            if i == len(self.hops) - 1:
                packet[-len(filler):] = filler
            
            hmac_data = bytes(packet) + self.onion_payload.associated_data if self.onion_payload.associated_data else bytes(packet)
            next_hmac = hmac.new(hop.keys.mu_key, hmac_data, hashlib.sha256).digest()
        
        final_packet = (
            bytes([0]) +
            PrivateKey(self.session_key).public_key.format() +
            bytes(packet) +
            next_hmac
        )
        
        # Debug print for final packet
        print(f"Final packet: {final_packet.hex()}")
        return final_packet

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 main.py <output_directory> <input_file>")
        sys.exit(1)
        
    output_directory = Path(sys.argv[1])
    input_file = Path(sys.argv[2])
    
    output_directory.mkdir(parents=True, exist_ok=True)
    
    onion_payload = OnionPayload.from_json_file(input_file)
    print("OnionPayload loaded:")
    print(f"Session key: {onion_payload.session_key.hex()}")
    print(f"Associated data: {onion_payload.associated_data.hex()}")
    for hop in onion_payload.hops:
        print(f"Hop {hop.id}: pubkey={hop.pubkey.hex()}, payload={hop.payload.hex()}")
    
    crypto = SphinxCrypto(onion_payload)
    crypto.generate_hop_keys_secrets()
    
    builder = OnionPacketBuilder(onion_payload)
    final_packet = builder.construct_packet()
    
    output_file = output_directory / "output.txt"
    with open(output_file, 'w') as f:
        f.write(final_packet.hex())

if __name__ == "__main__":
    main()
