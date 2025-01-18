import json
import hashlib
import hmac
from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
from typing import Any, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor

from wallet_dataclasses import DerivedKey, DeserializedKey
from utils import validate_bytes_length, split_derivation_string, bcli
from constants import EXTENDED_KEY_LENGTH, PRIVATE_KEY_LENGTH, CHAINCODE_LENGTH, PUBKEY_COMPRESSED_LENGTH

WALLET_NAME = "wallet_109"
EXTENDED_PRIVATE_KEY = "wpkh(tprv8ZgxMBicQKsPcvvA9Y4GcwhZJAx6KCmqw4sz9PEidDEhyFNwSXkie7xSL72KaZCx2vTVsG63mGwCKQAUxm9pTS41TpWTEs7PTDBqXb8uY2L/84h/1h/0h/0/*)#vu7vzl0x"

def is_hardened_index(index: int) -> bool:
    """Check if a child index is hardened   ."""
    return index >= 0x80000000

# Decode a base58 string into an array of bytes
def base58_decode(base58_string: str) -> bytes:
    base58_alphabet = list("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    # Convert Base58 string to a big integer
    big_int = sum(
        base58_alphabet.index(char) * (58 ** idx)
        for idx, char in enumerate(reversed(base58_string))
    )
    # Count leading '1's to add leading zero bytes
    leading_zeros = len(base58_string) - len(base58_string.lstrip('1'))
    
    # Convert the integer to bytes
    if big_int == 0:
        decoded_bytes = b'\x00' * leading_zeros
    else:
        result_bytes = big_int.to_bytes((big_int.bit_length() + 7) // 8, byteorder='big')
        # Add leading zero bytes
        decoded_bytes = b'\x00' * leading_zeros + result_bytes
    
    # Chop off the 32 checksum bits and return
    return decoded_bytes[:-4]

    # BONUS POINTS: Verify the checksum!


# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
def deserialize_key(b: bytes) -> DeserializedKey:
    validate_bytes_length(b, EXTENDED_KEY_LENGTH, "extended key")

    # Parse each field according to the specification
    version = b[0:4]
    depth = b[4]
    parent_fingerprint = b[5:9]
    child_number = int.from_bytes(b[9:13], byteorder='big')
    chaincode = b[13:45]
    key_data = b[45:78]

    # Convert version to hex for readability
    version_hex = version.hex()
    
    # Determine if this is a private or public key and mainnet or testnet
    key_type = None
    network = None
    if version_hex == "0488b21e":
        key_type = "public"
        network = "mainnet"
    elif version_hex == "0488ade4":
        key_type = "private"
        network = "mainnet"
    elif version_hex == "043587cf":
        key_type = "public"
        network = "signet"
    elif version_hex == "04358394":
        key_type = "private"
        network = "signet"
    else:
        raise ValueError(f"Invalid version bytes: {version_hex}")
    
    # For private keys, verify the first byte is 0x00 and get the private key
    if key_type == "private":
        if key_data[0] != 0x00:
            raise ValueError("Invalid private key prefix")
        key = key_data[1:]
    else:
        key = key_data
    
    return DeserializedKey(
        version=version,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        chaincode=chaincode,
        key=key,
        key_type=key_type,
        network=network
    )


# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!
def get_pub_from_priv(priv: bytes) -> bytes:
    validate_bytes_length(priv, PRIVATE_KEY_LENGTH,"private key")
        
    # Create signing key from private bytes
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    
    # Get the verifying key (public key)
    vk = sk.get_verifying_key()
    
    # Get the compressed public key bytes (33 bytes with prefix)
    return vk.to_string("compressed")


# Perform a BIP32 parent private key -> child private key operation
# Return a JSON object with "key" and "chaincode" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> DerivedKey:
    # Input validation
    validate_bytes_length(key, PRIVATE_KEY_LENGTH,"private key")
    validate_bytes_length(chaincode, CHAINCODE_LENGTH,"cahincode")
    if index < 0 or index >= 0x80000000:
        raise ValueError(f"Invalid child index: {index}")
        
    if hardened:
        index += 0x80000000
    
    # Prepare the HMAC input data
    if hardened:
        # For hardened keys, we use the parent private key padded to 33 bytes
        data = b'\x00' + key
    else:
        # For normal derivation, we use the corresponding public key
        # First derive the public key
        data = get_pub_from_priv(key)
        
    # Append the child index in big-endian
    data += index.to_bytes(4, byteorder='big')
    
    # Calculate HMAC-SHA512 with chain code as key
    hmac_obj = hmac.new(chaincode, data, hashlib.sha512)
    i = hmac_obj.digest()
    
    # Split into left (IL) and right (IR) 32-byte sequences
    il, ir = i[:32], i[32:]
    
    # Convert IL to integer modulo the curve order n
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    il_int = int.from_bytes(il, byteorder='big')
    
    # Check that IL is less than the curve order
    if il_int >= n:
        raise ValueError("Derived key is invalid (IL >= n)")
    
    # Add parent private key to IL modulo n to get child private key
    key_int = int.from_bytes(key, byteorder='big')
    child_key_int = (il_int + key_int) % n
    
    # Check for invalid derivation (extremely unlikely)
    if child_key_int == 0:
        raise ValueError("Derived key is invalid (zero)")
        
    # Convert child key back to 32 bytes
    child_key = child_key_int.to_bytes(32, byteorder='big')
    
    # IR becomes the child chain code
    child_chaincode = ir
    
    return DerivedKey(key=child_key, chaincode=child_chaincode)


# Given an extended private key and a BIP32 derivation path,
# compute the first 2000 child private keys.
# Return an array of keys encoded as bytes.
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples.
def get_wallet_privs(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    """Derive child private keys following a BIP32 derivation path."""
    # Input validation
    validate_bytes_length(key, PRIVATE_KEY_LENGTH,"private key")
    validate_bytes_length(chaincode, CHAINCODE_LENGTH,"cahincode")
    
    # First derive the base path
    current_key = key
    current_chaincode = chaincode
    
    # Follow the derivation path
    for index, hardened in path:
        # Derive the next key in the path
        derived = derive_priv_child(current_key, current_chaincode, index, hardened)
        current_key = derived.key
        current_chaincode = derived.chaincode
    
    # Now generate 2000 child keys from the derived path
    child_keys = []
    for i in range(0,2000):
        # Always use non-hardened derivation for the final keys
        derived = derive_priv_child(current_key, current_chaincode, i, hardened=False)
        child_keys.append(derived.key)
    
    return child_keys


# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key.
# Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
# so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
def get_p2wpkh_program(pubkey: bytes, version: int=0) -> bytes:
    """Derive the P2WPKH witness program (scriptPubKey) for a given compressed public key."""
    # Input validation
    validate_bytes_length(pubkey, PUBKEY_COMPRESSED_LENGTH,"pubkey")
    if version < 0 or version > 16:
        raise ValueError("Version must be between 0 and 16")
    
    # Double hash the public key
    sha256_hash = hashlib.sha256(pubkey).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Construct the witness program
    # OP_n (version) + push_20 + hash
    witness_program = bytes([version]) + bytes([0x14]) + ripemd160_hash
    
    return witness_program


# Recover the wallet state from the blockchain:
# - Parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance
def recover_wallet_state(tprv: str):
    # Generate addresses and keys
    derivation_components = split_derivation_string(tprv)
    extended_key_bytes = base58_decode(derivation_components.key)
    deserialized = deserialize_key(extended_key_bytes)
    derivation_path = derivation_components.parse_path()

    privs = get_wallet_privs(deserialized.key, deserialized.chaincode, derivation_path)
    pubs = [get_pub_from_priv(priv) for priv in privs]
    programs = [get_p2wpkh_program(pub) for pub in pubs]

    # Create lookup sets
    our_scripts = set(p.hex() for p in programs)
    script_to_info = {}
    
    # Map scripts to their info
    for i, program in enumerate(programs):
        hex_script = program.hex()
        script_info = json.loads(bcli(f"decodescript {hex_script}"))
        script_to_info[hex_script] = {
            "address": script_info["address"],
            "pub": pubs[i].hex(),
            "priv": privs[i].hex()
        }

    state = {
        "utxo": {},
        "balance": 0,
        "transactions": []
    }

    height = 300
    for h in range(height + 1):

        block_hash = bcli(f"getblockhash {h}")
        block_data = json.loads(bcli(f"getblock {block_hash} 2"))
        
        for tx in block_data["tx"]:
            tx_id = tx["txid"]
            
            # Check outputs (receiving to our wallet)
            if "vout" in tx:
                for out in tx["vout"]:
                    if "scriptPubKey" in out and "hex" in out["scriptPubKey"]:
                        script = out["scriptPubKey"]["hex"]
                        if script in our_scripts:
                            amount = out["value"]
                            state["balance"] += amount
                            
                            outpoint = f"{tx_id}:{out['n']}"
                            state["utxo"][outpoint] = {
                                "amount": amount,
                                "script": script,
                                "address": script_to_info[script]["address"],
                                "priv": script_to_info[script]["priv"],
                                "pub": script_to_info[script]["pub"]
                            }
                            
                            state["transactions"].append({
                                "type": "receive",
                                "block": h,
                                "txid": tx_id,
                                "amount": amount,
                                "address": script_to_info[script]["address"]
                            })

            # Check inputs (spending from our wallet)
            if "vin" in tx:
                for inp in tx["vin"]:
                    if "txinwitness" in inp and len(inp["txinwitness"]) >= 2:
                        witness_pubkey = inp["txinwitness"][1]
                        outpoint = f"{inp['txid']}:{inp['vout']}"
                        
                        # Only process if it's spending one of our UTXOs
                        if outpoint in state["utxo"]:
                            utxo = state["utxo"][outpoint]
                            if utxo["pub"] == witness_pubkey:
                                amount = utxo["amount"]
                                state["balance"] -= amount
                                del state["utxo"][outpoint]
                                
                                state["transactions"].append({
                                    "type": "spend",
                                    "block": h,
                                    "txid": tx_id,
                                    "amount": amount,
                                    "address": utxo["address"]
                                })

    return state

if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']:.8f}")