import hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
from typing import List, Any
from pathlib import Path
from wallet_methods import (
    get_pub_from_priv,
    get_p2wpkh_program)
from wallet_dataclasses import WalletState, BitcoinAmount
from constants import (
    PUBKEY_COMPRESSED_LENGTH,
    PUBKEY_COMPRESSED_PREFIX_02,
    PUBKEY_COMPRESSED_PREFIX_03,
    TX_ID_LENGTH,
    EMPTY_SCRIPTSIG,
    DEFAULT_SEQUENCE,
    PUBKEY_HASH_LENGTH,
    P2WPKH_SCRIPTCODE_LENGTH
)
from utils import validate_bytes_length, pretty_dict, get_script_to_info, enough_amount_for_transaction

# Get directory where current file is located
CURRENT_DIR = Path(__file__).parent

# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.
def create_multisig_script(keys: List[bytes]) -> bytes:
    # Validate inputs
    if len(keys) != 2:
        raise ValueError("Exactly 2 keys required")
        
    # Validate each key format and length
    for key in keys:
        validate_bytes_length(key, PUBKEY_COMPRESSED_LENGTH, "pubkey")
        if key[0:1] not in (PUBKEY_COMPRESSED_PREFIX_02, PUBKEY_COMPRESSED_PREFIX_03):
            raise ValueError("Invalid public key format")
    
    # Sort keys for deterministic output
    sorted_keys = sorted(keys)
    
    # Build script:
    # OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    script = (
        bytes([0x52])  # OP_2
        + bytes([0x21])  # Push 33 bytes
        + sorted_keys[0]
        + bytes([0x21])  # Push 33 bytes
        + sorted_keys[1]
        + bytes([0x52])  # OP_2
        + bytes([0xAE])  # OP_CHECKMULTISIG
    )
    return script

# Given an output script as a byte array, compute the p2wsh witness program
# This is a segwit version 0 pay-to-script-hash witness program.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
def get_p2wsh_program(script: bytes, version: int=0) -> bytes:
    # Compute SHA256 of the script
    script_hash = hashlib.sha256(script).digest()
    # Create witness program:
    # [version_byte] [32-byte-hash]
    # // edit [version_byte] ([0x20] for 32 bytes) [32-byte-hash]
    return bytes([version]) + bytes([0x20]) + script_hash


# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig
def input_from_utxo(txid: bytes, index: int) -> bytes:
    """Create a serialized transaction input from an outpoint."""
    # Validate inputs
    validate_bytes_length(txid, TX_ID_LENGTH, "tx id")
    if index < 0:
        raise ValueError("Output index cannot be negative")

    # Reverse txid bytes for protocol serialization
    reversed_txid = txid[::-1]
    
    # Convert index to 4 bytes, little-endian
    index_bytes = index.to_bytes(4, byteorder='little', signed=False)
    
    # Empty scriptSig (1 byte length of 0)
    empty_script = EMPTY_SCRIPTSIG
    
    # Default sequence (0xFFFFFFFF)
    sequence = DEFAULT_SEQUENCE
    
    # Concatenate all parts
    return reversed_txid + index_bytes + empty_script + sequence
    

# Given an output script and value (in satoshis), return a serialized transaction output
def output_from_options(script: bytes, value: int) -> bytes:
    # Validate value
    if value < 0:
        raise ValueError("Value cannot be negative")
    
    # Convert value to 8 bytes, little-endian
    value_bytes = value.to_bytes(8, byteorder='little', signed=False)
    
    # Get script length as a varint
    script_length = len(script)
    if script_length < 0xfd:
        length_bytes = bytes([script_length])
    elif script_length <= 0xffff:
        length_bytes = bytes([0xfd]) + script_length.to_bytes(2, byteorder='little', signed=False)
    elif script_length <= 0xffffffff:
        length_bytes = bytes([0xfe]) + script_length.to_bytes(4, byteorder='little', signed=False)
    else:
        length_bytes = bytes([0xff]) + script_length.to_bytes(8, byteorder='little', signed=False)
    
    # Concatenate: value + script_length + script
    return value_bytes + length_bytes + script


# Given a JSON utxo object, extract the public key hash from the output script
# and assemble the p2wpkh scriptcode as defined in BIP143
# <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
def get_p2wpkh_scriptcode(utxo: dict[str, Any]) -> bytes:
    """
    Create the P2WPKH scriptcode following BIP143 specification.
    
    The scriptcode must follow this exact format:
    - 1 byte:  0x19 (decimal 25, total script length)
    - 1 byte:  0x76 (OP_DUP)
    - 1 byte:  0xa9 (OP_HASH160)
    - 1 byte:  0x14 (push next 20 bytes)
    - 20 bytes: [pubkey hash]
    - 1 byte:  0x88 (OP_EQUALVERIFY)
    - 1 byte:  0xac (OP_CHECKSIG)
    
    Total length is always exactly 25 bytes.
    """
    try:
        # The witness program in the UTXO looks like:
        # [version_byte] [push_byte] [20-byte-pubkey-hash]
        # We need to extract just the pubkey hash
        
        # Get the hex script from UTXO
        hex_script = utxo['script']
        
        # Skip first 4 hex chars (2 bytes in binary):
        # - first byte is version (0x00 for P2WPKH)
        # - second byte is push operation (0x14 for 20 bytes)
        # Then take next 40 hex chars (20 bytes in binary) which is the pubkey hash
        pubkey_hash_hex = hex_script[4:44]
        
        # Convert hex string to bytes
        pubkey_hash = bytes.fromhex(pubkey_hash_hex)
        
        # Verify we got exactly 20 bytes
        validate_bytes_length(pubkey_hash, PUBKEY_HASH_LENGTH, "pubkey hash")
            
        # Now construct the scriptcode following the exact BIP143 template
        scriptcode = (
            # First byte: total script length (always 25)
            bytes([0x19])  
            
            # Second byte: OP_DUP - duplicates top stack item
            + bytes([0x76])
            
            # Third byte: OP_HASH160 - performs RIPEMD160(SHA256())
            + bytes([0xa9])
            
            # Fourth byte: Push next 20 bytes
            + bytes([0x14])
            
            # Next 20 bytes: The actual pubkey hash we extracted
            + pubkey_hash
            
            # Second-to-last byte: OP_EQUALVERIFY
            + bytes([0x88])
            
            # Last byte: OP_CHECKSIG
            + bytes([0xac])
        )
        
        # Verify we built it correctly
        validate_bytes_length(scriptcode, P2WPKH_SCRIPTCODE_LENGTH, "p2wpkh_scriptcode")
        return scriptcode
        
    except (KeyError, IndexError) as e:
        raise ValueError(f"Invalid UTXO format: {str(e)}")


# Compute the commitment hash for a single input and return bytes to sign.
# This implements the BIP 143 transaction digest algorithm
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
# We assume only a single input and two outputs,
# as well as constant default values for sequence and locktime
def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes], tx_version: int = 1) -> bytes:
    def dsha256(data: bytes) -> bytes:
        return hashlib.new("sha256", hashlib.new("sha256", data).digest()).digest()
    # Version
    version = (tx_version).to_bytes(4, byteorder='little', signed=False)

    # All TX input outpoints (only one in our case)
    hash_prevouts = dsha256(outpoint)

    # All TX input sequences (only one for us, always default value)
    sequence = DEFAULT_SEQUENCE  # 0xFFFFFFFF
    hash_sequence = dsha256(sequence)

    # Single outpoint being spent
    # Already provided as parameter

    # Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)
    # Already provided as parameter

    # Value of output being spent
    value_bytes = value.to_bytes(8, byteorder='little', signed=True)

    # Sequence of output being spent (always default for us)
    # Using DEFAULT_SEQUENCE (0xFFFFFFFF)

    # All TX outputs
    all_outputs = b''.join(outputs)
    hash_outputs = dsha256(all_outputs)

    # Locktime (always default for us)
    locktime = (0).to_bytes(4, byteorder='little', signed=False)

    # SIGHASH_ALL (always default for us)
    hash_type = (1).to_bytes(4, byteorder='little', signed=False)

    # Concatenate everything in specified order
    commitment_data = (
        version +           # 4 bytes
        hash_prevouts +     # 32 bytes
        hash_sequence +     # 32 bytes
        outpoint +         # 36 bytes
        scriptcode +       # variable
        value_bytes +      # 8 bytes
        sequence +         # 4 bytes
        hash_outputs +     # 32 bytes
        locktime +         # 4 bytes
        hash_type          # 4 bytes
    )
    
    # Return double SHA256 of the commitment
    return dsha256(commitment_data)


# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.
def get_key_index(utxo: dict[str,Any], programs: List[str]) -> int:
    """Find the index of the witness program that can spend the given UTXO."""
    try:
        # Extract witness program from UTXO script
        script = utxo.get('script')
        if not script or not isinstance(script, str):
            raise ValueError("Invalid UTXO: missing or invalid script")
            
        # Find matching program in our list
        try:
            return programs.index(script)
        except ValueError:
            raise ValueError(f"No matching witness program found for UTXO script: {script}")
            
    except (AttributeError, KeyError) as e:
        raise ValueError(f"Invalid UTXO format: {str(e)}")



# Given a private key and message digest as bytes, compute the ECDSA signature.
# Bitcoin signatures:
# - Must be strict-DER encoded
# - Must have the SIGHASH_ALL byte (0x01) appended
# - Must have a low s value as defined by BIP 62:
#   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
def sign(priv: bytes, msg: bytes) -> bytes:
    """Sign a message digest using ECDSA with Bitcoin-specific requirements."""
    # Keep signing until we produce a signature with "low s value"
    # We will have to decode the DER-encoded signature and extract the s value to check it
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    # Create signing key from private key bytes
    try:
        signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    except Exception as e:
        raise ValueError(f"Invalid private key: {str(e)}")

    # BIP 62: The order of the secp256k1 curve
    n = SECP256k1.order

    while True:
        # Generate signature in DER format
        signature = signing_key.sign_deterministic(
            msg,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der
        )
        
        # Parse DER signature to extract R and S values
        # DER format: 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S]
        try:
            # Skip 0x30 and total length
            pos = 2
            # Skip 0x02 and R length
            r_len = signature[pos + 1]
            pos += 2 + r_len
            # Skip 0x02 and read S length
            s_len = signature[pos + 1]
            pos += 2
            # Extract S value
            s = int.from_bytes(signature[pos:pos + s_len], byteorder='big')
            
            # Check if S is > N/2 (BIP 62 low S requirement)
            # If so, we need to negate it
            half_n = n >> 1
            if s > half_n:
                continue
                
            # Valid low-S signature found
            # Append SIGHASH_ALL byte
            return signature + bytes([0x01])
            
        except (IndexError, ValueError) as e:
            # Should never happen with valid ECDSA library
            raise ValueError(f"Invalid DER signature generated: {str(e)}")


# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    """
    Create a P2WPKH witness for transaction signing following BIP 141.
    
    Args:
        priv: Private key bytes
        msg: Message digest to sign (commitment hash)
        
    Returns:
        Serialized witness stack with signature and public key
        
    Format (BIP 141):
    - var_int: number of witness stack items (2 for P2WPKH)
    - For each stack item:
        - var_int: length of item
        - bytes: item data
    Stack items are:
    1. signature (with SIGHASH_ALL)
    2. compressed public key
    """
    # Get signature using existing sign() function
    signature = sign(priv, msg)
    
    # Get compressed public key from private key
    pubkey = get_pub_from_priv(priv)
    
    # Start witness with var_int for number of items (2)
    # Since it's < 0xfd, we can use a single byte
    witness = bytes([0x02])  # var_int for 2 items
    
    # Add signature as first stack item
    sig_len = len(signature)
    if sig_len < 0xfd:
        witness += bytes([sig_len])
    elif sig_len <= 0xffff:
        witness += bytes([0xfd]) + sig_len.to_bytes(2, byteorder='little', signed=False)
    elif sig_len <= 0xffffffff:
        witness += bytes([0xfe]) + sig_len.to_bytes(4, byteorder='little', signed=False)
    else:
        raise ValueError("Signature too long")
    witness += signature
    
    # Add compressed public key as second stack item
    pubkey_len = len(pubkey)
    if pubkey_len < 0xfd:
        witness += bytes([pubkey_len])
    elif pubkey_len <= 0xffff:
        witness += bytes([0xfd]) + pubkey_len.to_bytes(2, byteorder='little', signed=False)
    elif pubkey_len <= 0xffffffff:
        witness += bytes([0xfe]) + pubkey_len.to_bytes(4, byteorder='little', signed=False)
    else:
        raise ValueError("Public key too long")
    witness += pubkey
    
    return witness


# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    """
    Create a P2WSH witness for a 2-of-2 multisig transaction.
    
    Args:
        privs: List of exactly 2 private keys as bytes
        msg: Message digest to sign (commitment hash)
        
    Returns:
        Serialized witness stack with format:
        - var_int: number of witness stack items (4 for P2WSH multisig)
        - First item: Empty byte for CHECKMULTISIG bug
        - Second item: First signature
        - Third item: Second signature
        - Fourth item: Complete multisig script
        
    Each stack item is prefixed with its length as a var_int.
    """
    # Validate inputs
    if len(privs) != 2:
        raise ValueError("Exactly 2 private keys required")
    
    # Get public keys
    pubkeys = []
    signatures = []
    
    # Generate public keys and signatures
    for priv in privs:
        # Get compressed public key
        pubkey = get_pub_from_priv(priv)
        pubkeys.append(pubkey)
        
        # Sign message
        signature = sign(priv, msg)
        signatures.append(signature)
    
    # Create the multisig script
    script = create_multisig_script(pubkeys)
    
    # Start building witness with number of stack items (4)
    witness = bytes([0x04])  # var_int for 4 items
    
    # Add empty bytes for CHECKMULTISIG bug
    witness += bytes([0x00])  # Length 0
    
    # Add signatures
    for signature in signatures:
        sig_len = len(signature)
        if sig_len < 0xfd:
            witness += bytes([sig_len])
        elif sig_len <= 0xffff:
            witness += bytes([0xfd]) + sig_len.to_bytes(2, byteorder='little', signed=False)
        elif sig_len <= 0xffffffff:
            witness += bytes([0xfe]) + sig_len.to_bytes(4, byteorder='little', signed=False)
        else:
            raise ValueError("Signature too long")
        witness += signature
    
    # Add script
    script_len = len(script)
    if script_len < 0xfd:
        witness += bytes([script_len])
    elif script_len <= 0xffff:
        witness += bytes([0xfd]) + script_len.to_bytes(2, byteorder='little', signed=False)
    elif script_len <= 0xffffffff:
        witness += bytes([0xfe]) + script_len.to_bytes(4, byteorder='little', signed=False)
    else:
        raise ValueError("Script too long")
    witness += script
    
    return witness


def encode_varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin variable-length integer."""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return bytes([0xfd]) + n.to_bytes(2, byteorder='little', signed=False)
    elif n <= 0xffffffff:
        return bytes([0xfe]) + n.to_bytes(4, byteorder='little', signed=False)
    else:
        return bytes([0xff]) + n.to_bytes(8, byteorder='little', signed=False)

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    """
    Assemble a complete Bitcoin transaction following the protocol specification.
    
    Transaction Format:
    Field Size    |  Description      | Implementation
    ------------------------------------------------------------------
    4 bytes      |  version          | uint32_t (version 2)
    2 bytes      |  flag             | Always 0001 for witness tx
    1+ bytes     |  tx_in count      | varint
    41+ bytes    |  tx_in[]          | Array of inputs
    1+ bytes     |  tx_out count     | varint
    9+ bytes     |  tx_out[]         | Array of outputs
    variable     |  tx_witnesses[]   | Array of witness data, one per input
    4 bytes      |  lock_time        | uint32_t
    
    Args:
        inputs: List of serialized transaction inputs (41+ bytes each)
        outputs: List of serialized transaction outputs (9+ bytes each)
        witnesses: List of witness data, must match inputs length
        
    Returns:
        Hex-encoded transaction string suitable for broadcast
        
    Raises:
        ValueError: If inputs/outputs are empty or witness count doesn't match inputs
    """
    # Input validation
    if not inputs:
        raise ValueError("Transaction must have at least one input (tx_in count never zero)")
    if not outputs:
        raise ValueError("Transaction must have at least one output")
    if len(witnesses) != len(inputs):
        raise ValueError("Number of witnesses must match number of inputs")
        
    # Initialize transaction buffer
    tx = bytearray()
    
    # 4 bytes: version (always 2 for SegWit)
    tx.extend((2).to_bytes(4, byteorder='little', signed=False))
    
    # 2 bytes: witness flag (0001)
    tx.extend(bytes.fromhex("0001"))
    
    # 1+ bytes: input count as varint
    tx.extend(encode_varint(len(inputs)))
    
    # 41+ bytes per input: input list
    for input_data in inputs:
        tx.extend(input_data)
    
    # 1+ bytes: output count as varint
    tx.extend(encode_varint(len(outputs)))
    
    # 9+ bytes per output: output list
    for output_data in outputs:
        tx.extend(output_data)
    
    # Variable size: witness data (one per input)
    for witness_data in witnesses:
        tx.extend(witness_data)
    
    # 4 bytes: lock_time (0 = not locked)
    tx.extend((0).to_bytes(4, byteorder='little', signed=False))
    
    # Convert to hex string
    return tx.hex()


# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    """
    Calculate transaction ID (double SHA256 hash) of non-witness transaction data.
    Returns reversed hex string as per Bitcoin convention.
    
    Args:
        inputs: List of serialized transaction inputs
        outputs: List of serialized transaction outputs
        
    Returns:
        32-byte txid as reversed hex string
    """
    # Build transaction without witness data
    tx = bytearray()
    
    # Version (4 bytes, little-endian)
    tx.extend((2).to_bytes(4, "little"))
    
    # Input count (varint)
    tx.extend(encode_varint(len(inputs)))
    
    # Inputs
    for input_data in inputs:
        tx.extend(input_data)
    
    # Output count (varint)
    tx.extend(encode_varint(len(outputs)))
    
    # Outputs
    for output_data in outputs:
        tx.extend(output_data)
    
    # Locktime (4 bytes)
    tx.extend(bytes.fromhex("00000000"))
    
    # Double SHA256
    first_hash = hashlib.sha256(tx).digest()
    final_hash = hashlib.sha256(first_hash).digest()
    
    # Convert to hex and reverse bytes
    return final_hash[::-1].hex()


def spend_p2wpkh(state: WalletState) -> str:
    FEE = BitcoinAmount(1000)  # 1000 satoshis
    AMT = BitcoinAmount(1000000)  # 0.01 BTC in satoshis
    
    selected_utxo = None
    for utxo in state.utxos:
        if enough_amount_for_transaction(utxo=utxo, transaction_amount=AMT, fee=FEE):
            selected_utxo = utxo
            break
    if not selected_utxo:
        raise ValueError("No UTXO found with sufficient value")

    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian
    txid_bytes = bytes.fromhex(selected_utxo['txid'])
    input_bytes = input_from_utxo(txid_bytes, selected_utxo['vout'])

    # Compute destination output script and output
    # Get public keys for 2-of-2 multisig
    pubkey1 = get_pub_from_priv(bytes.fromhex(state.privs[0]))
    pubkey2 = get_pub_from_priv(bytes.fromhex(state.privs[1]))
    multisig_script = create_multisig_script([pubkey1, pubkey2])
    witness_program = get_p2wsh_program(multisig_script)
    output1_bytes = output_from_options(witness_program, AMT.satoshis)

    # Compute change output script and output
    change_program = get_p2wpkh_program(get_pub_from_priv(bytes.fromhex(state.privs[0])))
    utxo_amount = BitcoinAmount(selected_utxo['amount']['satoshis'])
    change_amount = utxo_amount.satoshis - AMT.satoshis - FEE.satoshis
    output2_bytes = output_from_options(change_program, change_amount)

    # Get the message to sign
    scriptcode = get_p2wpkh_scriptcode(selected_utxo)
    msg = get_commitment_hash(
        input_bytes[:36],  # just the outpoint part
        scriptcode,
        selected_utxo['amount']['satoshis'],
        [output1_bytes, output2_bytes]
    )

    # Fetch the private key we need to sign with
    key_index = get_key_index(selected_utxo, state.programs)
    priv = state.privs[key_index]

    # Sign!
    witness = get_p2wpkh_witness(bytes.fromhex(priv), msg)

    # Assemble
    final_tx = assemble_transaction(
        [input_bytes],
        [output1_bytes, output2_bytes],
        [witness]
    )

    # Reserialize without witness data and double-SHA256 to get the txid
    txid = get_txid([input_bytes], [output1_bytes, output2_bytes])

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    
    return final_tx, txid



# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(state: object, txid: str) -> str:
    COIN_VALUE = 1000000
    FEE = 1000
    AMT = 0
    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian

    # Compute destination output script and output

    # Compute change output script and output

    # Get the message to sign

    # Sign!

    # Assemble

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    return "finalhex"


if __name__ == "__main__":
    # Recover wallet state: We will need all key pairs and unspent coins
    recovered_wallet_state = WalletState.load_state(f"{CURRENT_DIR}/wallet_state.json")
    
    tx_hex, txid = spend_p2wpkh(recovered_wallet_state)

    print(f"Transaction hex: {tx_hex}")
    print(f"Transaction ID: {txid}")