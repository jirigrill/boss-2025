from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, asdict
import json
from subprocess import run
from wallet_dataclasses import UTXO, BitcoinAmount

def validate_bytes_length(data: bytes, expected_length: int, name: str) -> None:
    """Validate length of bytes data."""
    if len(data) != expected_length:
        raise ValueError(f"Invalid {name} length: {len(data)} (should be {expected_length})")
    
def pretty_dict(data: dict | list) -> str:
    """Convert a dictionary or list into a pretty-formatted string."""
    return json.dumps(data, indent=4, default=str)

def to_satoshis(amount_btc: float) -> int:
    return int(amount_btc * 100_000_000)

def enough_amount_for_transaction(utxo: UTXO, transaction_amount: BitcoinAmount, fee: BitcoinAmount) -> bool:
    """
    Check if UTXO has enough amount for given transaction_amount and fee
    
    Args:
        utxo: UTXO to check
        transaction_amount: Amount to send
        fee: Transaction fee
    """
    return int(utxo['amount']['satoshis']) >= transaction_amount.satoshis + fee.satoshis


def is_utxo_unspent(txid: str, vout: int) -> bool:
    try:
        # gettxout returns None (empty string in our case) if the output is spent
        result = bcli(f"gettxout {txid} {vout}")
        return bool(result.strip())
    except Exception as e:
        # Log the error if needed
        return False
    

def serialize(*args) -> bytes | str:
    """Adds all arguments together if they are of the same types"""
    if not args:
        raise TypeError("At least one argument must be provided")
    
    # Get the type of the first argument
    expected_type = type(args[0])
    
    # Check if all arguments are of the same type
    if not all(isinstance(arg, expected_type) for arg in args):
        raise TypeError(f"All arguments must be of type {expected_type.__name__}")
    
    # Add all arguments
    result = args[0]
    for arg in args[1:]:
        result += arg
    
    return result


@dataclass
class DerivationComponents:
    key: str
    path: str
    checksum: str

    def parse_path(self) -> List[Tuple[int, bool]]:
        """
        Convert path string into list of (number, is_hardened) tuples.
        Example: "/84h/1h/0h/0/*" -> [(84, True), (1, True), (0, True), (0, False)]
        The wildcard '*' is skipped in the output.
        """
        # Remove leading slash and split by '/'
        components = self.path.strip('/').split('/')
        
        result = []
        for component in components:
            # Skip wildcard
            if '*' in component:
                continue
                
            # Check if hardened (ends with 'h')
            is_hardened = component.endswith('h')
            
            # Remove 'h' suffix if present and convert to int
            number = int(component[:-1] if is_hardened else component)
            
            result.append((number, is_hardened))
            
        return result

def split_derivation_string(input_str: str) -> Optional[DerivationComponents]:
    """Split a derivation string into its components."""
    try:
        # Verify the string starts with "wpkh("
        if not input_str.startswith("wpkh("):
            return None
            
        # Find the indices of the key-path separator and checksum
        path_start = input_str.find('/')
        checksum_start = input_str.find('#')
        

        if path_start == -1 or checksum_start == -1:
            return None
            
        # Extract the components
        key = input_str[5:path_start]
        path = input_str[path_start:checksum_start]
        checksum = input_str[checksum_start:]
        
        return DerivationComponents(key=key, path=path, checksum=checksum)
        
    except Exception:
        return None
    

# Assuming Bitcoin Core is running and connected to signet using default datadir,
# execute an RPC and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# Examples: bcli("getblockcount")
#           bcli("getblockhash 100")
def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())


def decode_script(hex_script: str) -> dict:
    """Decode a script using Bitcoin Core's decodescript RPC."""
    try:
        decoded = json.loads(bcli(f"decodescript {hex_script}"))
        return decoded
    except Exception as e:
        return {"error": str(e)}
    

def get_script_to_info(programs: list, pubs: list, privs: list) -> dict[str, Any]:
    """Map scripts to their info"""
    script_to_info = {}
    for i, program in enumerate(programs):
        hex_script = program.hex()
        script_info = json.loads(bcli(f"decodescript {hex_script}"))
        script_to_info[hex_script] = {
            "address": script_info["address"],
            "pub": pubs[i].hex(),
            "priv": privs[i].hex()
        }
    return script_to_info