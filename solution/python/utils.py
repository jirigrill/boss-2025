from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass
import json
from subprocess import run

def validate_bytes_length(data: bytes, expected_length: int, name: str) -> None:
    """Validate length of bytes data."""
    if len(data) != expected_length:
        raise ValueError(f"Invalid {name} length: {len(data)} (should be {expected_length})")

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