def bytes_to_hex(bytes_str: bytes) -> str:
     """Convert bytes to hexadecimal string."""
     return bytes_str.hex()

def validate_bytes_length(data: bytes, expected_length: int, name: str) -> None:
    """Validate length of bytes data."""
    if len(data) != expected_length:
        raise ValueError(f"Invalid {name} length: {len(data)} (should be {expected_length})")
