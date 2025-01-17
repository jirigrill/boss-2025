from typing import Any, Union, Optional, Dict
from dataclasses import dataclass
from utils import bytes_to_hex

@dataclass
class DeserializedKey:
    version: bytes
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chaincode: bytes
    key: bytes
    key_type: str
    network: str

    def to_hex(self, field: Optional[str] = None) -> Union[str, Dict[str, str]]:
        """Convert a specific field or all byte fields to hex."""
        if field is not None:
            value = getattr(self, field)
            if isinstance(value, bytes):
                return bytes_to_hex(value)
            raise ValueError(f"Field '{field}' is not bytes type")

        return {
            'version': bytes_to_hex(self.version),
            'depth': self.depth,  # Not bytes
            'parent_fingerprint': bytes_to_hex(self.parent_fingerprint),
            'child_number': self.child_number,  # Not bytes
            'chaincode': bytes_to_hex(self.chaincode),
            'key': bytes_to_hex(self.key),
            'key_type': self.key_type,  # Not bytes
            'network': self.network,  # Not bytes
        }


@dataclass
class DerivedKey:
    key: bytes
    chaincode: bytes

    def to_hex(self, field: Optional[str] = None) -> Union[str, Dict[str, str]]:
        """Convert a specific field or all byte fields to hex."""
        if field is not None:
            value = getattr(self, field)
            if isinstance(value, bytes):
                return bytes_to_hex(value)
            raise ValueError(f"Field '{field}' is not bytes type")

        return {
            'key': bytes_to_hex(self.key),
            'chaincode': bytes_to_hex(self.chaincode)
        }