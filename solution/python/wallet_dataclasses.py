from typing import Any, Union, Optional, Dict
from dataclasses import dataclass

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
                return value.hex()
            raise ValueError(f"Field '{field}' is not bytes type")

        return {
            'version': self.version.hex(),
            'depth': self.depth,  # Not bytes
            'parent_fingerprint': self.parent_fingerprint.hex(),
            'child_number': self.child_number,  # Not bytes
            'chaincode': self.chaincode.hex(),
            'key': self.key.hex(),
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
                return value.hex()
            raise ValueError(f"Field '{field}' is not bytes type")

        return {
            'key': self.key.hex(),
            'chaincode': self.chaincode.hex()
        }
