from typing import Any, Union, Optional, Dict
from dataclasses import dataclass, field, asdict
from pathlib import Path
import json
from decimal import Decimal

# Get directory where current file is located
CURRENT_DIR = Path(__file__).parent

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

@dataclass
class BitcoinAmount:
    """Represents a Bitcoin amount with proper satoshi handling"""
    satoshis: int
    
    @classmethod
    def from_btc(cls, btc: Union[Decimal, float, str]) -> 'BitcoinAmount':
        """Convert BTC amount to BitcoinAmount instance."""
        # Convert input to Decimal for precise calculation
        if isinstance(btc, (float, str)):
            btc_decimal = Decimal(str(btc))  # Convert through string to avoid float precision issues
        else:
            btc_decimal = btc
            
        satoshis = int(btc_decimal * Decimal('100000000'))
        return cls(satoshis)
    
    def to_btc(self) -> Decimal:
        """Convert satoshis to BTC with proper decimal precision"""
        return Decimal(self.satoshis) / Decimal('100000000')
    
    def __add__(self, other: 'BitcoinAmount') -> 'BitcoinAmount':
        return BitcoinAmount(self.satoshis + other.satoshis)
    
    def __sub__(self, other: 'BitcoinAmount') -> 'BitcoinAmount':
        return BitcoinAmount(self.satoshis - other.satoshis)
    
    def __lt__(self, other: 'BitcoinAmount') -> bool:
        return self.satoshis < other.satoshis


@dataclass
class Transaction:
    """Represents a wallet transaction"""
    type: str  # 'receive' or 'spend'
    block: int
    txid: str
    amount: BitcoinAmount
    address: str


@dataclass
class UTXO:
    """Represents an Unspent Transaction Output"""
    txid: str
    vout: int
    amount: BitcoinAmount
    script: str
    address: str
    private_key: str
    public_key: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UTXO':
        """Create UTXO from dictionary data"""
        return cls(
            txid=data['txid'],
            vout=data['vout']['n'],
            amount=BitcoinAmount.from_btc(float(data['amount'])),
            script=data['script'],
            address=data['address'],
            private_key=data['priv'],
            public_key=data['pub']
        )


@dataclass
class WalletState:
    privs: list[str]
    programs: set[str]
    balance: BitcoinAmount = field(default_factory=lambda: BitcoinAmount(0))
    utxos: list[UTXO] = field(default_factory=list)
    transactions: list[Transaction] = field(default_factory=list)

    def _convert_bytes_to_hex(self, obj):
        """Helper method to convert bytes objects to hex strings"""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {key: self._convert_bytes_to_hex(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_bytes_to_hex(item) for item in obj]
        elif isinstance(obj, set):
            return sorted(self._convert_bytes_to_hex(item) for item in obj)
        return obj
    

    def save_state(self, filename: str | Path) -> None:
        """Save the wallet state to a JSON file."""
        state_dict = asdict(self)
        serializable_dict = self._convert_bytes_to_hex(state_dict)
        filepath = CURRENT_DIR / filename
        
        # Create parent directories if they don't exist
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with filepath.open('w') as f:
            json.dump(serializable_dict, f, indent=4)
    
    @classmethod
    def load_state(cls, filepath: str | Path) -> 'WalletState':
        """Loads the wallet state from a JSON file."""
        path = Path(filepath)
        
        with path.open('r') as f:
            state_dict = json.load(f)
            
        return cls(**state_dict)
