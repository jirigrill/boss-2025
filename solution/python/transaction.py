from typing import List, Optional

class MempoolTransaction:
    """
    Represents a single transaction in the mempool.
    Each transaction has a unique ID, fee, weight, and optional parent transactions.
    """
    def __init__(self, txid: str, fee: str, weight: str, parents: Optional[str] = None):
        self.txid = txid
        self.fee = int(fee)
        self.weight = int(weight)
        self.parents = parents.split(';') if parents and parents.strip() else []
        
    def __repr__(self) -> str:
        return (f"MempoolTransaction(txid={self.txid}, fee={self.fee}, "
                f"weight={self.weight}, parents={self.parents})")