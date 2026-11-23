from abc import ABC, abstractmethod
from typing import List
from ..transaction import MempoolTransaction

class BlockBuilderStrategy(ABC):
    """
    Abstract base class that defines the interface for block construction strategies.
    All block building strategies must inherit from this class and implement its methods.
    """
    MAX_BLOCK_WEIGHT = 4_000_000

    def __init__(self, transactions: List[MempoolTransaction]):
        self.transactions = transactions

    @abstractmethod
    def construct_block(self) -> List[MempoolTransaction]:
        """
        Constructs a valid block from the available transactions.
        Each strategy implements this method with its own approach to optimization.
        
        Returns:
            List[MempoolTransaction]: A list of transactions forming a valid block
        """
        pass

    def get_block_metrics(self, block: List[MempoolTransaction]) -> dict:
        """
        Calculates key metrics for the constructed block.
        These metrics are used to compare different strategies.
        """
        total_fee = sum(tx.fee for tx in block)
        total_weight = sum(tx.weight for tx in block)
        return {
            'total_transactions': len(block),
            'total_fee': total_fee,
            'total_weight': total_weight,
            'fee_rate': total_fee / total_weight if total_weight > 0 else 0
        }