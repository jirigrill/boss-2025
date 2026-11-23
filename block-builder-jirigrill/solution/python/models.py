from dataclasses import dataclass
from typing import List
from solution.python.transaction import MempoolTransaction

@dataclass
class BlockSolution:
    """
    Represents a potential block solution with its metrics.
    This immutable data class helps track different possible block configurations
    during the optimization process.
    """
    transactions: List[MempoolTransaction]
    total_fee: int
    total_weight: int