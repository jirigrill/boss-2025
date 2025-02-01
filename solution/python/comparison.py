from typing import List, Type, Optional
from solution.python.transaction import MempoolTransaction
from solution.python.strategies.base import BlockBuilderStrategy
from solution.python.strategies.greedy import GreedyBlockBuilder
from solution.python.strategies.dynamic import DynamicBlockBuilder
from solution.python.strategies.weighted_random import WeightedRandomBlockBuilder
from solution.python.strategies.hybrid import HybridBlockBuilder

class BlockBuilderComparison:
    """
    Compares different block building strategies.
    """
    DEFAULT_STRATEGIES = [
        GreedyBlockBuilder,
        DynamicBlockBuilder,
        WeightedRandomBlockBuilder,
        HybridBlockBuilder
    ]

    def __init__(
        self, 
        transactions: List[MempoolTransaction],
        strategies: Optional[List[Type[BlockBuilderStrategy]]] = None
    ):
        """
        Initialize comparison with transactions and optional strategies.
        """
        self.transactions = transactions
        self.strategies = strategies or self.DEFAULT_STRATEGIES

    def compare_strategies(self) -> dict:
        """
        Compares block building strategies.
        """
        return {
            self._get_strategy_name(strategy): self._evaluate_strategy(strategy)
            for strategy in self.strategies
        }

    def _get_strategy_name(self, strategy_class: Type[BlockBuilderStrategy]) -> str:
        """
        Generate a consistent strategy name.
        """
        name = strategy_class.__name__.lower()
        if name.endswith('blockbuilder'):
            name = name.replace('blockbuilder', '')
        return name

    def _evaluate_strategy(self, strategy_class):
        """
        Evaluates a single block building strategy.
        """
        builder = strategy_class(self.transactions)
        block = builder.construct_block()
        
        return {
            'block': block,
            'stats': self._calculate_stats(block)
        }

    def _calculate_stats(self, block: List[MempoolTransaction]) -> dict:
        """
        Calculates comprehensive statistics for a block solution.
        """
        total_fee = sum(tx.fee for tx in block)
        total_weight = sum(tx.weight for tx in block)
        return {
            'total_transactions': len(block),
            'total_fee': total_fee,
            'total_weight': total_weight,
            'fee_rate': total_fee / total_weight if total_weight > 0 else 0
        }