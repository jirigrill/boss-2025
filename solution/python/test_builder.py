import pytest
import os
from solution.python.builder import parse_mempool_csv
from solution.python.strategies.greedy import GreedyBlockBuilder
from solution.python.strategies.dynamic import DynamicBlockBuilder
from solution.python.strategies.hybrid import HybridBlockBuilder
from solution.python.strategies.weighted_random import WeightedRandomBlockBuilder

@pytest.fixture
def transactions():
   """Fixture to load transactions from mempool."""
   base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
   csv_path = os.path.join(os.path.dirname(base_dir), 'mempool.csv')
   return parse_mempool_csv(csv_path)

@pytest.mark.parametrize("strategy_class", [
    GreedyBlockBuilder,
    DynamicBlockBuilder,
    HybridBlockBuilder,
    WeightedRandomBlockBuilder
])
def test_block_construction(transactions, strategy_class):
    """
    Validate block construction rules for each strategy.
    
    Checks:
    1. Total block weight ≤ 4,000,000
    2. No duplicate transactions
    3. Ancestors appear before descendants
    """
    # Construct block
    builder = strategy_class(transactions)
    block = builder.construct_block()
    block_txids = [tx.txid for tx in block]

    # Weight constraint
    total_weight = sum(tx.weight for tx in block)
    assert total_weight <= 4_000_000, \
        f"{strategy_class.__name__}: Block weight exceeds limit"

    # Unique transactions
    assert len(block_txids) == len(set(block_txids)), \
        f"{strategy_class.__name__}: Duplicate transactions found"

    # Ancestor ordering
    for tx in block:
        if tx.parents:
            tx_index = block_txids.index(tx.txid)
            for parent_id in tx.parents:
                parent_index = block_txids.index(parent_id)
                assert parent_index < tx_index, \
                    f"{strategy_class.__name__}: Parent after child"