from typing import List, Set
from solution.python.strategies.base import BlockBuilderStrategy
from solution.python.analyzer import TransactionAnalyzer
from solution.python.transaction import MempoolTransaction

class GreedyBlockBuilder(BlockBuilderStrategy):
    """
    A greedy approach to block construction that prioritizes transactions
    with the highest fee rate while maintaining all required constraints.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        super().__init__(transactions)
        self.analyzer = TransactionAnalyzer(transactions)

    def construct_block(self) -> List[MempoolTransaction]:
        """
        Constructs a block using a greedy strategy that selects transactions
        with the highest fee rate while respecting dependencies.
        """
        selected_txs: Set[str] = set()
        block: List[MempoolTransaction] = []
        remaining_weight = self.MAX_BLOCK_WEIGHT

        sorted_txs = sorted(
            self.transactions,
            key=lambda tx: self.analyzer.get_ancestor_metrics(tx.txid)['fee_rate'],
            reverse=True
        )

        for tx in sorted_txs:
            if tx.txid not in selected_txs:
                ancestors = self.analyzer.ancestors[tx.txid]
                needed_weight = tx.weight + sum(
                    self.analyzer.tx_map[aid].weight 
                    for aid in ancestors - selected_txs
                )
                
                if needed_weight <= remaining_weight:
                    # Add ancestors first - ensure topological order
                    ancestor_list = sorted(
                        list(ancestors - selected_txs),
                        key=lambda aid: len(self.analyzer.ancestors[aid])
                    )
                    for aid in ancestor_list:
                        ancestor = self.analyzer.tx_map[aid]
                        block.append(ancestor)
                        selected_txs.add(aid)
                        remaining_weight -= ancestor.weight
                    
                    # Add transaction after all ancestors
                    block.append(tx)
                    selected_txs.add(tx.txid)
                    remaining_weight -= tx.weight

        return block