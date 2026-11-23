from typing import List, Dict
import random
from solution.python.strategies.base import BlockBuilderStrategy
from solution.python.analyzer import TransactionAnalyzer
from solution.python.transaction import MempoolTransaction

class WeightedRandomBlockBuilder(BlockBuilderStrategy):
    """
    Block building strategy using weighted random selection.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        super().__init__(transactions)
        self.analyzer = TransactionAnalyzer(transactions)
        self.tx_map = {tx.txid: tx for tx in transactions}
        random.seed(42)  # Ensure reproducibility

    def construct_block(self) -> List[MempoolTransaction]:
        """
        Constructs a block using weighted random selection.
        """
        block: List[MempoolTransaction] = []
        remaining_weight = self.MAX_BLOCK_WEIGHT
        selected_txids = set()

        # Compute transaction weights
        tx_weights = self._compute_transaction_weights()

        # Shuffle transactions to introduce randomness
        shuffled_txs = list(self.transactions)
        random.shuffle(shuffled_txs)

        for tx in shuffled_txs:
            if tx.txid in selected_txids:
                continue

            # Select ancestors
            ancestors = sorted(
                [self.tx_map[aid] for aid in self.analyzer.ancestors[tx.txid]
                if aid not in selected_txids],
                key=lambda tx: len(self.analyzer.ancestors[tx.txid])
            )

            # Calculate total weight
            total_ancestor_weight = sum(ancestor.weight for ancestor in ancestors)
            total_weight = total_ancestor_weight + tx.weight

            # Probabilistic selection based on weighted score
            if (total_weight <= remaining_weight and 
                random.random() < tx_weights[tx.txid]):
                
                # Add ancestors
                for ancestor in ancestors:
                    block.append(ancestor)
                    selected_txids.add(ancestor.txid)
                    remaining_weight -= ancestor.weight

                # Add transaction
                block.append(tx)
                selected_txids.add(tx.txid)
                remaining_weight -= tx.weight

        return block

    def _compute_transaction_weights(self) -> Dict[str, float]:
        """
        Compute selection weights for transactions.
        """
        weights = {}
        for tx in self.transactions:
            metrics = self.analyzer.get_ancestor_metrics(tx.txid)
            
            # Multi-factor weight calculation
            weight = (
                metrics['fee_rate'] *  # Fee rate consideration
                (tx.fee / max(tx.weight, 1)) *  # Direct efficiency
                (1 - 0.1 * len(self.analyzer.ancestors[tx.txid]))  # Dependency penalty
            )
            
            # Normalize weight
            weights[tx.txid] = min(max(weight, 0), 1)
        
        return weights