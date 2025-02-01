from typing import List, Set, Dict
from solution.python.strategies.base import BlockBuilderStrategy
from solution.python.analyzer import TransactionAnalyzer
from solution.python.transaction import MempoolTransaction

class HybridBlockBuilder(BlockBuilderStrategy):
    """
    Block building strategy combining multiple optimization techniques.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        super().__init__(transactions)
        self.analyzer = TransactionAnalyzer(transactions)
        self.tx_map = {tx.txid: tx for tx in transactions}

    def construct_block(self) -> List[MempoolTransaction]:
        """
        Constructs an optimized block using hybrid selection strategy.
        """
        block: List[MempoolTransaction] = []
        remaining_weight = self.MAX_BLOCK_WEIGHT
        selected_txids = set()

        # Compute transaction priorities with advanced scoring
        tx_priorities = {
            tx.txid: self._calculate_transaction_priority(tx)
            for tx in self.transactions
        }

        # First pass: high-priority transactions with complex dependencies
        sorted_txs = sorted(
            self.transactions,
            key=lambda tx: tx_priorities[tx.txid],
            reverse=True
        )

        for tx in sorted_txs:
            if tx.txid in selected_txids:
                continue

            # Identify ancestors
            ancestors = sorted(
                [self.tx_map[aid] for aid in self.analyzer.ancestors[tx.txid]
                if aid not in selected_txids],
                key=lambda tx: len(self.analyzer.ancestors[tx.txid])
            )

            # Calculate total weight
            total_ancestor_weight = sum(ancestor.weight for ancestor in ancestors)
            total_weight = total_ancestor_weight + tx.weight

            # Add if weight permits
            if total_weight <= remaining_weight:
                # Add ancestors
                for ancestor in ancestors:
                    block.append(ancestor)
                    selected_txids.add(ancestor.txid)
                    remaining_weight -= ancestor.weight

                # Add main transaction
                block.append(tx)
                selected_txids.add(tx.txid)
                remaining_weight -= tx.weight

        # Second pass: fill remaining space
        remaining_txs = [
            tx for tx in self.transactions 
            if tx.txid not in selected_txids
        ]

        # Sort remaining by direct efficiency
        sorted_remaining = sorted(
            remaining_txs,
            key=lambda tx: tx.fee / max(tx.weight, 1),
            reverse=True
        )

        for tx in sorted_remaining:
            if tx.weight <= remaining_weight:
                block.append(tx)
                remaining_weight -= tx.weight

        return block

    def _calculate_transaction_priority(self, tx: MempoolTransaction) -> float:
        """
        Compute a comprehensive priority score for transaction selection.
        """
        metrics = self.analyzer.get_ancestor_metrics(tx.txid)
        
        return (
            metrics['fee_rate'] *  # Base fee rate
            (1 - 0.05 * len(self.analyzer.ancestors[tx.txid])) *  # Dependency penalty
            (tx.fee / max(tx.weight, 1)) *  # Direct efficiency
            (1 + 0.1 * (len(self.analyzer.ancestors[tx.txid]) > 0))  # Dependency bonus
        )