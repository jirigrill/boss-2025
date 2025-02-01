from typing import List, Set, Dict, Tuple
from solution.python.strategies.base import BlockBuilderStrategy
from solution.python.analyzer import TransactionAnalyzer
from solution.python.transaction import MempoolTransaction

class DynamicBlockBuilder(BlockBuilderStrategy):
    """
    Advanced block building strategy with complex optimization.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        super().__init__(transactions)
        self.analyzer = TransactionAnalyzer(transactions)
        self.tx_map = {tx.txid: tx for tx in transactions}

    def construct_block(self) -> List[MempoolTransaction]:
        """
        Constructs an optimized block using multi-stage selection.
        """
        # Precompute transaction clusters and dependencies
        tx_clusters = self._create_transaction_clusters()
        block: List[MempoolTransaction] = []
        selected_txids = set()
        remaining_weight = self.MAX_BLOCK_WEIGHT

        sorted_clusters = sorted(
            tx_clusters,
            key=lambda cluster: sum(
                self._calculate_cluster_efficiency(txid) 
                for txid in cluster
            ),
            reverse=True
        )

        for cluster in sorted_clusters:
            cluster_txs = sorted(
                cluster,
                key=lambda txid: self._calculate_cluster_efficiency(txid),
                reverse=True
            )

            for txid in cluster_txs:
                if txid in selected_txids:
                    continue

                ancestors = sorted(
                    [self.tx_map[aid] for aid in self.analyzer.ancestors[txid]
                        if aid not in selected_txids],
                    key=lambda tx: len(self.analyzer.ancestors[tx.txid])
                )

                total_weight = sum(ancestor.weight for ancestor in ancestors) + self.tx_map[txid].weight

                if total_weight <= remaining_weight:
                    for ancestor in ancestors:
                        block.append(ancestor)
                        selected_txids.add(ancestor.txid)
                        remaining_weight -= ancestor.weight

                    tx = self.tx_map[txid]
                    block.append(tx)
                    selected_txids.add(txid)
                    remaining_weight -= tx.weight

        return block

    def _create_transaction_clusters(self) -> List[Set[str]]:
        """
        Creates transaction clusters based on dependency relationships.
        """
        clusters = []
        processed_txids = set()

        for tx in sorted(
            self.transactions, 
            key=lambda tx: self._calculate_cluster_efficiency(tx.txid), 
            reverse=True
        ):
            if tx.txid in processed_txids:
                continue

            cluster = set()
            ancestors = sorted(
                self.analyzer.ancestors[tx.txid],
                key=lambda aid: len(self.analyzer.ancestors[aid])
            )
            cluster.update(ancestors)
            cluster.add(tx.txid)
            
            for potential_child_id, potential_child_tx in self.tx_map.items():
                if any(parent in cluster for parent in potential_child_tx.parents):
                    cluster.add(potential_child_id)

            clusters.append(cluster)
            processed_txids.update(cluster)

        return clusters


    def _calculate_cluster_efficiency(self, txid: str) -> float:
        """
        Calculate an efficiency score for a transaction.
        """
        metrics = self.analyzer.get_ancestor_metrics(txid)
        tx = self.tx_map[txid]
        
        return (
            metrics['fee_rate'] * 
            (1 + 0.05 * bool(self.analyzer.ancestors[txid])) *
            (tx.fee / max(tx.weight, 1))
        )