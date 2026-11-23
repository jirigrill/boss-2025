from typing import List, Set, Dict, Optional
from solution.python.transaction import MempoolTransaction

class TransactionAnalyzer:
    """
    Analyzes relationships between transactions and computes metrics.
    This class handles the graph-like structure of transaction dependencies.
    
    The analyzer maintains a cache of computed metrics and relationships to avoid
    recalculating them for each transaction multiple times.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        # Create a map for O(1) transaction lookup
        self.tx_map = {tx.txid: tx for tx in transactions}
        # Pre-compute ancestor relationships
        self.ancestors = self._compute_all_ancestors()
        # Pre-compute all transaction metrics
        self.metrics = self._compute_transaction_metrics()

    def _compute_all_ancestors(self) -> Dict[str, Set[str]]:
        """
        Computes the complete ancestor set for each transaction.
        For each transaction, finds all its ancestors recursively.
        """
        ancestors = {}
        for txid, tx in self.tx_map.items():
            if txid not in ancestors:
                ancestors[txid] = self._get_ancestors(tx)
        return ancestors

    def _get_ancestors(self, tx: MempoolTransaction, ancestor_set: Optional[Set[str]] = None) -> Set[str]:
        """
        Recursively finds all ancestors of a transaction.
        Uses a set to track ancestors and avoid duplicate processing.
        """
        if ancestor_set is None:
            ancestor_set = set()
        
        for parent_id in tx.parents:
            if parent_id not in ancestor_set and parent_id in self.tx_map:
                ancestor_set.add(parent_id)
                self._get_ancestors(self.tx_map[parent_id], ancestor_set)
        
        return ancestor_set

    def _compute_transaction_metrics(self) -> Dict[str, Dict]:
        """
        Computes fee and weight metrics for each transaction including its ancestors.
        These metrics are used to evaluate the value of including a transaction.
        """
        metrics = {}
        for txid, tx in self.tx_map.items():
            ancestor_txs = [self.tx_map[aid] for aid in self.ancestors[txid]]
            total_fee = sum(t.fee for t in ancestor_txs) + tx.fee
            total_weight = sum(t.weight for t in ancestor_txs) + tx.weight
            
            metrics[txid] = {
                'cumulative_fee': total_fee,
                'cumulative_weight': total_weight,
                'fee_rate': total_fee / total_weight
            }
        return metrics

    def get_ancestor_metrics(self, txid: str) -> Dict:
        """Returns the cached metrics for a transaction including its ancestors."""
        return self.metrics[txid]