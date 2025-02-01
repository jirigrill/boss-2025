from typing import List
import sys
from solution.python.transaction import MempoolTransaction
from solution.python.utils import parse_mempool_csv, write_block_to_file
from solution.python.comparison import BlockBuilderComparison

class BlockBuilder:
    """
    Compares and selects the optimal block building strategy.
    """
    def __init__(self, transactions: List[MempoolTransaction]):
        self.comparison = BlockBuilderComparison(transactions)

    def construct_block(self) -> List[MempoolTransaction]:
        """
        Compares strategies and selects the best block.
        """
        # Compare all strategies
        comparison_results = self.comparison.compare_strategies()
        
        # Select the strategy with the highest total fee
        best_strategy = max(
            comparison_results.items(), 
            key=lambda x: x[1]['stats']['total_fee']
        )[0]

        print(f"Selected strategy: {best_strategy}")
        
        # Log detailed comparison
        self._log_strategy_comparison(comparison_results)
        
        return comparison_results[best_strategy]['block']

    def _log_strategy_comparison(self, results: dict) -> None:
        """
        Logs detailed comparison of all strategies.
        """
        print("\nStrategy Comparison:")
        for strategy, data in results.items():
            stats = data['stats']
            print(f"{strategy.capitalize()} Strategy:")
            print(f"  Transactions: {stats['total_transactions']}")
            print(f"  Total Fee: {stats['total_fee']:,} satoshis")
            print(f"  Total Weight: {stats['total_weight']:,}")
            print(f"  Fee Rate: {stats['fee_rate']:.4f}")

def main():
    try:
        transactions = parse_mempool_csv('../mempool.csv')
        builder = BlockBuilder(transactions)
        block = builder.construct_block()
        write_block_to_file(block)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()