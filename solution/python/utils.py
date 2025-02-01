import os
from typing import List
from solution.python.transaction import MempoolTransaction

def parse_mempool_csv(file_path: str = 'mempool.csv') -> List[MempoolTransaction]:
    """
    Parses a CSV file containing mempool transactions.
    Returns a list of MempoolTransaction objects.
    """
    with open(file_path) as f:
        return [MempoolTransaction(*line.strip().split(',')) 
                for line in f.readlines() if line.strip()]

def write_block_to_file(block: List[MempoolTransaction], file_name: str = 'block.txt') -> None:
    """
    Writes block transactions to a file, one transaction ID per line.
    """
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(script_dir, file_name)
    with open(output_path, 'w') as f:
        for tx in block:
            f.write(f"{tx.txid}\n")