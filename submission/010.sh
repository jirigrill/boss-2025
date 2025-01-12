
# Only one tx in block 444,431 signals opt-in RBF. What is its txid?
BLOCK="444431"

bitcoin-cli getblock $(bitcoin-cli getblockhash $BLOCK) 2 | jq -r '.tx[] | select(.vin[].sequence < 4294967294) | .txid'