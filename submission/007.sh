# Only one single output remains unspent from block 123,321. What address was it sent to?
BLOCK="123321"

BLOCK_TXS=($(bitcoin-cli getblock $(bitcoin-cli getblockhash $BLOCK) | jq -r '.tx[]'))

for txid in "${BLOCK_TXS[@]}"; do
    TX_INFO=$(bitcoin-cli getrawtransaction $txid 1)
    # Get number of outputs (vouts)
    NUM_VOUTS=$(echo $TX_INFO | jq '.vout | length')

    for vout in $(seq 0 $(($NUM_VOUTS - 1))); do
        ADDRESS=$(echo $TX_INFO | jq -r ".vout[$vout].scriptPubKey.address")
        if [ ! -z "$(bitcoin-cli gettxout $txid $vout)" ]; then
            echo $ADDRESS
        fi
    done
done

