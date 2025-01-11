# Which tx in block 257,343 spends the coinbase output of block 256,128?

ORIGIN_BLOCK="256128"
SPEND_BLOCK="257343"

COIN_TX=$(bitcoin-cli getblock $(bitcoin-cli getblockhash $ORIGIN_BLOCK) | jq -r '.tx[0]')
COIN_ADDRESS=$(bitcoin-cli decoderawtransaction $(bitcoin-cli getrawtransaction $COIN_TX) | jq -r '.vout[0].scriptPubKey.address')

SPENDING_TX=""
for txid in $(bitcoin-cli getblock $(bitcoin-cli getblockhash $SPEND_BLOCK) | jq -r '.tx[]'); do
    [ ! -z "$SPENDING_TX" ] && break
    
    RAW_TX=$(bitcoin-cli getrawtransaction $txid)
    
    bitcoin-cli decoderawtransaction $RAW_TX | jq -r '.vin[] | select(.txid != null) | .txid + " " + (.vout | tostring)' | while read prev_txid prev_vout; do
        PREV_TX=$(bitcoin-cli getrawtransaction $prev_txid)
        PREV_ADDRESS=$(bitcoin-cli decoderawtransaction $PREV_TX | jq -r ".vout[$prev_vout].scriptPubKey.address")
        
        if [ "$PREV_ADDRESS" = "$COIN_ADDRESS" ]; then
            SPENDING_TX=$txid
            echo $txid
            break
        fi
    done
done