# Which tx in block 257,343 spends the coinbase output of block 256,128?

# ORIGIN_BLOCK="256128"
# SPEND_BLOCK="257343"

# COIN_TX=$(bitcoin-cli getblock $(bitcoin-cli getblockhash $ORIGIN_BLOCK) | jq -r '.tx[0]')
# COIN_ADDRESS=$(bitcoin-cli decoderawtransaction $(bitcoin-cli getrawtransaction $COIN_TX) | jq -r '.vout[0].scriptPubKey.address')

# SPENDING_TX=""
# for txid in $(bitcoin-cli getblock $(bitcoin-cli getblockhash $SPEND_BLOCK) | jq -r '.tx[]'); do
#     [ ! -z "$SPENDING_TX" ] && break
    
#     RAW_TX=$(bitcoin-cli getrawtransaction $txid)
    
#     bitcoin-cli decoderawtransaction $RAW_TX | jq -r '.vin[] | select(.txid != null) | .txid + " " + (.vout | tostring)' | while read prev_txid prev_vout; do
#         PREV_TX=$(bitcoin-cli getrawtransaction $prev_txid)
#         PREV_ADDRESS=$(bitcoin-cli decoderawtransaction $PREV_TX | jq -r ".vout[$prev_vout].scriptPubKey.address")
        
#         if [ "$PREV_ADDRESS" = "$COIN_ADDRESS" ]; then
#             SPENDING_TX=$txid
#             echo $txid
#             break
#         fi
#     done
# done


ORIGIN_BLOCK="256128"
SPEND_BLOCK="257343"

# Get coinbase transaction and address with minimal calls
COIN_TX_DATA=$(bitcoin-cli getblock $(bitcoin-cli getblockhash $ORIGIN_BLOCK) true)
COIN_TX=$(echo "$COIN_TX_DATA" | jq -r '.tx[0]')
COIN_ADDRESS=$(bitcoin-cli getrawtransaction $COIN_TX 1 | jq -r '.vout[0].scriptPubKey.address')

# Get all spend block transactions in one call
SPEND_BLOCK_DATA=$(bitcoin-cli getblock $(bitcoin-cli getblockhash $SPEND_BLOCK) true)

# More efficient loop using direct jq parsing
SPENDING_TX=""
for txid in $(echo "$SPEND_BLOCK_DATA" | jq -r '.tx[]'); do
    [ ! -z "$SPENDING_TX" ] && break
    
    # Get full decoded transaction in one call
    TX_DATA=$(bitcoin-cli getrawtransaction $txid 1)
    
    # Use single jq query to check inputs
    if echo "$TX_DATA" | jq -r --arg addr "$COIN_ADDRESS" '
        .vin[] | 
        select(.txid != null) | 
        . as $in | 
        $in.txid as $tid | 
        $in.vout as $vout |
        ($tid + " " + ($vout | tostring))
    ' | while read prev_txid prev_vout; do
        PREV_ADDRESS=$(bitcoin-cli getrawtransaction $prev_txid 1 | jq -r ".vout[$prev_vout].scriptPubKey.address")
        
        if [ "$PREV_ADDRESS" = "$COIN_ADDRESS" ]; then
            echo "found"
            break
        fi
    done | grep -q "found"; then
        SPENDING_TX=$txid
        break
    fi
done

echo $SPENDING_TX