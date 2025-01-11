# How many satoshis did this transaction pay for fee?:
#  `c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42`

TRANSACTION="c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42"

TRANSACTION_DETAIL=$(bitcoin-cli getrawtransaction "$TRANSACTION" true)
INPUTS=$(echo "$TRANSACTION_DETAIL" | jq -r '.vin')
OUTPUTS=$(echo "$TRANSACTION_DETAIL" | jq -r '.vout')

ALL_INPUT_VALUES=$(echo "$INPUTS" | jq -c '.[]' | while read -r input; do
    PREV_TXID=$(echo "$input" | jq -r '.txid')
    PREV_VOUT=$(echo "$input" | jq -r '.vout')
    PREV_VALUE=$(bitcoin-cli getrawtransaction "$PREV_TXID" true | jq -r ".vout[$PREV_VOUT].value")
    echo $PREV_VALUE
done)

TOTAL_INPUT=$(echo "$ALL_INPUT_VALUES" | paste -sd+ - | bc)

ALL_OUTPUT_VALUES=$(echo "$OUTPUTS" | jq -c '.[].value')
TOTAL_OUTPUT=$(echo "$ALL_OUTPUT_VALUES" | paste -sd+ - | bc)
FEE=$(echo "$TOTAL_INPUT - $TOTAL_OUTPUT" | bc)

# Convert to satoshis and show only whole number
FEE_SATS=$(echo "$FEE * 100000000" | bc | cut -d. -f1)
echo $FEE_SATS