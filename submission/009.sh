# How many satoshis did this transaction pay for fee?:
#  `c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42`

TRANSACTION="c346d9277128f5d67740f8847f11aff5cef440b6d102fcd5ddcdb40d9a12df42"

TRANSACTION_DETAIL=$(bitcoin-cli getrawtransaction "$TRANSACTION" true)
INPUTS=$(echo "$TRANSACTION_DETAIL" | jq -r '.vin')
ALL_INPUT_VALUES=$(echo "$INPUTS" | jq -r '.[] | "\(.txid) \(.vout)"' | while read -r txid vout; do
    bitcoin-cli getrawtransaction "$txid" true | jq -r ".vout[$vout].value * 100000000"
done)
echo "$TRANSACTION_DETAIL" | jq --arg sum "$(echo "$ALL_INPUT_VALUES" | paste -sd+ - | bc)" \
    '([.vout[].value * 100000000] | add | floor) as $output_sats | 
    ($sum | tonumber) - $output_sats' -r