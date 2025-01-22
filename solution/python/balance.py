import json
from ecdsa import SECP256k1
from typing import Any, Dict, List

from wallet_dataclasses import (
    WalletState,
    UTXO,
    BitcoinAmount,
    Transaction
)
from utils import (
    split_derivation_string,
    bcli,
    get_script_to_info
)
from wallet_methods import (
    base58_decode,
    deserialize_key,
    get_wallet_privs,
    get_pub_from_priv,
    get_p2wpkh_program
)

WALLET_NAME = "wallet_109"
EXTENDED_PRIVATE_KEY = "wpkh(tprv8ZgxMBicQKsPcvvA9Y4GcwhZJAx6KCmqw4sz9PEidDEhyFNwSXkie7xSL72KaZCx2vTVsG63mGwCKQAUxm9pTS41TpWTEs7PTDBqXb8uY2L/84h/1h/0h/0/*)#vu7vzl0x"

# Recover the wallet state from the blockchain:
# - Parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance
def recover_wallet_state(tprv: str) -> WalletState:
    # Generate addresses and keys
    # Generate addresses and keys
    derivation_components = split_derivation_string(tprv)
    extended_key_bytes = base58_decode(derivation_components.key)
    deserialized = deserialize_key(extended_key_bytes)
    derivation_path = derivation_components.parse_path()

    privs = get_wallet_privs(deserialized.key, deserialized.chaincode, derivation_path)
    pubs = [get_pub_from_priv(priv) for priv in privs]
    programs = [get_p2wpkh_program(pub) for pub in pubs]

    # Create lookup sets
    our_scripts = set(p.hex() for p in programs)
    script_to_info = get_script_to_info(programs, pubs, privs)
    
    # Initialize wallet state
    wallet_state = WalletState(privs=privs, programs=our_scripts)

    # Scan blockchain
    height = 300
    for h in range(height + 1):
        block_hash = bcli(f"getblockhash {h}")
        block_data = json.loads(bcli(f"getblock {block_hash} 2"))
        
        for tx in block_data["tx"]:
            tx_id = tx["txid"]
            
            # Check outputs (receiving to our wallet)
            if "vout" in tx:
                for out in tx["vout"]:
                    if "scriptPubKey" in out and "hex" in out["scriptPubKey"]:
                        script = out["scriptPubKey"]["hex"]
                        if script in our_scripts:
                            # Convert amount to BitcoinAmount
                            amount = BitcoinAmount.from_btc(out["value"])
                            wallet_state.balance += amount
                            
                            # Create UTXO object
                            utxo = UTXO(
                                txid=tx_id,
                                vout=out["n"],
                                amount=amount,
                                script=script,
                                address=script_to_info[script]["address"],
                                private_key=script_to_info[script]["priv"],
                                public_key=script_to_info[script]["pub"]
                            )
                            wallet_state.utxos.append(utxo)
                            
                            # Record transaction
                            wallet_state.transactions.append(Transaction(
                                type="receive",
                                block=h,
                                txid=tx_id,
                                amount=amount,
                                address=script_to_info[script]["address"]
                            ))

            # Check inputs (spending from our wallet)
            if "vin" in tx:
                for inp in tx["vin"]:
                    if "txinwitness" in inp and len(inp["txinwitness"]) >= 2:
                        witness_pubkey = inp["txinwitness"][1]
                        outpoint = f"{inp['txid']}:{inp['vout']}"
                        
                        # Find matching UTXO
                        matching_utxo = next(
                            (utxo for utxo in wallet_state.utxos 
                             if f"{utxo.txid}:{utxo.vout}" == outpoint),
                            None
                        )
                        
                        if matching_utxo and matching_utxo.public_key == witness_pubkey:
                            wallet_state.balance -= matching_utxo.amount
                            
                            # Remove spent UTXO
                            wallet_state.utxos = [
                                utxo for utxo in wallet_state.utxos 
                                if f"{utxo.txid}:{utxo.vout}" != outpoint
                            ]
                            
                            # Record transaction
                            wallet_state.transactions.append(Transaction(
                                type="spend",
                                block=h,
                                txid=tx_id,
                                amount=matching_utxo.amount,
                                address=matching_utxo.address
                            ))

    return wallet_state

if __name__ == "__main__":
    recovered_wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    recovered_wallet_state.save_state("wallet_state.json")
    print(f"{WALLET_NAME} {recovered_wallet_state.balance.to_btc()}")