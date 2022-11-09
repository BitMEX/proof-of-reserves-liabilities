#!/usr/bin/python3

import argparse
import copy
import json
import logging
import math
import requests
from requests.auth import _basic_auth_str
import time
import yaml

def rpc_request(rpc, method, params, timeout=5):
    headers = {
        "Authorization": _basic_auth_str(rpc["user"], rpc["password"]),
        "Content-Type": "application/json",
    }
    data = {
        "method": method,
        "params": params,
        "jsonrpc": "2.0",
        "id": 0,
    }
    encoded_data = json.dumps(data).encode("utf-8")

    response = requests.post(
        "http://{}:{}".format(rpc["host"], rpc["port"]), data=encoded_data, headers=headers, timeout=timeout
    )
    try:
        result = json.loads(response.content)
        if result["result"] is not None:
            return result["result"]
        elif result["error"] is not None:
            raise Exception(json.dumps(result["error"]))
    except Exception as e:
        raise Exception("RPC call failed. Raw return output: {}".format(response))

def ensure_bitcoind(rpc):
    # Test connection with bitcoind rpc
    while True:
        try:
            time.sleep(1)
            rpc_request(rpc, "getblockcount", [])
            break
        except Exception as e:
            logging.info(
                "Bitcoin server not responding, sleeping and trying again: {}".format(
                    str(e)
                )
            )

def compile_proofs(rpc, proof):
    if proof is None:
        raise Exception("Unable to load proof file")

    if rpc_request(rpc, "getnetworkinfo", [])["version"] < 210000:
        raise Exception("You need to run Bitcoin Core v0.21 or higher!")

    info = rpc_request(rpc, "getblockchaininfo", [])
    # Re-org failure is really odd and unclear to the user when pruning
    # so we're not bothering to support this.
    if info["pruned"]:
        logging.warning("Proof of Reserves on pruned nodes not well-supported. Node can get stuck reorging past pruned blocks.")

    network = info["chain"]

    block_count = rpc_request(rpc, "getblockcount", [])
    logging.info("Bitcoind alive: At block {}".format(block_count))

    addresses = []

    with open(proof) as proof_file:

        logging.info("Loading yaml proof file into memory, this may take a few minutes.")
        proof_data = yaml.safe_load(proof_file)
        logging.info("Done.")

        # Refresh block count after file loads in case we made progress
        block_count = rpc_request(rpc, "getblockcount", [])

        if network != proof_data["chain"]:
            raise Exception("Network mismatch: bitcoind:{} vs proof:{}".format(network, proof_data["chain"]))

        if block_count < proof_data["height"]:
            raise Exception("Chain height locally is behind the claimed height in the proof. Bailing.")

        block_hash = rpc_request(rpc, "getblockhash", [proof_data["height"]])

        try:
            rpc_request(rpc, "getblock", [block_hash])
        except Exception as e:
            if "pruned":
                raise Exception("Looks like your node has pruned beyond the reserve snapshot; bailing.")
            else:
                raise Exception("Fatal: Unable to retrieve block at snapshot height")

        logging.info("Running test against {} dataset".format(proof_data["chain"]))

        m_sigs = proof_data["claim"]["m"]
        n_keys = proof_data["claim"]["n"]
        keys = proof_data["keys"]
        xpubs = proof_data.get("xpub", [])
        logging.info("Multisig {}/{} keys being proven against: {}".format(m_sigs, n_keys, keys))
        logging.info("or addresses derived from pubkey: {}".format(xpubs))

        # Lastly, addresses
        for addr_info in proof_data["address"]:

            if addr_info["addr_type"] == "unspendable":
                logging.warning("Address {} is marked as unspendable, skipping this value".format(addr_info["addr"]))
                continue

            elif addr_info["addr_type"] in ("sh", "sh_wsh", "wsh"):

                # Each address should have compressed or uncompressed keys in this set
                pubkeys_left = copy.deepcopy(keys)

                if addr_info["addr_type"] in ("wsh", "sh_wsh"): # Switch to compressed
                    pubkeys_left = []
                    for key in keys:
                        # Trying "both" compressed versions to avoid additional python dependencies
                        even_key = "02"+key[2:-64]
                        odd_key = "03"+key[2:-64]
                        if even_key in addr_info["script"]:
                            pubkeys_left.append(even_key)
                        elif odd_key in addr_info["script"]:
                            pubkeys_left.append(odd_key)
                        else:
                            raise Exception("Wrong compressed keys?")

                # Should have one additional vanitygen key
                assert len(pubkeys_left) == n_keys - 1

                # Next, we make sure the script is a multisig template
                pubkey_len = 33*2 if addr_info["addr_type"] != "sh" else 65*2
                pubkey_sep = hex(int(pubkey_len/2))[2:]

                script = addr_info["script"]
                if script[:2] != hex(0x50+m_sigs)[2:]:
                    raise Exception("Address script doesn't match multisig: {}".format(script))
                script = script[2:]
                found_vanitykey = False
                wrong_keys = False
                ordered_pubkeys = []
                for i in range(len(pubkeys_left)+1):
                    if script[:2] != pubkey_sep:
                        raise Exception("Address script doesn't match multisig: {}".format(pubkey_sep))
                    pubkey = script[2:2+pubkey_len]
                    ordered_pubkeys.append(pubkey)
                    script = script[2+pubkey_len:]
                    if pubkey not in pubkeys_left:
                        if found_vanitykey == False:
                            found_vanitykey = True
                        else:
                            # Some testnet values have wrong keys, ignore balance and continue
                            wrong_keys = True
                            break
                    else:
                        pubkeys_left.remove(pubkey)

                if wrong_keys:
                    logging.warning("Address {} is missing some given keys, skipping these values".format(addr_info["addr"]))
                    continue

                assert len(pubkeys_left) == 0
                assert found_vanitykey

                if script != hex(0x50+n_keys)[2:]+"ae":
                    raise Exception("Address script doesn't match multisig: {}".format(script))

                # Lastly, construct the descriptor for querying
                ordered_join = ",".join(ordered_pubkeys)
                if addr_info["addr_type"] == "sh":
                    descriptor = "sh(multi({},{}))".format(m_sigs, ordered_join)
                elif addr_info["addr_type"] == "sh_wsh":
                    descriptor = "sh(wsh(multi({},{})))".format(m_sigs, ordered_join)
                elif addr_info["addr_type"] == "wsh":
                    descriptor = "wsh(multi({},{}))".format(m_sigs, ordered_join)
                else:
                    raise Exception("Unexpected addr_type")

            elif addr_info["addr_type"] in ("wpkh"):
                # check xpub, then we present descriptor as script
                assert xpubs[0] in addr_info["script"]
                descriptor = addr_info["script"]
            else:
                raise Exception("Unknown address type {}".format(addr_info["addr_type"]))

            addresses.append({"desc":descriptor})

        return {"address":addresses, "height": proof_data["height"], "total": proof_data["total"]}

def validate_proofs(rpc, proof_data):

    if proof_data is None:
        raise Exception("Needs proof arg")

    info = rpc_request(rpc, "getblockchaininfo", [])
    # Re-org failure is really odd and unclear to the user when pruning
    # so we're not bothering to support this.
    if info["pruned"]:
        logging.warning("Proof of Reserves on pruned nodes not well-supported. Node can get stuck reorging past pruned blocks.")

    logging.info("Bitcoind alive: At block {}".format(rpc_request(rpc, "getblockcount", [])))

    descriptors_to_check = []

    block_hash = rpc_request(rpc, "getblockhash", [proof_data["height"]])

    # Check that we know about that block before doing anything
    block_info = rpc_request(rpc, "getblock", [block_hash])

    # WARNING This can be unstable if there's a reorg at tip
    if block_info["confirmations"] < 1:
        raise Exception("Block {} is not in best chain!".format(block_hash))

    # Load descriptors
    descriptors_to_check = []
    for addr_info in proof_data["address"]:
        descriptors_to_check.append(addr_info["desc"])

    logging.info("Lets rewind")

    # Looks good, now let's get chaintip to where we want it to be
    # This may take more syncing forward, or a reorg backwards.
    #
    # If we're at tip the key doesn't exist and we can't freeze, so continue
    if "nextblockhash" in block_info:
        try:
            rpc_request(rpc, "invalidateblock", [block_info["nextblockhash"]])
        except Exception:
            logging.info("Invalidate call timed out... continuing")
            pass

    # Wait until we can get response from rpc server
    ensure_bitcoind(rpc)

    # Longer calls for next section to avoid timeouts from the reorg computation happening
    best_hash = rpc_request(rpc, "getbestblockhash", [], 60)
    while best_hash != block_hash:
        minute_wait = 0.5
        logging.info(
            "Reorging/Syncing to {}. THIS CAN TAKE A REALLY LONG TIME!!! Sleeping for {} minutes.".format(
                block_hash, minute_wait
            )
        )
        logging.info(
            "Blocks to go: {}".format(
                abs(block_info["height"] - rpc_request(rpc, "getblock", [best_hash], 30)["height"])
            )
        )
        time.sleep(60 * minute_wait)
        best_hash = rpc_request(rpc, "getbestblockhash", [], 30)

    # "413 Request Entity Too Large" otherwise
    chunk_size = 60000
    num_scan_chunks = math.ceil(len(descriptors_to_check)/chunk_size)
    proven_amount = 0
    for i in range(num_scan_chunks):
        now = time.time()
        logging.info("Scanning chunk {}/{}... this may take a while".format(i+1, num_scan_chunks))
        # Making extremely long timeout for scanning job
        res = rpc_request(rpc, "scantxoutset", ["start", descriptors_to_check[i*chunk_size:(i+1)*chunk_size]], 60*60)
        logging.info("Done. Took {} seconds".format(time.time()-now))

        if not res["success"]:
            raise Exception("Scan results not successful???")

        if res["bestblock"] != block_hash:
            raise Exception("We retrieved snapshot from wrong block? {} vs {}".format(res["bestblock"], block_hash))

        proven_amount += res["total_amount"]

        if args.verbose:
            logging.info(res)

    logging.info(
        "***RESULTS***\nHeight of proof: {}\nBlock proven against: {}\nProven amount(BTC): {}".format(
            proof_data["height"], block_hash, proven_amount
        )
    )

    with open(block_hash+"_result.json", 'w') as f:
        json.dump({"amount_proven": proven_amount}, f)

    logging.info("IMPORTANT! Call this script with --reconsider to bring your bitcoin node back to tip when satisfied with the results")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to validate BitMEX Proof of Reserves"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--proof",
        help="Complete filepath to BitMEX proof of reserves file.",
    )
    group.add_argument(
        "--reconsider",
        help="Setting this causes all invalidated blocks to be reconsidered and exit early.",
        action="store_true",
    )
    parser.add_argument(
        "--rpcauth", help="<username>:<password> for RPC connection", required=True
    )
    parser.add_argument("--rpchostDANGERDANGER", help="Hostname for RPC connection. Beware of exposing your bitcoind to external machines!", required=False, default="127.0.0.1")
    parser.add_argument("--rpcport", help="Port for RPC connection", required=True)
    parser.add_argument(
        "--verbose", "-v", help="Prints more information about scanning results"
    )
    args = parser.parse_args()

    rpc = {"user": args.rpcauth.split(":")[0], "password": args.rpcauth.split(":")[1], "host": args.rpchostDANGERDANGER, "port": args.rpcport}

    logging.getLogger().setLevel(logging.INFO)

    ensure_bitcoind(rpc)

    if args.reconsider:
        logging.info("Reconsidering blocks and exiting.")
        for tip in rpc_request(rpc, "getchaintips", []):
            # Move on from timeout
            try:
                rpc_request(rpc, "reconsiderblock", [tip["hash"]], 0.01)
            except Exception:
                pass
    elif args.proof is not None:
        compiled_proof = compile_proofs(rpc, args.proof)
        validate_proofs(rpc, compiled_proof)

