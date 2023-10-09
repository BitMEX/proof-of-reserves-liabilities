#!/usr/bin/python3

import argparse
import copy
from collections import Counter
import json
import logging
import math
import os
import requests
import time
import yaml
from urllib.parse import urlparse
import functools


class JsonRPCException(Exception):
    pass


class BitcoinRPC:
    def __init__(self, uri):
        # pull network out of the schema, and set the schema back to HTTP for RPC
        self.config = urlparse(uri)
        self.network = self.config.scheme
        self.bitcoind = f"http://{self.config.netloc}"
        self.version = None

    def __getattr__(self, method):
        def wrapper(method, params=[], **kwargs):
            data = {
                "method": method,
                "params": params,
                "jsonrpc": "2.0",
                "id": 0,
            }
            r = requests.post(self.bitcoind, json=data, **kwargs)
            logging.debug(r.text)
            r.raise_for_status()
            result = r.json()
            if result["error"] is not None:
                raise JsonRPCException(result["error"])
            return result["result"]

        return functools.partial(wrapper, method)

    def wait_until_alive(self):
        while True:
            try:
                time.sleep(1)
                self.version = self.getnetworkinfo([])["version"]
                break
            except Exception as e:
                logging.exception("Bitcoin server not responding, sleeping for retry.")


def read_proof_file(proof_file):
    with open(proof_file) as data:
        logging.info(
            "Loading yaml proof file into memory, this may take a few minutes."
        )
        data = yaml.safe_load(data)
        logging.info("Done loading.")
        return data


def compress(pubkeys):
    result = []
    for key in pubkeys:
        # Trying "both" compressed versions to avoid additional python dependencies
        result.append("02" + key[2:-64])
        result.append("03" + key[2:-64])
    return result


def compile_proofs(proof_data):
    m_sigs = proof_data["claim"]["m"]
    n_keys = proof_data["claim"]["n"]
    keys = proof_data["keys"]
    xpubs = proof_data.get("xpub", [])
    logging.info(
        "Multisig {}/{} keys being proven against: {}".format(m_sigs, n_keys, keys)
    )
    logging.info("or addresses derived from pubkey: {}".format(xpubs))

    addrs = proof_data["address"]

    dupe_addresses = [
        k for k, c in Counter([a["addr"] for a in addrs]).items() if c > 1
    ]
    if dupe_addresses:
        raise ValueError("Duplicate address: {}".format(dupe_addresses))

    dupe_scripts = [
        k
        for k, c in Counter(
            [a["script"] for a in addrs if a["addr_type"] != "unspendable"]
        ).items()
        if c > 1
    ]
    if dupe_scripts:
        raise ValueError("Duplicate scripts: {}".format(dupe_scripts))

    descriptors = []
    unspendable = 0
    claimed = 0
    pubkeys_uncompressed = keys
    pubkeys_compressed = compress(keys)

    # Lastly, addresses
    for addr_info in addrs:
        if addr_info["addr_type"] == "unspendable":
            logging.warning(
                "Address {} is marked as unspendable, skipping this value".format(
                    addr_info["addr"]
                )
            )
            unspendable += int(addr_info["balance"])
            continue

        elif addr_info["addr_type"] in ("sh", "sh_wsh", "wsh"):
            # Each address should have n compressed or uncompressed keys in this set
            if addr_info["addr_type"] in ("wsh", "sh_wsh"):
                pubkeys = pubkeys_compressed
            else:
                pubkeys = pubkeys_uncompressed

            # Next, we make sure the script is a multisig template
            pubkey_len = 33 * 2 if addr_info["addr_type"] != "sh" else 65 * 2
            pubkey_sep = hex(int(pubkey_len / 2))[2:]

            script = addr_info["script"]
            if script[:2] != hex(0x50 + m_sigs)[2:]:
                raise Exception(
                    "Address script doesn't match multisig: {}".format(script)
                )
            script = script[2:]
            found_vanitykey = 0
            found_pubkeys = 0
            wrong_keys = False
            ordered_pubkeys = []
            while len(script) > 4:
                if script[:2] != pubkey_sep:
                    raise Exception(
                        f"Address script doesn't match multisig: {pubkey_sep} from {addr_info['script']} remaining {script}"
                    )
                pubkey = script[2 : 2 + pubkey_len]
                ordered_pubkeys.append(pubkey)
                script = script[2 + pubkey_len :]
                if pubkey in pubkeys:
                    found_pubkeys += 1
                else:
                    found_vanitykey += 1

            # each bitmex 3/4 multisig should contain one per-account 'vanity' key, and 3 drawn from the set of founder keys
            # note in testnet there are 4 possible founder keys to match against
            assert found_pubkeys == 3
            assert found_vanitykey == 1

            if script != hex(0x50 + n_keys)[2:] + "ae":
                raise Exception(
                    "Address script doesn't match multisig: {}".format(script)
                )

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
            for xp in xpubs:
                if xp in addr_info["script"]:
                    descriptor = addr_info["script"]
                    break
            else:
                raise Exception(
                    "None of expected pubkeys found in descriptor {}".format(
                        addr_info["script"]
                    )
                )
        else:
            raise Exception("Unknown address type {}".format(addr_info["addr_type"]))
        addr_balance = int(addr_info["balance"])
        claimed += addr_balance
        descriptors.append((descriptor, addr_balance, addr_info["addr"]))

    if claimed + unspendable != proof_data["total"]:
        raise Exception(
            f"Proof file total {proof_data['total']} does not match sum of individual claims {claimed}"
        )

    return {
        "descriptors": descriptors,
        "height": proof_data["height"],
        "chain": proof_data["chain"],
        "total": proof_data["total"],
        "claimed": claimed,
        "unspendable": unspendable,
    }


def validate_proofs(bitcoin, proof_data, chunk_size=60000):
    if proof_data is None:
        raise Exception("Needs proof arg")

    bci = bitcoin.getblockchaininfo([])
    # Re-org failure is really odd and unclear to the user when pruning
    # so we're not bothering to support this.
    if bci["pruned"]:
        logging.warning(
            "Proof of Reserves on pruned nodes not well-supported. Node can get stuck reorging past pruned blocks."
        )

    block_count = bitcoin.getblockcount([])
    logging.info(f"Bitcoind at block {block_count} chain {bci['chain']}")

    if bci["chain"] != proof_data["chain"]:
        raise Exception(
            f"Network mismatch: bitcoind:{bci['chain']} vs proof:{proof_data['chain']}"
        )

    if block_count < proof_data["height"]:
        raise Exception(
            f"Chain height {block_count} is behind the claimed height in the proof {proof_data['height']}. Bailing."
        )

    block_hash = bitcoin.getblockhash([proof_data["height"]])
    try:
        bitcoin.getblock([block_hash])
    except Exception as e:
        if "pruned":
            raise Exception(
                "Looks like your node has pruned beyond the reserve snapshot; bailing."
            )
        else:
            raise Exception("Fatal: Unable to retrieve block at snapshot height")

    logging.info(
        f"Running against {proof_data['chain']} chain, rewinding tip to {block_hash}".format()
    )

    # there could be forks leading from the block we want, so we need to invalidate them
    # one-by-one, until nextblockhash is empty
    while True:
        # Check that we know about that block before doing anything
        block_info = bitcoin.getblock([block_hash])

        # WARNING This can be unstable if there's a reorg at tip
        if block_info["confirmations"] < 1:
            raise Exception("Block {} is not in best chain!".format(block_hash))

        # Looks good, now let's get chaintip to where we want it to be
        # This may take more syncing forward, or a reorg backwards.
        #
        # If we're at tip the key doesn't exist, so continue
        if "nextblockhash" in block_info:
            try:
                logging.info(
                    f"Invalidating child block {block_info['nextblockhash']} and any successors"
                )
                bitcoin.invalidateblock([block_info["nextblockhash"]])
            except Exception:
                logging.info("Invalidate call timed out... continuing")
                pass
        else:
            logging.info("Tip no longer has a next block, continuing")
            break

        # Wait until we can get response from rpc server
        bitcoin.wait_until_alive()

        # if invalidateblock hit a HTTP timeout, this attempted to poll until it completes. This might not be sound
        # in the case of multiple forks though, since we will jump to the next valid fork and not get back to best_hash

        # best_hash = bitcoin.getbestblockhash([], timeout=60)
        # while best_hash != block_hash:
        #     minute_wait = 0.5
        #     logging.info(
        #         "Waiting for re-org to {block_hash}. This can take a long time. Sleeping for {minute_wait} minutes."
        #     )
        #     logging.info(
        #         "Blocks to go: {}".format(
        #             abs(block_info["height"] - bitcoin.getblock([best_hash], timeout=30)["height"])
        #         )
        #     )
        #     time.sleep(60 * minute_wait)
        #     best_hash = bitcoin.getbestblockhash([], timeout=30)

    # large batches are efficient, however you are likely to time out submitting the request, rather than on
    # bitcoin failing to do the workload.
    # "413 Request Entity Too Large" otherwise
    descriptors_to_check = proof_data["descriptors"]

    num_scan_chunks = math.ceil(len(descriptors_to_check) / chunk_size)
    proven_amount = 0
    for i in range(num_scan_chunks):
        now = time.time()
        logging.info(f"Scanning chunk {i+1}/{num_scan_chunks}, this may take a while")
        # Making extremely long timeout for scanning job
        chunk = descriptors_to_check[i * chunk_size : (i + 1) * chunk_size]
        res = bitcoin.scantxoutset(
            ["start", [x[0] for x in chunk]],
            timeout=60 * 60,
        )
        chunk_expected = sum([x[1] for x in chunk])

        if not res["success"]:
            raise Exception("scantxoutset did not indicate success")

        if bitcoin.version >= 210000 and res["bestblock"] != block_hash:
            raise Exception(
                f"Tip move during verify, unsound result. Got {res['bestblock']} expected {block_hash}"
            )

        chunk_amount = int(100000000 * res["total_amount"])
        if chunk_expected != chunk_amount:
            addrs = ",".join([x[2] for x in chunk])
            logging.warning(
                f"chunk total differs. Expected {chunk_expected} got {chunk_amount} for addrs {addrs}"
            )

        proven_amount += chunk_amount
        logging.info(
            f"...completed chunk. Verified {chunk_amount} sats in {time.time() - now} seconds"
        )

    logging.info(
        "***RESULTS***\nHeight of proof: {}\nBlock proven against: {}\nClaimed amount (sats): {}\nProven amount(sats): {}".format(
            proof_data["height"], block_hash, proof_data["claimed"], proven_amount
        )
    )
    return {
        "amount_claimed": proof_data["claimed"],
        "amount_proven": proven_amount,
        "height": proof_data["height"],
        "block": block_hash,
    }


def reconsider_blocks(bitcoin):
    # no need to consider forks below our current height
    bci = bitcoin.getblockchaininfo([])

    logging.info(f"Reconsidering all forks above height {bci['blocks']}")
    for tip in bitcoin.getchaintips([]):
        try:
            if tip["height"] >= bci["blocks"]:
                if tip["status"] != "active":
                    logging.info(f"Reconsidering non-active tip: {tip}")
                    bitcoin.reconsiderblock([tip["hash"]], timeout=60 * 60)
        except requests.exceptions.ReadTimeout:
            logging.exception("while reconsiding tip")

    bitcoin.wait_until_alive()
    bci = bitcoin.getblockchaininfo([])
    logging.info(f"Tip is now at {bci['blocks']}")


if __name__ == "__main__":
    BITCOIND_DEFAULT = os.environ.get("BITCOIND", "https://bitcoin:pass@localhost:1234")
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
        "--bitcoin", default=BITCOIND_DEFAULT, help="Override bitcoind URI"
    )
    parser.add_argument(
        "--verbose", "-v", help="Prints more information about scanning results"
    )
    parser.add_argument(
        "--result-file",
        help="Write amount verified to a file (json format)",
    )
    parser.add_argument(
        "--allow-unspendable",
        help="Allow unspendable (unproven) claims in total (testnet)",
        action="store_true",
    )
    parser.add_argument(
        "--chunk-size",
        default=10000,
        type=int,
    )
    args = parser.parse_args()

    bitcoin = BitcoinRPC(args.bitcoin)
    logging.getLogger().setLevel(logging.INFO)

    bitcoin.wait_until_alive()
    if bitcoin.version < 180100:
        raise Exception("You need to run Bitcoin Core v0.18.1 or higher!")

    if args.reconsider:
        reconsider_blocks(bitcoin)

    elif args.proof is not None:
        data = read_proof_file(args.proof)
        compiled_proof = compile_proofs(data)
        validated = validate_proofs(bitcoin, compiled_proof, chunk_size=args.chunk_size)

        if args.result_file is not None:
            logging.info(f"Writing results {validated} to {args.result_file}")
            with open(args.result_file, "w") as f:
                json.dump(validated, f)

        logging.info(
            "IMPORTANT! Call this script with --reconsider to bring your bitcoin node back to tip when satisfied with the results"
        )

        if validated["amount_proven"] < validated["amount_claimed"]:
            print(
                f"WARNING: More claimed {validated['amount_claimed']} than proven {validated['amount_proven']}"
            )
            exit(-1)

        allowed_unspendable = (
            compiled_proof["unspendable"] if args.allow_unspendable else 0
        )
        if compiled_proof["total"] > validated["amount_proven"] + allowed_unspendable:
            print(
                f"WARNING: Total claimed {validated['amount_claimed']} exceeds proven {validated['amount_proven']} plus allowed unspendable {allowed_unspendable}"
            )
            exit(-1)
