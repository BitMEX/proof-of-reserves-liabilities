#! /usr/bin/env python3

from decimal import Decimal
import json
import logging
import os
import requests
from requests.auth import _basic_auth_str
import shutil
import subprocess
import time
import unittest
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

class TestReserves(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        logging.getLogger().setLevel(logging.INFO)

        # Fire up bitcoind
        self.bin_path = "/app/bitcoind"
        self.bitcoin_dir = "/app/.bitcoin"
        shutil.rmtree(self.bitcoin_dir, ignore_errors=True)
        os.makedirs(self.bitcoin_dir)
        self.regtest_bitcoind_proc = subprocess.Popen(
            [self.bin_path, "--datadir={}".format(self.bitcoin_dir), "--rpcuser=user", "--rpcpassword=password", "-regtest", "-connect=0", "-rpcport=18443", "-wallet=default", "-fallbackfee=0.00001000"]
        )

        while True:
            try:
                self.rpc = {"user": "user", "password": "password", "host": "127.0.0.1", "port": 18443}
                print("1")
                ensure_bitcoind(self.rpc)
                print("2")
                net_info = rpc_request(self.rpc, "getblockchaininfo", [], 60)
                print("3")
                rpc_request(self.rpc, "createwallet", ["defaul"], 60)
                print("4")
                assert net_info["chain"] == "regtest"
                break
            except Exception as e:
                logging.info("Regtest daemon not responding yet, sleeping: {}\n".format(e))
                time.sleep(2)

    @classmethod
    def tearDownClass(self):
        print("Tearing down unit tests...", flush=True)

        self.regtest_bitcoind_proc.kill()
        os.waitpid(self.regtest_bitcoind_proc.pid, 0)

    def test_reserves(self):
        logging.info("Generating a regtest PoR file, and running it through the validator")
        assert rpc_request(self.rpc, "getbalance", []) == 0

        # Generate 3 3-of-4 addresses using 3 static pubkeys:
        # 0) legacy uncompressed
        # 1) nested segwit
        # 2) native segwit

        # testnet keys
        static_uncompressed_keys = ["04ceba29da1af96a0f2ef7cda6950b8be2baeb1adf12c0d5efebb70dbcaa086ba029cd82a0cfb8dedf65b8760cf271f2b8a50466bbf0b9339c5ffefbe2a4165326", "04d5a42b90e9d7156155661979530a09d2e12e252ef4104e5611274a7ae7e2b0940657307b129bef948ea932d2d3f20e1a0513c9e84fd850f743ee66a2e3348d1f", "04c10be2f0dc20f4285c25156aa22a0c46d2b89ccc4d1c8eaed92ea0c1a8f40c0003c26eda3bba9d087d0c521327fa1f0426ca510147957c8e342527ce7d9d0048"]
        static_compressed_keys = ["02ceba29da1af96a0f2ef7cda6950b8be2baeb1adf12c0d5efebb70dbcaa086ba0", "03d5a42b90e9d7156155661979530a09d2e12e252ef4104e5611274a7ae7e2b094", "02c10be2f0dc20f4285c25156aa22a0c46d2b89ccc4d1c8eaed92ea0c1a8f40c00"]

        legacy_key = "04ffeec30e5b7657f12f52249e6ab282e768a7a829b79213850af60121dea49fd230598677929e637beed9624bfcfb62721ff7f14a88d996521520651c993e3f41"
        nested_key = "025a2edfd78a4d8bba9616170a02bc61736020d66e447d4501130148cc0fcb5b24"
        native_key = "03534341220e385e2d9ac1db696dceb3db48f96ed1d2718393302e7fe88f78976f"

        legacy = rpc_request(self.rpc, "createmultisig", [3, static_uncompressed_keys + [legacy_key], "legacy"])
        nested = rpc_request(self.rpc, "createmultisig", [3, static_compressed_keys + [nested_key], "p2sh-segwit"])
        native = rpc_request(self.rpc, "createmultisig", [3, static_compressed_keys + [native_key], "bech32"])

        # Deposit some specific amounts for testing the utxo scanning
        gen_addr = rpc_request(self.rpc, "getnewaddress", [])
        rpc_request(self.rpc, "generatetoaddress", [101, gen_addr])
        dep_sizes = [Decimal('0.0001'), Decimal('0.00004'), Decimal('0.000007')]
        for addr, dep_size in zip([legacy["address"], nested["address"], native["address"]], dep_sizes):
            rpc_request(self.rpc, "sendtoaddress", [addr, str(dep_size)])
        gen_addr = rpc_request(self.rpc, "getnewaddress", [])
        rpc_request(self.rpc, "generatetoaddress", [1, gen_addr])

        # This is where validator will check in history
        proof_height = rpc_request(self.rpc, "getblockcount", [])
        proof_hash = rpc_request(self.rpc, "getblockhash", [proof_height])

        # Do another deposit to make sure this isn't found by the validator script
        rpc_request(self.rpc, "sendtoaddress", [native["address"], 1])
        gen_addr = rpc_request(self.rpc, "getnewaddress", [])
        last_blocks = rpc_request(self.rpc, "generatetoaddress", [10, gen_addr])
        total_height = proof_height + 10

        # Construct the proof, tool takes uncompressed version and convertes internally
        proof = {"height": proof_height, "chain":"regtest", "claim": {"m": 3, "n": 4}, "total": int(sum(dep_sizes)), "keys": static_uncompressed_keys}
        proof["address"] = [{"addr_type": "sh", "addr": legacy["address"], "script": legacy["redeemScript"]}, {"addr_type": "sh_wsh", "addr": nested["address"], "script": nested["redeemScript"]}, {"addr_type": "wsh", "addr": native["address"], "script": native["redeemScript"]}]

        with open("test.proof", "w") as f:
            yaml.dump(proof, f)

        # Run validator tool against the proof file
        run_args = ["python3", "/app/validate_reserves.py", "--rpcauth", "user:password", "--rpchost", "127.0.0.1", "--rpcport", "18443", "--proof", "test.proof", "--result-file", proof_hash+"_result.json"]
        output = subprocess.check_output(run_args).decode('utf-8')

        # Check output file's value
        with open(proof_hash+"_result.json") as f:
            result = json.load(f)
            self.assertEqual(str(result["amount_proven"]), str(sum(dep_sizes)))

        # Check that blockheight looks right
        self.assertEqual(rpc_request(self.rpc, "getblockcount", []), proof_height)

        # --reconsider call to make sure that it resets blockheight of the node, don't use rpchost to check default
        run_args = ["python3", "/app/validate_reserves.py", "--rpcauth", "user:password", "--rpcport", "18443", "--reconsider"]
        output = subprocess.check_output(run_args).decode('utf-8')
        while rpc_request(self.rpc, "getblockcount", []) != total_height:
            time.sleep(0.1)

        self.assertEqual(rpc_request(self.rpc, "getbestblockhash", []), last_blocks[-1])

if __name__ == "__main__":
    unittest.main()
