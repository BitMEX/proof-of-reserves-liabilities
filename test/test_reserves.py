#! /usr/bin/env python3

from decimal import Decimal
import json
import logging
import os
import requests
import shutil
import subprocess
import time
import unittest
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
            logging.info(r.text)
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
                logging.info("Bitcoin server not responding, sleeping for retry.")


def make_reserves_proof(bitcoin, dep_sizes=["0.0001", "0.00004", "0.000007"]):
    logging.info("Generating a regtest PoR file, and running it through the validator")
    assert bitcoin.getbalance([]) == 0

    # Generate 3 3-of-4 addresses using 3 static pubkeys:
    # 0) legacy uncompressed
    # 1) nested segwit
    # 2) native segwit

    # testnet keys
    static_uncompressed_keys = [
        "04ceba29da1af96a0f2ef7cda6950b8be2baeb1adf12c0d5efebb70dbcaa086ba029cd82a0cfb8dedf65b8760cf271f2b8a50466bbf0b9339c5ffefbe2a4165326",
        "04d5a42b90e9d7156155661979530a09d2e12e252ef4104e5611274a7ae7e2b0940657307b129bef948ea932d2d3f20e1a0513c9e84fd850f743ee66a2e3348d1f",
        "04c10be2f0dc20f4285c25156aa22a0c46d2b89ccc4d1c8eaed92ea0c1a8f40c0003c26eda3bba9d087d0c521327fa1f0426ca510147957c8e342527ce7d9d0048",
    ]
    static_compressed_keys = [
        "02ceba29da1af96a0f2ef7cda6950b8be2baeb1adf12c0d5efebb70dbcaa086ba0",
        "03d5a42b90e9d7156155661979530a09d2e12e252ef4104e5611274a7ae7e2b094",
        "02c10be2f0dc20f4285c25156aa22a0c46d2b89ccc4d1c8eaed92ea0c1a8f40c00",
    ]

    legacy_key = "04ffeec30e5b7657f12f52249e6ab282e768a7a829b79213850af60121dea49fd230598677929e637beed9624bfcfb62721ff7f14a88d996521520651c993e3f41"
    nested_key = "025a2edfd78a4d8bba9616170a02bc61736020d66e447d4501130148cc0fcb5b24"
    native_key = "03534341220e385e2d9ac1db696dceb3db48f96ed1d2718393302e7fe88f78976f"

    legacy = bitcoin.createmultisig(
        [3, static_uncompressed_keys + [legacy_key], "legacy"],
    )
    nested = bitcoin.createmultisig(
        [3, static_compressed_keys + [nested_key], "p2sh-segwit"],
    )
    native = bitcoin.createmultisig(
        [3, static_compressed_keys + [native_key], "bech32"],
    )

    dep_sizes = [Decimal(x) for x in dep_sizes]

    # Deposit some specific amounts for testing the utxo scanning
    gen_addr = bitcoin.getnewaddress([])
    spendable = sum(dep_sizes)
    bitcoin.generatetoaddress([101, gen_addr])

    while bitcoin.getbalance([]) < spendable:
        print("need more blocks for balance")
        bitcoin.generatetoaddress([2, gen_addr])

    for addr, dep_size in zip(
        [legacy["address"], nested["address"], native["address"]], dep_sizes
    ):
        bitcoin.sendtoaddress([addr, str(dep_size)])
    gen_addr = bitcoin.getnewaddress([])
    bitcoin.generatetoaddress([1, gen_addr])

    # This is where validator will check in history
    proof_height = bitcoin.getblockcount([])

    # Do another deposit *above* the proof height to make sure this isn't found by the validator script
    bitcoin.sendtoaddress([native["address"], 1])

    # now mine blocks above the proof's height
    gen_addr = bitcoin.getnewaddress([])
    bitcoin.generatetoaddress([10, gen_addr])

    # Construct the proof, tool takes uncompressed version and convertes internally
    proof = {
        "height": proof_height,
        "chain": "regtest",
        "claim": {"m": 3, "n": 4},
        "total": int(100000000 * sum(dep_sizes)),
        "keys": static_uncompressed_keys,
    }
    proof["address"] = [
        {
            "addr_type": "sh",
            "addr": legacy["address"],
            "script": legacy["redeemScript"],
        },
        {
            "addr_type": "sh_wsh",
            "addr": nested["address"],
            "script": nested["redeemScript"],
        },
        {
            "addr_type": "wsh",
            "addr": native["address"],
            "script": native["redeemScript"],
        },
    ]
    return proof


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
            [
                self.bin_path,
                "--datadir={}".format(self.bitcoin_dir),
                "--rpcuser=user",
                "--rpcpassword=password",
                "-regtest",
                "-connect=0",
                "-rpcport=18443",
                "-wallet=default",
                "-fallbackfee=0.00001000",
            ]
        )

        self.bitcoin = BitcoinRPC("regtest://user:password@127.0.0.1:18443")
        self.bitcoin.wait_until_alive()
        if self.bitcoin.version >= 210000:
            self.bitcoin.createwallet(["default"])

        net_info = self.bitcoin.getblockchaininfo([])
        assert net_info["chain"] == "regtest"

    @classmethod
    def tearDownClass(self):
        print("Tearing down unit tests...", flush=True)

        self.regtest_bitcoind_proc.kill()
        os.waitpid(self.regtest_bitcoind_proc.pid, 0)

    def test_reserves(self):
        proof = make_reserves_proof(self.bitcoin)
        with open("test.proof", "w") as f:
            yaml.dump(proof, f)

        proof_hash = self.bitcoin.getblockhash([proof["height"]])

        # check again that validation will require some re-winding
        tip_height = self.bitcoin.getblockcount([])
        tip_hash = self.bitcoin.getblockhash([tip_height])
        assert proof["height"] < tip_height

        # Run validator tool against the proof file
        run_args = [
            "python",
            "/app/validate_reserves.py",
            "--bitcoin",
            "regtest://user:password@127.0.0.1:18443",
            "--proof",
            "test.proof",
            "--result-file",
            proof_hash + "_result.json",
        ]
        output = subprocess.check_output(run_args).decode("utf-8")

        # Check output file's value
        with open(proof_hash + "_result.json") as f:
            result = json.load(f)
            self.assertEqual(str(result["amount_proven"]), str(proof["total"]))
            self.assertEqual(str(result["amount_claimed"]), str(proof["total"]))

        # Check that blockheight looks right
        self.assertEqual(self.bitcoin.getblockcount([]), proof["height"])

        # --reconsider call to make sure that it resets blockheight of the node, don't use rpchost to check default
        run_args = [
            "python",
            "/app/validate_reserves.py",
            "--bitcoin",
            "regtest://user:password@127.0.0.1:18443",
            "--reconsider",
        ]
        output = subprocess.check_output(run_args).decode("utf-8")
        while self.bitcoin.getblockcount([]) != tip_height:
            time.sleep(0.1)
        self.assertEqual(self.bitcoin.getbestblockhash([]), tip_hash)

        # check rejection of proofs containing duplicate addresses/scripts
        proof["address"].append(proof["address"][0])

        with open("testbad.proof", "w") as f:
            yaml.dump(proof, f)

        # Run validator tool against the proof file
        run_args = [
            "python",
            "/app/validate_reserves.py",
            "--bitcoin",
            "regtest://user:password@127.0.0.1:18443",
            "--proof",
            "testbad.proof",
            "--result-file",
            proof_hash + "_result.json",
        ]
        with self.assertRaises(subprocess.CalledProcessError) as context:
            subprocess.check_output(run_args, stderr=subprocess.STDOUT)
        self.assertEqual(context.exception.returncode, 1)
        self.assertIn("Duplicate address", context.exception.output.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
