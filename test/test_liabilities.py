#! /usr/bin/env python3

import logging
import random
import re
import subprocess
import unittest
from validate_liabilities import gen_sub_nonce


class TestLiabilities(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        logging.getLogger().setLevel(logging.INFO)

    @classmethod
    def tearDownClass(self):
        print("Tearing down unit tests...", flush=True)

    def test_liabilities(self):
        logging.info("Generating test liabilities")

        # Generate a list of 7 account-sat_balance pairs
        account_list = [(5, 1), (3, 0)]
        for i in range(6):
            # We don't expect account collision here in test, all values are serialized as 64-bit uints
            # divide by 8 is to avoid overflow at the root liability
            account_list.append(
                (random.randrange(2**64), random.randrange((2**64) / 8))
            )

        account_map = dict(account_list)
        with open("balances.txt", "w") as f:
            f.write("account,amount\n")
            for account in account_list:
                f.write("{},{}\n".format(account[0], account[1]))

        # Put through PoL proof generator
        # any 8 byte number, unique per real proof for privacy
        block_height = str(random.randrange(2**64))
        run_args = [
            "python3",
            "/app/generate_liabilities.py",
            "--liabilities",
            "balances.txt",
            "--blockheight",
            block_height,
        ]
        output = subprocess.check_output(run_args).decode("utf-8")
        with open("liability_proof.txt", "w") as f:
            f.write(output)

        output = output.split("\n")

        # Make sure output file has split into 16 leaves, none of them value 0

        # 16 leaves, 15 nodes, 1 blockheight output, and one empty line
        self.assertEqual(len(output), 16 + 15 + 1 + 1)
        self.assertEqual(output[0], "block_height:" + block_height)
        for line in output[1:]:
            if line == "":
                break
            assert int(line.split(",")[1]) >= 1

        # Run through validator for each user, make sure balances match
        for nonce_arg in ["--account_nonce", "--nonce"]:
            with open("nonces.txt", "r") as f:
                for line in f.readlines():
                    account, nonce = line.split(",")
                    # Making sub-nonce which is served by the API to users by default
                    if nonce_arg == "--nonce":
                        nonce = gen_sub_nonce(
                            nonce, int(block_height), int(account)
                        ).hex()
                    # Call validator tool
                    run_args = [
                        "python3.7",
                        "/app/validate_liabilities.py",
                        "--account",
                        account,
                        nonce_arg,
                        nonce.strip(),
                        "--proof",
                        "liability_proof.txt",
                    ]
                    output = subprocess.check_output(run_args).decode("utf-8")
                    validated_amount = int(
                        re.findall("Validated (\d+) sats", output.replace(",", ""))[0]
                    )
                    self.assertEqual(account_map[int(account)], validated_amount)


if __name__ == "__main__":
    unittest.main()
