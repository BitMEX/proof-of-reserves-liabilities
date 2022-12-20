#!/usr/bin/python3

import argparse
import csv
import hashlib
import hmac
from io import StringIO
import math
import random
import secrets
import struct

# Generates key for HMAC
def gen_sub_nonce(account_nonce, block_height, user_id) :
    m = hashlib.sha256()
    m.update(bytearray.fromhex(account_nonce))
    m.update(struct.pack("<Q", block_height))
    m.update(struct.pack("<Q", user_id))
    return m.digest()

def leaf_hash(value, sub_nonce, leaf_index):
    m = hmac.new(sub_nonce, msg=struct.pack("<Q", value)+struct.pack("<Q", leaf_index), digestmod=hashlib.sha256)
    return m.digest()

def merkleize_nodes(left_digest, left_value, right_digest, right_value):
    m = hashlib.sha256()
    m.update(left_digest)
    m.update(struct.pack("<Q", left_value))
    m.update(right_digest)
    m.update(struct.pack("<Q", right_value))
    return m.digest()

# If we want to generate all-new nonces, just delete file
def maybe_generate_nonces(nonce_file, liabilities):
    user_nonce = {}
    try:
        with open(nonce_file, "r") as f:
            for line in f:
                line = line.strip().split(",")
                if not (len(line) == 1 and line[0] == ""):
                    user_id, nonce = line
                    user_nonce[int(user_id)] = nonce
    except FileNotFoundError:
        pass

    fresh_entries = False
    for liability in liabilities:
        if liability[0] not in user_nonce:
            fresh_entries = True
            user_nonce[liability[0]] = secrets.token_hex(32)

    if fresh_entries:
        with open(nonce_file, "w") as f:
            for k,v in user_nonce.items():
                f.write("{},{}\n".format(k, v))

    return user_nonce

def load_liabilities_file(liabilities_file):
    with open(liabilities_file, "r") as f:
        return f.read()

def parse_liabilities(liabilities_text):
    liabilities = []
    f = StringIO(liabilities_text)
    liability_reader = csv.reader(f, delimiter=",")
    for i, liability in enumerate(liability_reader):
        if i == 0:
            assert liability == ['account', 'amount']
            continue
        liabilities.append([int(liability[0]), int(liability[1])])
    return liabilities


def generate_liabilities_tree(
    liabilities, user_nonces, block_height, min_split=2, exclude_zeros=True
):

    # Find the next power of two leaf size that gives reasonable amount of value anonomity
    # We want every leaf to be split at least once!
    stuffed_size = len(liabilities)*min_split
    final_tree_height = math.ceil(math.log(stuffed_size, 2))
    final_leaf_number = 2**final_tree_height

    # Keep splitting the list until we have enough leaves
    while True:
        # Greedily chop up balances to pad out leaves to power of 2
        stretched_liabilities = []
        stretched_liabilities_len = len(liabilities)

        liabilities = sorted(liabilities, key=lambda x: x[1])

        for liability in reversed(liabilities):
            # If leaf is value 1, it cannot be meaningfully split
            if stretched_liabilities_len < final_leaf_number and liability[1] > 1:
                stretched_liabilities_len += 1
                # Split should always leave at least 1 sat on both leaves
                val1 = random.SystemRandom().randint(1, liability[1] - 1)
                val2 = liability[1] - val1
                stretched_liabilities.append([liability[0], val1])
                stretched_liabilities.append([liability[0], val2])
            elif liability[1] == 0 and exclude_zeros:
                # 0-value liabilities can be filtered out and dealt with by not matching
                # any leaves
                continue
            else:
                stretched_liabilities.append(liability)

        liabilities = stretched_liabilities
        # We're done expanding
        if stretched_liabilities_len == final_leaf_number:
            break

    # Don't allow verifiers to figure out ordering of users
    random.SystemRandom().shuffle(liabilities)

    leaves = []
    for leaf_index, liability in enumerate(liabilities):
        user_id, value = liability
        leaves.append((leaf_hash(value, gen_sub_nonce(user_nonces[user_id], block_height, user_id), leaf_index), value))

    # Build the tree from the leaf hashes
    tree = [leaves]
    row_count = int(len(leaves)/2)
    row_index = 1
    while row_count > 0:
        row_nodes = []
        for i in range(row_count):
            left_node, right_node = tree[row_index-1][i*2:i*2+2]
            row_nodes.append((merkleize_nodes(left_node[0], left_node[1], right_node[0], right_node[1]), left_node[1] + right_node[1]))
        tree.append(row_nodes)
        row_index += 1
        row_count = int(len(row_nodes)/2)

    # Now output proof file:
    # block_height
    # <node_hash>,<node_value> where tree is published root to leaves line by line

    tree_strings = ["block_height:{}".format(block_height)]

    for row in reversed(tree):
        for node in row:
            tree_strings.append("{},{}".format(node[0].hex(), node[1]))
    return "\n".join(tree_strings)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to generatee BitMEX Proof of Liabilities"
    )
    parser.add_argument(
        "--liabilities",
        help="Path to csv file to use as input for liabilities proof",
        required=True,
    )
    parser.add_argument(
        "--blockheight",
        help="Block height of the csv snapshot(used to mix the leaves)",
        required=True,
        type=int,
    )
    parser.add_argument(
        "--min-split",
        help="minimum number of splits for each leaf",
        default=2,
        type=int,
    )
    args = parser.parse_args()
    liabilities_text = load_liabilities_file(args.liabilities)
    liabilities = parse_liabilities(liabilities_text)
    user_nonces = maybe_generate_nonces("nonces.txt", liabilities)
    print(generate_liabilities_tree(liabilities, user_nonces, args.blockheight, min_split=args.min_split))
