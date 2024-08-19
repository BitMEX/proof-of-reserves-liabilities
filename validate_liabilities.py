#!/usr/bin/python3

import argparse
import csv
import hashlib
import hmac
import itertools
import struct
from collections import namedtuple

TreeNode = namedtuple("TreeNode", ["hash", "sats", "lineno"], defaults=[0])


# Generates key for HMAC
def gen_sub_nonce(account_nonce, block_height, user_id):
    m = hashlib.sha256()
    m.update(bytearray.fromhex(account_nonce))
    m.update(struct.pack("<Q", block_height))
    m.update(struct.pack("<Q", user_id))
    return m.digest()


def leaf_hash(value, sub_nonce, leaf_index):
    m = hmac.new(
        sub_nonce,
        msg=struct.pack("<Q", value) + struct.pack("<Q", leaf_index),
        digestmod=hashlib.sha256,
    )
    return m.digest()


def merkleize_nodes(left, right):
    m = hashlib.sha256()
    m.update(left.hash)
    m.update(struct.pack("<Q", left.sats))
    m.update(right.hash)
    m.update(struct.pack("<Q", right.sats))
    return TreeNode(m.digest(), left.sats + right.sats)


def read_tree(proof_file):
    tree = []
    row_size = 1  # starts with root, doubles until we hit eof
    with open(proof_file, "r") as f:
        proofreader = csv.reader(f, delimiter=",")
        # Construct the tree as we read in lines, don't verify anything yet
        new_row = []
        node_row_index = 0
        for index, line in enumerate(proofreader):
            if index == 0:
                label, value = line[0].split(":")
                assert label == "block_height"
                block_height = int(value)
            else:
                new_row.append(
                    TreeNode(bytearray.fromhex(line[0]), int(line[1]), index + 1)
                )
                assert len(line) == 2
                if node_row_index + 1 == row_size:
                    tree.append(new_row)
                    row_size *= 2
                    node_row_index = 0
                    new_row = []
                else:
                    node_row_index += 1

    # check leaf layer complete
    n = len(tree[-1])
    if not ((n & (n - 1) == 0) and n != 0):
        raise Exception("Proof file has invalid amount of hashes(must be power of 2)")

    tree.reverse()
    return block_height, tree


def validate_liabilities(block_height, tree, account, nonce, account_nonce, args):
    if nonce:
        nonce_bytes = bytearray.fromhex(nonce)
    elif account_nonce:
        nonce_bytes = gen_sub_nonce(account_nonce, block_height, account)
        print(
            f"Snapshot nonce for account {account} at height {block_height} is {nonce_bytes.hex()}"
        )

    # Scan through leaves looking for matches
    summed_value = 0

    print("Number of leaf nodes to scan {}".format(len(tree[0])))

    # Iterate through leaves and build proofs, printing them out if we find a matching leaf hash, and the tree computation is correct
    for leaf_index in range(len(tree[0])):
        # Compute leaf hash, bail fast if non-matching
        if (
            leaf_hash(tree[0][leaf_index][1], nonce_bytes, leaf_index)
            != tree[0][leaf_index].hash
        ):
            continue

        print(
            "Hash match for leaf {} claims {:,} sats".format(
                leaf_index, tree[0][leaf_index].sats
            )
        )

        # Next validate tree up to root, printing out single proof
        current_index = leaf_index

        proof_nodes = []  # [us,      parent,         ..., n-parent,     root]
        proof_siblings = []  # [sibling, parent-sibling, ..., n-parent-sib]
        for height in range(len(tree) - 1):
            # Grab sibling hash, value, add to proof
            left_index = current_index - current_index % 2
            sibling_index = (
                current_index + 1 if current_index % 2 == 0 else current_index - 1
            )

            proof_nodes.append(tree[height][current_index])
            proof_siblings.append(tree[height][sibling_index])

            # Validate parent hash matches expected
            left_node, right_node = tree[height][left_index : left_index + 2]
            expected_parent = merkleize_nodes(left_node, right_node)
            current_index = int(current_index / 2)
            parent_node = tree[height + 1][current_index]
            if expected_parent.hash != parent_node.hash:
                raise Exception(
                    "Tree node hash computation mismatch: {} vs {}".format(
                        expected_parent, parent_node
                    )
                )
            if expected_parent.sats != parent_node.sats:
                raise Exception(
                    "Tree node sats computation mismatch: {} vs {}".format(
                        expected_parent, parent_node
                    )
                )

        # Gets this far? It's a match
        assert expected_parent.hash == tree[-1][0].hash
        proof_nodes.append(tree[-1][0])

        if args.print_proof_csv:
            print(
                "{},{},{},{}".format(
                    leaf_index,
                    block_height,
                    proof_nodes[0].sats,
                    ",".join(
                        "{},{}".format(n.hash.hex(), n.sats) for n in proof_siblings
                    ),
                )
            )
        elif args.print_tree:
            for p, s in itertools.zip_longest(proof_nodes, proof_siblings):
                print(
                    "  {} {:26,} {:10} {:10}".format(
                        p.hash.hex(), p.sats, p.lineno, s.lineno if s else ""
                    )
                )

        summed_value += tree[0][leaf_index].sats

    print("Validated {:,} sats for account {}".format(summed_value, account))
    print(
        "Total liabilities {:,} sats, root hash {}".format(
            tree[-1][0].sats, tree[-1][0].hash.hex()
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to validate BitMEX Proof of Liabilities"
    )
    parser.add_argument(
        "--proof",
        help="Complete filepath to BitMEX proof of liabilities file",
        required=True,
    )
    parser.add_argument(
        "--account",
        type=int,
        help="BitMEX numerical account ID",
        required=True,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--nonce",
        help="Nonce to decrypt your balances. Unique per proof. DO NOT SHARE WITH ANYONE!",
    )
    group.add_argument(
        "--account_nonce",
        help="EXPERT: Master nonce to decrypt your balances. Static for the lifetime of your account. Use --nonce if at all possible.",
    )
    parser.add_argument(
        "--print-proof-csv",
        action="store_true",
        help="print proof matches as comma separated list of nodes",
        default=False,
    )
    parser.add_argument(
        "--print-tree",
        action="store_true",
        help="print tree path as text: node hash, parent line number, sibling line number",
    )
    args = parser.parse_args()


if __name__ == "__main__":
    block_height, tree = read_tree(args.proof)
    validate_liabilities(
        block_height, tree, args.account, args.nonce, args.account_nonce, args
    )
