# Tools for Generating and Validating Proofs of Reserves (PoR) and Liabilities (PoL)

These tools allow you to independantly verify exchange solvency by auditing that stated reserves exist and checking they exceed the known liabilities of the exchange to users. Use of these tools is subject to the [BitMEX Terms of Service](https://www.bitmex.com/terms).

BitMEX regularly publish our reserves and liabilities here:

* mainnet dataset: https://public.bitmex.com/?prefix=data/porl/
* testnet dataset: https://public-testnet.bitmex.com/?prefix=data/porl/

As a user you can verify that your own liability, plus that of the insurance fund is included.

A walkthrough of the tools is available by [BitMEX Research](https://blog.bitmex.com/research/):

* 12 Aug 2021 [Fixing The Privacy Gap In Proof Of Liability Protocols](https://blog.bitmex.com/addressing-the-privacy-gap-in-proof-of-liability-protocols/)
* 13 Aug 2021 [Proof of Reserves & Liabilities – BitMEX Demonstration](https://blog.bitmex.com/proof-of-reserves-liabilities-bitmex-demonstration/)
* 9 Nov 2022 [BitMEX Provides Snapshot Update to Bitcoin Proof of Reserves & Proof of Liabilities](https://blog.bitmex.com/bitmex-provides-snapshot-update-to-proof-of-reserves-proof-of-liabilities/)


### Installation

You may wish to switch to a Python virtual environment first.

```
$ python -m venv venv
$ . venv/bin/activate
$ pip3 install -r requirements.txt
```

To validate reserves you will require a running bitcoin daemon, with a reachable RPC server, dedicated to this task.

No additional services are required to validate liabilities.

# Reserves

This tool will take a proof file containing the balances of all BitMEX addresses, plus the locking scripts used to derive the address from exchange keys. It takes control of a Bitcoin Core (bitcoind) instance, rewinds the bitcoin chain state to that of the prooof, then verifies the claimed Bitcoin is indeed under the control of the given keys at that block height. You must validate yourself that the public keys belong to BitMEX!


### ⚠️ Warning ⚠️

NOTE: You are required to be running a bitcoind node v0.21 or higher.
Running `validate_reserves.py` will modify your bitcoind's chainstate by invaliding a block to cause a local rewind. While designed to be recoverable, ensure you have *no other* services using the bitcoind at the same time, or they too will observe a chain rewind.
Validation may take a long time to complete, 30 minutes or longer.

You should run this on a local node that you can control, and then reset the chainstate after doing so.

You may need to run the script multiple times if Bitcoin Core RPC becomes unresponsive due to the load while rewinding blocks.
As long as the `--reconsider` flag isn't given, your Core node will continue to 'reorg' in the background,
succeeding eventually.


Sample output from running PoR tool on testnet dataset against testnet bitcoind RPC server.
```
$ python3 validate_reserves.py --proof testnet_reserves.yaml --bitcoin testnet://username:password@localhost:18332
...
WARNING:root:Proof of Reserves on pruned nodes not well-supported. Node can get stuck reorging past pruned blocks.
INFO:root:Bitcoind alive: At block 1938810
INFO:root:Lets rewind
INFO:root:Invalidate call timed out... continuing
INFO:root:Reorging/Syncing to 00000000000000177167f10d1920ee888319bf5459c7d2c878084cbb354c86cf. THIS CAN TAKE A REALLY LONG TIME!!! Sleeping for 0.5 minutes.
INFO:root:Blocks to go: 1523
INFO:root:Scanning chunk 1/2... this may take a while
INFO:root:Done. Took 42.012248039245605 seconds
INFO:root:Scanning chunk 2/2... this may take a while
INFO:root:Done. Took 28.771291971206665 seconds
INFO:root:***RESULTS***
Height of proof: 1933558
Block proven against: 00000000000000177167f10d1920ee888319bf5459c7d2c878084cbb354c86cf
Proven amount(BTC): 205393.049391
INFO:root:IMPORTANT! Call this script with --reconsider to bring your bitcoin node back to tip when satisfied with the results

# Run --reconsider to re-set your node to undo block invalidations, getting your node back to chaintip
$ python3 validate_reserves.py --reconsider --bitcoin testnet://username:password@localhost:18332
INFO:root:Reconsidering blocks and exiting.
```

Note that the RPC server port default is different for different networks: 8332(mainnet), 18332(testnet).
Note that Bitcoin Core supports 'pruning' block undo data beyond a certain depth. It is highly recommended
that this tool is run against an unpruned bitcoind, otherwise the script may fail if it tries to rewind deeper than pruning allows.

# Liabilities

We provide a tool in two parts, firstly to generate and secondly to verify a custom implementation of [Maxwell Proof of Liabilities](https://eprint.iacr.org/2018/1139.pdf) using a novel blinding approach to make user balances pseudonymous. If you are looking to verify exchange data, [skip ahead to validation](#validation).

## Creation of Liabilities

The starting point is a list of the liabilitity to each user, keyed by an account number:

    $ cat liabilities-100-20210225D150000099012000.csv
    account,amount
    1,1000
    2,3000
    4,4000000000
    5,0

Each account is issued a single 32-byte 'account nonce' for the lifetime of that account, which is shared with the user.
For this demonstration we keep these in a text file `nonces.txt`, note that any missing nonces will be generated with each liabilities run:

    $ cat nonces.txt
    2,b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
    3,38de14dcd1425739ddbe2bcf7505c1bac602fd185727dc7f2fa9ddaeff9a36c9

For convience we number liabilities based on the prevailing bitcoin block height. We first derive a sub-nonce for each user at this height, which permits participating in peer validation of a particular liabilties datset without revealing all past (and future) account balances:

    sub_nonce = sha256(account_nonce || block_height || account_number)

Next all user balances are split ("blinded") into multiple parts, with the ratio of the split determined by a random number generator, thereby information about the distribution of account balances, and active users over time on the participating platform is no longer revealed. 0-value liabilities are dropped as they are not liabilities at all. The parts are shuffled into a random order.

Next the liability chunks are arranged as the leaves of a merkle sum proof, a modified version of the [Maxwell Proof of Liabilities](https://bitcointalk.org/index.php?topic=595180.0) scheme.

Each leaf of the tree contains the `leaf_value` (in satoshis) in plaintext and, using the user's `sub_nonce`, a commitment of the `leaf_value` and the index of the leaf `leaf_index`. All input numerical values being serialized as 8-byte unsigned values.

    leaf_digest = HMAC256(sub_nonce, leaf_value || leaf_index)

Including the `leaf_index` prevents two identical `leaf_value`'s for the same user (unlikely!) having an identical `leaf_digest`.

The binary tree construction continues, node by node, up the tree. The root of the tree therefore commits to the sum total of all liabilities of all the leaves:

```
node_value = left_value + right_value
node_digest = sha256(left_digest||left_value||right_digest||right_value)
```

Continuing our sample dataset:

    % python3 generate_liabilities.py --liabilities liabilities-100-20210225D150000099012000.csv --blockheight 100 | tee liabilities-100-proof.csv
    block_height:100
    ceb08dfd693430ece544df853a989684056c0800088d61bfcc38c0d16cc1e1c7,4000004000
    449b24ad1789df614e1de58a924a312335cf2bb8d9830c89b113d74354bcea78,2352507629
    6ad03b1284e87e672cb57fcf3d97e64ef1eff6c648679c33e433d4b2b0636c33,1647496371
    e54b0f6e0ec5845eed44f1b9e58d202ac8468b3fcb0c2d4961846d1d6cdff7b1,1076759806
    b9bee9ed5991578f3674622172d4d14397e7eff8eb8fc19cb20c9421dab17c84,1275747823
    dbe039f6addaf13a7a712d34a946f0ffb1106884a2ca978bc8c34ea4fb262938,1647493311
    9640e3293a500a40638c22b51ddebc9b6046b9d9bda17b832debee81d57e9fb6,3060
    48e433bb032ad89fc9ff52ab74c0a6af295fe41be6a1300fe8b02febbce535fc,450471613
    bcb09e9ed1450e39e1b5ebb44c299d9d40408026f388fd8b57117dacf8b5f335,626288193
    8701c3bc3bbc1e6e7699129f812ea915eff8fb4bb4d644189580a887d24741c5,530
    b7cae0de2ac83de99b0e02f19d2b420dd07ad3e93e0b360119b4c98b63e98b02,1275747293
    e078517622f1f679851e1d5e61a9d3f44589e5c750b541714154ea028f12e6f7,1647492901
    b3ca4573d1c7b56c4834bff4f11804ec82a39fa47de3c45cccfee2ef49c1d05e,410
    31e1e8af2893f647a4c933454b99170799f5591895814eb52e208280cef132eb,590
    20f222b2a4e1ebc3ba36e2907095604cf982a919d9b16ac2083d9881131e02d5,2470

    $ cat nonces.txt
    2,b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
    3,38de14dcd1425739ddbe2bcf7505c1bac602fd185727dc7f2fa9ddaeff9a36c9
    1,4b014f71332f674b47ccec77ac055c7f6e94f7968afe15b9ffb63b9c392ee97a
    4,b4fb0f6cb39e1b47e159996d54121309d92fed531a4f55b7a30772cb5f21cf8a
    5,239573aae4710e1c1d09ffdf9de67a031176318a5caa901897183014776d607a

The liabilities output can now be made public, the nonces can be disclosed to each user individually. The output of `generate_liabilities.py` contains one line per tree node. The tree is published root first, then left child, then right
child, then one level down starting with left-most child in that row, etc.


NOTE: child node values are commmitted to individually to avoid [specific attacks](https://eprint.iacr.org/2018/1139.pdf) the prover could engage in on the original scheme proposed.

## Validation

Validation requires Python 3.7 and above.

We will run as user `2` above, who has been communicated the account nonce `b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412`.

    % python3 validate_liabilities.py --proof liabilities-100-proof.csv --account 2 --account_nonce b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
    Number of leaf nodes to scan 8
    Hash match for leaf 3 claims 1,294 sats
    Hash match for leaf 5 claims 1,706 sats
    Validated 3,000 sats for account 2
    Total liabilities 4,000,004,000 sats, root hash 85b0a83970a74a6ad0ee5d4bec5d3afe0048d18b8342e31e2d3a45e0f17879c7

More verbose modes are also available, see help for details: `--print-tree` and `--print-proof-csv`

The input file assumes the following CSV header: `account, amount`. Each line corresponds to a leaf in the Merkle sum tree.
Accounts are non-negative integers, serialized as 8-byte unsigned integers. Leaves are shuffled prior to tree generation
as well as balance splitting to ensure the privacy of our users. The user runs `validate_liabilities.py` with
the user-specific `--account` and `--nonce` fields that are served to them through their web account or BitMEX API.
This will decode the amount of value under their account and allow the user to check the root hash against other
users' version of the hash. Note that nonce is assumed to be a 32-byte hex encoded string, unique per proof.


# Issues?

The output's "total liabilities" value can be directly compared against the proved reserves value to give assurances about
solvency.

If a user is unable to prove their balance's inclusion, please contact us at https://www.bitmex.com/contact for assistance.
