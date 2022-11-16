# Tool Suite for Generating and Validating Proofs of Reserves(PoR) and Liabilities(PoL)

These tools allow you to independantly verify exchange solvency by auditing that stated reserves exist and checking they exceed the known liabilities of the exchange to users.

BitMEX regularly publish our reserves and liabilities here:

* mainnet dataset: https://public.bitmex.com/?prefix=data/porl/
* testnet dataset: https://public-testnet.bitmex.com/?prefix=data/porl/

As a user you can verify that your own liability, plus that of the insurance fund is included.

A Walkthrough of the tools and methodology is available at:

* BitMEX Research, 12 Aug 2021 [Fixing The Privacy Gap In Proof Of Liability Protocols](https://blog.bitmex.com/addressing-the-privacy-gap-in-proof-of-liability-protocols/)
* BitMEX Research, 13 Aug 2021 [Proof of Reserves & Liabilities – BitMEX Demonstration](https://blog.bitmex.com/proof-of-reserves-liabilities-bitmex-demonstration/)
* BitMEX Research, 9 Nov 2022 [BitMEX Provides Snapshot Update to Bitcoin Proof of Reserves & Proof of Liabilities](https://blog.bitmex.com/bitmex-provides-snapshot-update-to-proof-of-reserves-proof-of-liabilities/)


### Installation

You may wish to switch to a Python virtual environment first.

```
$ python -m venv venv
$ . venv/bin/activate
$ pip3 install -r requirements.txt
```

To validate reserves you will require a running bitcoin daemon, with a reachable RPC server, dedicated to this task.

## Reserves

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
$ python3 validate_reserves.py --proof testnet_reserves.yaml --rpcauth username:password 127.0.0.1 --rpcport 18332
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
$ python3 validate_reserves.py --reconsider --rpcauth username:password --rpcport 18332
INFO:root:Reconsidering blocks and exiting.
```

Note that the RPC server port default is different for different networks: 8332(mainnet), 18332(testnet).
Note that Bitcoin Core supports 'pruning' block undo data beyond a certain depth. It is highly recommended
that this tool is run against an unpruned bitcoind, otherwise the script may fail if it tries to rewind deeper than pruning allows.

## Liabilities

We provide a tool in two parts, firstly to generate and secondly to verify a custom implementation of [Maxwell Proof of Liabilities](https://eprint.iacr.org/2018/1139.pdf) using a novel blinding approach to make user balances pseudonymous.

### Creation of Liabilities

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

Next all user balances are split ("blinded") into multiple parts, with the ratio of the split determined by a random number generator, thereby information about the distribution of account balances, and active users over time on the participating platform is no longer revealed. The parts are shuffled into a random order.

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
    85b0a83970a74a6ad0ee5d4bec5d3afe0048d18b8342e31e2d3a45e0f17879c7,4000004000
    4e6661db50e4ec1c42204c471c0a6fa2a8749127368f3358c340752208b160c9,963611993
    128b3b2bd3f6bde35d5ac2ba0a37def53fad7a607e6cdd76ee4ad39472b44447,3036392007
    448e972f7919df255c250b61d6ae1ea165f94cae229f3f610359ae0e2e63acb9,963610699
    bfa7eddb8a0a00f8e1eda939c41eaba51f9555b32d45b6f5828bca3950eea31f,1294
    51fb2bcf79c0439694c391960cfc0838db369b6fb2687c1fd4636476a2c34ca7,2039
    9649f6034051c9c81e3d246ae90473da35a8c02b4321c1b61436b75da139cf53,3036389968
    69c492be8d5b1f3cc507047460cabc116495e03fa6c76a7767655a94c2b9ae4f,963610032
    acb9b9fb9ae63ae09927dac870fa203d0113dade58f20a9855193b121d3ed035,667
    cbcdfae2f947e2b5b7dc2268f0f02f230867b77a0742940af16eff46f457a10e,0
    003c7fc49a6a476894dd6edfca066d5e3fe01cc63906214134fb6e2ee06a7d83,1294
    4c28a5dda0bb0dc42af1d942ea12b1f5fe1e3a22049de33166262c724363df63,333
    2150701b63061ebffa09aa4a0fb239fd59143e6f7ba7cdec3714412d09b97db3,1706
    f7c28544e2beb1abe170ca4d1aa177236f8e43383c2e83420bcbe8375aa4ba9b,1543636957
    943f858e804d09d241b05c9d063030da551ca4bde5133b303c8f23a4b76a5fde,1492753011

    $ cat nonces.txt
    2,b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
    3,38de14dcd1425739ddbe2bcf7505c1bac602fd185727dc7f2fa9ddaeff9a36c9
    1,4b014f71332f674b47ccec77ac055c7f6e94f7968afe15b9ffb63b9c392ee97a
    4,b4fb0f6cb39e1b47e159996d54121309d92fed531a4f55b7a30772cb5f21cf8a
    5,239573aae4710e1c1d09ffdf9de67a031176318a5caa901897183014776d607a

The liabilities output can now be made public, the nonces can be disclosed to each user individually. The output of `generation_liabilities.py` contains one line per tree node. The tree is published root first, then left child, then right
child, then one level down starting with left-most child in that row, etc.


NOTE: child node values are commmitted to individually to avoid [specific attacks](https://eprint.iacr.org/2018/1139.pdf) the prover could engage in on the original scheme proposed.

### Validation tool

Validation requires Python 3.7 and above.

We will run as user `2` above, who has been communicated the account nonce `b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412`.

    % python3 validate_liabilities.py --proof liabilities-100-proof.csv --account 2 --account_nonce b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
    Number of leaf nodes to scan 8
    Hash match for leaf 3 claims 1,294 sats
    Hash match for leaf 5 claims 1,706 sats
    Validated 3,000 satoshis for account 2, total liabilities 4,000,004,000

More verbose modes are also available, see help for details: --print-tree --print-proof-csv

The input file assumes the following CSV header: `account, amount`. Each line corresponds to a leaf in the Merkle sum tree.
Accounts are non-negative integers, serialized as 8-byte unsigned integers. Leaves are shuffled prior to tree generation
as well as balance splitting to ensure the privacy of our users. The user runs `validate_liabilities.py` with
the user-specific `--account` and `--nonce` fields that are served to them through their web account or BitMEX API.
This will decode the amount of value under their account and allow the user to check the root hash against other
users' version of the hash. Note that nonce is assumed to be a 32-byte hex encoded string, unique per proof.


# Issues?

The output's "total liabilities" value can be directly compared against the proved reserves value to give assurances about
solvency. If a user is unable to prove their subbalance's inclusion in this total value, please contact us at https://www.bitmex.com/contact for resolution.

