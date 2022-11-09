# Tool Suite for Generating and Validating Proofs of Reserves(PoR) and Liabilities(PoL)

By running these validation tools, one can gain assurances that the sum of BTC deposits(reserves) is strictly
more than the sum of customer liabilities at a given timeframe.

### Installation

You may wish to switch to a Python virtual environment first.

```
$ pip3 install -r requirements.txt
```

To validate reserves you will require a running bitcoin daemon, with a reachable RPC server, dedicated to this task.

## Reserves

This tool will intake a proof file showing all BitMEX scripts, rewind the bitcoind's state to the stated height, and outputs the amount
of verified BTC under the control of the stated keys at that block height. You must validate yourself that the public keys belong to BitMEX!

* Grab mainnet reserves dataset from: https://public.bitmex.com/?prefix=data/porl/
* Grab testnet reserves dataset from: https://public-testnet.bitmex.com/?prefix=data/porl/

### ⚠️ Warning ⚠️

NOTE: You are required to be running a bitcoind node v0.21 or higher.
Running `validate_reserves.py` will modify your bitcoind's chainstate by invaliding a block to cause a local rewind. While designed to be recoverable, ensure you have *no other* services using the bitcoind at the same time, or they too will observe a chain rewind.
Validation may take a long time to complete, 30 minutes or longer.

You should run this on a local node that you can control, and then reset the chainstate after doing so.

You may need to run the script multiple times if Bitcoin Core RPC becomes unexpectedly unresponsive due to the load while rewinding blocks.
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

This pair of tools generate and validate a custom implementation of [Maxwell Proof of Liabilities](https://eprint.iacr.org/2018/1139.pdf).
Validation requires Python 3.7 and above.

Effectively BitMEX runs this internally, using our account balances to create the proof file.
The tool maintains a nonce for each user in `nonces.txt`, stable between proofs.

```
$ # Run by BitMEX to compile the merkle proofs and generated nonces for decrypting leaves
$ python3 generate_liabilities.py --liabilities liabilities-100-20210225D150000099012000.csv --blockheight 100 > liabilities-100-proof.dat
$ cat nonces.txt
...
350078,b88860add96111d84d38a500266df715158f91375d9aaa98aa58356f9a872412
350082,38de14dcd1425739ddbe2bcf7505c1bac602fd185727dc7f2fa9ddaeff9a36c9
350084,5def3d7f4394d7f8b462e28d7b0e99554ee023d92c4e587ebd7d0cfb09d7cc05
...
```

We then write the output file (`liabilities-100-proof.dat`) to the URLs given above:

```
$ # Run by BitMEX users to validate their own branches of the merkle proof
$ python3 validate_liabilities.py --proof liabilities-100-proof.dat --account 350082 --nonce 38de14dcd1425739ddbe2bcf7505c1bac602fd185727dc7f2fa9ddaeff9a36c9
Number of leaf nodes to scan 524288
Hash match for leaf 120974 claims 104,741 sats
Hash match for leaf 483170 claims 895,263 sats
Validated 1,000,004 in satoshis for account 350082, total liabilities 20,361,487,836,260

# More verbose modes are also available, see help for details: --print-tree --print-proof-csv

```

The input file assumes the following CSV header: `account, amount`. Each line corresponds to a leaf in the Merkle sum tree.
Accounts are non-negative integers, serialized as 8-byte unsigned integers. Leaves are shuffled prior to tree generation
as well as balance splitting to ensure the privacy of our users. The user runs `validate_liabilities.py` with
the user-specific `--account` and `--nonce` fields that are served to them through their web account or BitMEX API.
This will decode the amount of value under their account and allow the user to check the root hash against other
users' version of the hash. Note that nonce is assumed to be a 32-byte hex encoded string, unique per proof.
The output of the generation tool contains one line per tree node. The tree is published root first, then left child, then right
child, then one level down starting with left-most child in that row, etc.

### Design of Liabilities

Each user has their own account number internally within BitMEX. Each account is issued a single 32-byte nonce for the lifetime
of that account, with sub-nonces being derived per proof.  The merkle sum proof is a modified version of the [Maxwell Proof of Liabilities](https://bitcointalk.org/index.php?topic=595180.0) scheme,
where a Merkle Tree is used to prove to individual users that their liabilities are included in a published total liabilities number.

First, the leaves of the tree are calculated, all input values being serialized as 8-byte unsigned values, and leaf_value standing for satoshis:
```
sub_nonce = sha256(account_nonce||block_height,account_number)
leaf_digest = HMAC256(sub_nonce, leaf_value||leaf_index)
```

The account number, sub-nonce, and block height are all static per proof file. Block height ensures that every single proof "shuffles" the account nonce.
Leaf index allows the proof to include "sharded" account balances, where each user has multiple leaves, without revealing any patterns to third parties.

These leaves are then shuffled, and a binary tree constructed, node by node, again all 8-byte unsigned values, and values as satoshis:
```
node_digest = sha256(left_digest||left_value||right_digest||right_value)
```

Where left_value and right_value are the sums of those nodes' children's values as well. Therefore the root of the tree commits to the sum total of all liabilities of all the leaves!

NOTE: child node values are commmitted to individually to avoid [specific attacks](https://eprint.iacr.org/2018/1139.pdf) the prover could engage in on the original scheme proposed.

# Issues?

The output's "total liabilities" value can be directly compared against the proved reserves value to give assurances about
solvency. If a user is unable to prove their subbalance's inclusion in this total value, please contact us at https://www.bitmex.com/contact for resolution.

