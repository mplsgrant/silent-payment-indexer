# silent-payment-indexer
This is a classroom project aimed at increasing the understanding of Silent Payments.

Silent Payments help keep your Bitcoin balances more private. Today, if people send you Bitcoin using one of your Bitcoin addresses, all that money ends up grouped together on the public blockchain. That means people know how much money you received. Silent Payments make it so the money does not get grouped together. It is possible to manually avoid getting your money grouped together, but that requires making a new Bitcoin address every time someone pays you. Silent Payments do that automatically.

This indexer helps with Silent Payments by searching through the blockchain for your money. It needs a secret from you to perform the search, and I recommend not provding that secret unless you know what you are doing. Afterall, this is just a classroom project.

# WIP Items
- [ ] Update tests to match the [current standard](https://github.com/bitcoin/bips/pull/1458#issuecomment-2013462784)
- [ ] Scan with libbitcoinkernel
- [ ] Scan with leveldb
- [ ] Scan with RPC
- [ ] Simplify scanning types
- [x] Run all recommneded tests for receiving
- [x] Add all tagged hashes
- [x] Run all recommended tests against pubkey extraction
- [x] Extract pubkeys from relevant txn type w/ basic testing
  - [x] p2pkh
  - [x] p2sh-p2wpkh
  - [x] p2wpkh
  - [x] p2tr

# Questions
- Labels for change: Will the m=0 labeled addresses look like a change addresses to nosy observers?
- Does declaring H as the blessed Nothing Up My Sleeves (NUMS) number reveal too much info? What if we did NUMS + hash

# Diagram

```
 ┏━━━━━━━━━━┱────────────╮           An outpoint - the transaction hash and its
 ┃ Outpoint ┃ txid, vout │           specific vout index.
 ┗━━━━━━━━━━┹────────────╯
 ┏━━━━━━━━━━┱────────────────────╮
 ┃ Sig Data ┃ scriptSig, witness │
 ┗━━━━━━━━━━┹────────────────────╯
 ┏━━━━━━━━━━┱──────────────────────╮ Trannsaction Output. The private key must
 ┃ TxOut    ┃ amount, scriptPubKey │ be able to sign the public key contained
 ┗━━━━━━━━━━┹──────────────────────╯ within.

╭───────────────────────────────────────────────────────────────────────────────╮
│ Alice has UTXOs, and she wants to spend them to an address that Bob can       │
│ discover. Bob provides a public key to Alice in the form of a Silent Payment  │
│ Address.                                                                      │
│ Special Public Keypairs: p2pkh, p2sh-p2wkph, p2wpkh, p2tr                     │
│                                                                               │
│   ╭────── BIP0352/Inputs Tagged Hash ───────╮                                 │
│   │Smallest Outpoint | ∑ Special Public Keys│                                 │
│   ╰─────────────────────────────────────────╯                                 │
│                                                                               │
│   ╭────── ECDH Shared Secret ────────────────────────────────────────────╮    │
│   │BIP0352/Inputs Tagged Hash * ∑ Special Private Keys * Bob's Public Key│    │
│   ╰──────────────────────────────────────────────────────────────────────╯    │
│                                                                               │
╰───────────────────────────────────────────────────────────────────────────────╯
```

# Out links
[Bitcoin Core PR Review Club](https://bitcoincore.reviews/28122)
