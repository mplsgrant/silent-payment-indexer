# silent-payment-indexer
This is a classroom project aimed at increasing the understanding of Silent Payments.

Silent Payments help keep your Bitcoin balances more private. Today, if people send you Bitcoin using one of your Bitcoin addresses, all that money ends up grouped together on the public blockchain. That means people know how much money you received. Silent Payments make it so the money does not get grouped together. It is possible to manually avoid getting your money grouped together, but that requires making a new Bitcoin address every time someone pays you. Silent Payments do that automatically.

This indexer helps with Silent Payments by searching through the blockchain for your money. It needs a secret from you to perform the search, and I recommend not provding that secret unless you know what you are doing. Afterall, this is just a classroom project.

# WIP Items
- [ ] Extract pubkeys from relevant txn type
  - [x] p2pkh
  - [x] p2sh-p2wpkh
  - [ ] p2wpkh
  - [ ] p2tr
