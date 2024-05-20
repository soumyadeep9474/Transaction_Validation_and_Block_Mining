# Blockchain Transaction Validator and Miner
This project is a blockchain transaction validator and miner implemented in Rust. It validates various types of Bitcoin transactions, assembles blocks, and mines new blocks.

## Overview
This project includes functionalities to:

* Fetch transactions from the mempool

* Validate transactions

* Mine new blocks

* Write mined blocks to a file

## Project Structure
```
├── src
│   ├── main.rs                   // consensus mechanism and proof-of-work implementation
│   ├── transaction_loader.rs     // transaction data fetching
│   ├── transaction_validator.rs  // transaction validation logic 
│                    
├── Cargo.toml
└── README.md
```
## Block Diagram
### Overview
The following diagram represents the main components and flow of the blockchain application, from fetching transactions to writing the mined block to a file.
```
+-----------------------------------+
| Fetch Transactions from Mempool   |
| Module: transaction_loader        |_______
| Function: fetch_transactions_from_mempool |
+-------------------------------------------+
                |
                v
+-----------------------------------+
| Validate Transactions             |
| Module: transaction_validator     |
| Function: validation_transaction  |
+-----------------------------------+
                |
                v
+-----------------------------------+
| Valid Transactions                |
+-----------------------------------+
                |
                v
+-----------------------------------+
| Mine Block                        |
| Function: mine_block              |
+-----------------------------------+
| Sub-functions:                    |
| - hashes_of_transactions          |
| - calculate_merkle_root           |
| - calculate_block_hash            |
| - merkle_damgard_util             |
| - sha256_compression              |
+-----------------------------------+
                |
                v
+-----------------------------------+
| Block Creation                    |
| Struct: Block                     |
| Function: Block::new              |
+-----------------------------------+
| Function: Block::to_output_string |
+-----------------------------------+
                |
                v
+-----------------------------------+
| Write to File                     |
| File: output.txt                  |_____
| Function: std::io::BufWriter::write_all |
+-----------------------------------------+
```
### Detailed Components
#### Transaction Loader

Module: `transaction_loader`

Function: `fetch_transactions_from_mempool`

---

#### Transaction Validator

Module: `transaction_validator`

Function: `validation_transaction`

Sub-functions:
- `verify_p2pkh_address`
- `verify_v0_p2wpkh_address`
- `verify_v0_p2wsh_address`
- `verify_v1_p2tr_address`
- `verify_p2sh_address`
- `verify_unknown`
- `verify_scriptsig_p2pkh`
- `verify_scriptsig_p2sh`
- `verify_witness_p2wpkh`
- `verify_witness_p2wsh`
---

#### Mine Block

Function: `mine_block`

Sub-functions:
- `hashes_of_transactions`
- `calculate_merkle_root`
- `calculate_block_hash`
- `merkle_damgard_util`
- `sha256_compression`
---

#### Block Creation

Struct: `Block`

Functions:
- `Block::new`
- `Block::to_output_string`
---

#### Write to File

File: `output.txt`

Function: `std::io::BufWriter::write_all`

## Usage
To use this project, follow these steps:

1) Clone the repository
2) Build the project using Cargo
3) Run the project to fetch transactions, validate them, mine a block, and write the block to a file
```
git clone <repository-url>
cd <repository-directory>
cargo build
cargo run
```

## Unit Tests
Unit tests are provided to verify the correctness of the functions. Run the tests using Cargo:
'''
cargo test
'''

## Conclusion
The blockchain transaction validator and miner is a comprehensive Rust project that demonstrates the process of fetching transactions, validating them, mining new blocks, and writing the mined blocks to a file. The modular design ensures that each component can be tested and maintained independently.
