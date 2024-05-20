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
