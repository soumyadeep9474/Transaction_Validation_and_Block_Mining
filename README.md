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
.
├── src
│   ├── main.rs                   // consensus mechanism and proof-of-work implementation
│   ├── transaction_loader.rs     // transaction data fetching
│   ├── transaction_validator.rs  // transaction validation logic 
│                    
├── Cargo.toml
└── README.md

```
