use serde::{Deserialize, Serialize};
use std:: fs;
use rayon::prelude::*;

/// Represents a transaction input.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    pub prevout: Prevout,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    #[serde(default)]
    pub witness: Option<Vec<String>>,
    pub sequence: u32,
    #[serde(default)]
    pub is_coinbase: bool,
    #[serde(default)]
    pub inner_redeemscript_asm: String,
    #[serde(default)]
    pub inner_witnessscript_asm: String,
}
/// Represents the previous output of a transaction input.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Prevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: i64,
}

/// Represents a transaction output.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Vout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: i64,
}

/// Represents a transaction.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Transaction {
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    #[serde(default)]
    pub is_coinbase: bool,
}

//calculate transaction fee
pub fn calculate_transaction_fee(transaction: &Transaction) -> i64 {
    // Calculate total input fee
    let input_fee: i64 = transaction
        .vin
        .iter()
        .map(|vin| vin.prevout.value)
        .sum();

    // Calculate total output fee
    let output_fee: i64 = transaction
        .vout
        .iter()
        .map(|vout| vout.value)
        .sum();

    // Subtract output fee from input fee to get transaction fee
    if input_fee >= output_fee {
        input_fee - output_fee
    } else {
        -1 // Transaction is invalid, input fee is less than output fee
    }
}
pub fn fetch_transactions_from_mempool() -> Vec<Transaction> {
    let transactions: Vec<Transaction> = fs::read_dir("./mempool")
        .unwrap()
        .par_bridge() // parallel processing
        .filter_map(|entry| {
            if let Ok(entry) = entry {
                if let Ok(json_data) = fs::read_to_string(entry.path()) {
                    serde_json::from_str::<Transaction>(&json_data).ok()
                } else {
                    None
                }
            } else {
                None
            }
        })
        .filter(|transaction| calculate_transaction_fee(transaction) != -1)
        .collect();

    // Sort transactions in descending order of transaction fees
    let mut sorted_transactions = transactions;
    sorted_transactions.par_sort_unstable_by_key(|transaction| {
        let fee = calculate_transaction_fee(transaction);
        std::cmp::Reverse(fee)
    });

    sorted_transactions
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_transactions_from_mempool() {
        let transactions = fetch_transactions_from_mempool();
       
        //Print the first transaction for verification
        if let Some(first_transaction) = transactions.first() {
            println!("First transaction: {:?}", first_transaction);
            println!("{:?}", calculate_transaction_fee(first_transaction));
        } else {
            println!("No transactions loaded.");
        }
        // Print the number of transactions loaded
        println!("Number of transactions loaded: {}", transactions.len());
        //Assert that transactions are not empty
        assert!(!transactions.is_empty());
    }

    #[test]
    fn test_transaction_fee() {
        // Create a test transaction
        let mut transaction = Transaction {
            version: 1,
            locktime: 0,
            vin: Vec::new(),
            vout: Vec::new(),
            is_coinbase: false,
        };
        // Add sample input and output values
        transaction.vin.push(Vin {
            txid: String::from("input_txid"),
            vout: 0,
            prevout: Prevout {
                scriptpubkey: String::new(),
                scriptpubkey_asm: String::new(),
                scriptpubkey_type: String::new(),
                scriptpubkey_address: String::new(),
                value: 10000, // Input value
            },
            scriptsig: String::new(),
            scriptsig_asm: String::new(),
            witness: None,
            sequence: 0,
            is_coinbase: false,
            inner_redeemscript_asm: String::new(),
            inner_witnessscript_asm: String::new(),
        });
        transaction.vout.push(Vout {
            scriptpubkey: String::new(),
            scriptpubkey_asm: String::new(),
            scriptpubkey_type: String::new(),
            scriptpubkey_address: String::new(),
            value: 9000, // Output value
        });
        // Calculate transaction fee
        let fee = calculate_transaction_fee(&transaction);
        // Print the transaction fee
        println!("Transaction fee: {:?}", fee);
    }
}
