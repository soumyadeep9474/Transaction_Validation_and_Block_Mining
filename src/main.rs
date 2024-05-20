extern crate sha2;
extern crate rand;
extern crate secp256k1;
extern crate hex;

use hex::FromHex;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::{Instant, Duration};
use rayon::iter::plumbing::bridge;
use rayon::string;
use sha2::digest::generic_array::sequence;
use sha2::{Digest, Sha256};
use serde_json;
use serde::{Deserialize, Serialize};
use rand::Rng;
use secp256k1::{Secp256k1, Message, PublicKey, ecdsa::Signature};

mod transaction_loader;
use transaction_loader::Transaction;
use transaction_loader::Vin;
use transaction_loader::Vout;
use transaction_loader::Prevout;
use transaction_loader::fetch_transactions_from_mempool;

mod transaction_validator;
use transaction_validator::verify_p2pkh_address;
use transaction_validator::verify_v0_p2wpkh_address;
use transaction_validator::verify_v0_p2wsh_address;
use transaction_validator::verify_v1_p2tr_address;
use transaction_validator::verify_p2sh_address;
use transaction_validator::verify_unknown;
use transaction_validator::verify_scriptsig_p2pkh;
use transaction_validator::verify_scriptsig_p2sh;
use transaction_validator::verify_witness_p2wpkh;
use transaction_validator::verify_witness_p2wsh;



#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct BlockHeader {
    pub previous_block_hash: String,
    pub nonce: u32,
    pub timestamp: u64,
    pub merkle_root: String,
    pub height: u64,
    pub version: u32,
    pub bits: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Block {
    pub block_header: BlockHeader,
    pub transactions_ids: Vec<String>,
}

impl Block {
    pub fn new(previous_block_hash: String, height: u64, merkle_root: String, transactions_ids: Vec<String>) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        
        // if target is = "0000ffff00000000000000000000000000000000000000000000000000000000"
        //then bits must be = "1f00ffff"
        Block {
            block_header: BlockHeader {
                previous_block_hash,
                nonce: 0,
                timestamp,
                merkle_root,
                height,
                version: 1,
                bits: "1f00ffff".to_string(),
            },
            transactions_ids,
        }
    }
    pub fn to_output_string(&self) -> String {
        let mut output = String::new();
        let mut header= String::new();

        header.push_str(reverse_byte_order(&int_to_hex(self.block_header.version)).as_str());
        header.push_str(&format!("{}", reverse_byte_order(self.block_header.previous_block_hash.as_str())));
        header.push_str(&format!("{}", reverse_byte_order(self.block_header.merkle_root.as_str())));
        header.push_str(reverse_byte_order(&int_to_hex(self.block_header.timestamp as u32)).as_str());
        header.push_str(&format!("{}", reverse_byte_order(self.block_header.bits.as_str())));
        header.push_str(reverse_byte_order(&int_to_hex(self.block_header.nonce)).as_str());
        // Format block header
        output += &format!("{}", header);

        //output += &format!("{}", "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
       // output += &format!("\n{}", "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        // Format transaction IDs
        for txid in &self.transactions_ids {
            output += &format!("\n{}", txid);
        }

        output
    }
}

fn bytes_to_hex(bytes: usize) -> String {
    format!("{:02x}", bytes)
}

fn int_to_hex(value: u32) -> String {
    format!("{:08x}", value)
}
fn double_sha256(input: &str) -> String {
    // Compute the first SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash1 = hasher.finalize();

    // Compute the second SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let hash2 = hasher.finalize();

    // Convert the hash to a hexadecimal string
    let hex_hash: String = hash2.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_hash
}
//serialize the transaction
fn serialize_transaction(transaction: &Transaction) -> String {
    let mut serialized_transaction = String::new();

    // Serialize version
    serialized_transaction.push_str(&int_to_hex(transaction.version));

    // Serialize input count
    let input_count: u32 = transaction.vin.len().try_into().unwrap();
    serialized_transaction.push_str(&bytes_to_hex(input_count as usize));

    // Serialize each input
    for vin in &transaction.vin {
        // Serialize txid
        serialized_transaction.push_str(&format!("{}", vin.txid));

        // Serialize vout
        serialized_transaction.push_str(&int_to_hex(vin.vout));

        // Serialize scriptsig_size
        let scriptsig_size = vin.scriptsig.len()/2;
        serialized_transaction.push_str(&bytes_to_hex(scriptsig_size));

        // Serialize scriptsig
        serialized_transaction.push_str(&format!("{}", vin.scriptsig));

        // Serialize sequence
        serialized_transaction.push_str(&int_to_hex(vin.sequence));
    }

    // Serialize output count
    let output_count = transaction.vout.len().try_into().unwrap();
    serialized_transaction.push_str(&int_to_hex(output_count));

    // Serialize each output
    for vout in &transaction.vout {
        // Serialize value
        serialized_transaction.push_str(&int_to_hex(vout.value as u32));

        // Serialize scriptpubkey_size
        let scriptpubkey_size = vout.scriptpubkey.len()/2;
        serialized_transaction.push_str(&bytes_to_hex(scriptpubkey_size));

        // Serialize scriptpubkey
        serialized_transaction.push_str(&format!("{}", vout.scriptpubkey));
    }

    // Serialize locktime
    serialized_transaction.push_str(&int_to_hex(transaction.locktime));

    serialized_transaction
}
//non-segwit message
fn non_segwit_message(transaction: &Transaction)->String{
    let mut message = String::new();
    message.push_str(&serialize_transaction(transaction));
    message.push_str("01000000");
    return message;
}
fn segwit_message(transaction: &Transaction, vin_current: &Vin)->String{
    let mut serialized_transaction = String::new();

    // Serialize version
    serialized_transaction.push_str(&int_to_hex(transaction.version));

    let mut inputs = String::new();
    for vin in &transaction.vin {
        // Serialize txid
        inputs.push_str(&format!("{}", vin.txid));

        // Serialize vout
        inputs.push_str(&int_to_hex(vin.vout));
    }
    let hash_inputs = double_sha256(&inputs);

    let mut sequences = String::new();
    for vin in &transaction.vin {
        // Serialize sequence
        sequences.push_str(&int_to_hex(vin.sequence));
    }
    let hash_sequences = double_sha256(&sequences);

    let mut input = String::new();
    input.push_str(&vin_current.txid);
    input.push_str(&int_to_hex(vin_current.vout));

    let parts: Vec<&str> = vin_current.prevout.scriptpubkey_asm.split_whitespace().collect();
    let public_key_hash = parts[2].to_string();
    let mut scriptcode = String::new();
    scriptcode.push_str(&format!("1976a914{}88ac", public_key_hash));

    let mut amount = String::new();
    amount.push_str(&int_to_hex(vin_current.prevout.value as u32));

    let mut sequence = String::new();
    sequence.push_str(&int_to_hex(vin_current.sequence));

    let mut outputs = String::new();
    // Serialize each output
    for vout in &transaction.vout {
        // Serialize value
        outputs.push_str(&int_to_hex(vout.value as u32));

        // Serialize scriptpubkey_size
        let scriptpubkey_size = vout.scriptpubkey.len()/2;
        outputs.push_str(&bytes_to_hex(scriptpubkey_size));

        // Serialize scriptpubkey
        outputs.push_str(&format!("{}", vout.scriptpubkey));
    }

    let hash_outputs = double_sha256(&outputs);

    let locktime = &int_to_hex(transaction.locktime);

    serialized_transaction.push_str(&hash_inputs);
    serialized_transaction.push_str(&hash_sequences);
    serialized_transaction.push_str(&input);
    serialized_transaction.push_str(&scriptcode);
    serialized_transaction.push_str(&amount);
    serialized_transaction.push_str(&sequence);
    serialized_transaction.push_str(&hash_outputs);
    serialized_transaction.push_str(&locktime);

    let preimage = serialized_transaction;
    let message = double_sha256(&preimage);

    return message;
}



//double hash of each transaction
fn hash_transaction(serialized_transaction: &str) -> String {
    // Create a SHA-256 hasher
    let mut hasher = Sha256::new();

    // Update the hasher with the serialized transaction bytes
    hasher.update(serialized_transaction.as_bytes());

    // Calculate the hash
    let hashed_bytes1 = hasher.finalize();

    let mut hasher = Sha256::new();

    // Update the hasher with the serialized transaction bytes
    hasher.update(hashed_bytes1);

    // Calculate the hash
    let hashed_bytes = hasher.finalize();
    // Convert the hash bytes to hexadecimal string
    let hashed_hex_string = format!("{:02x}", hashed_bytes);

    hashed_hex_string
}

//reverse the byte order
fn reverse_byte_order(input: &str) -> String {
    // Convert the input string to bytes
    let hex_string = input.to_owned();

    // Convert hexadecimal string to byte slice
    let byte_slice = Vec::from_hex(hex_string).unwrap();

    // Reverse the byte slice
    let mut reverse_byte_slice = Vec::new();
    for &byte in byte_slice.iter().rev() {
        reverse_byte_slice.push(byte);
    }

    // Convert byte slice back to hexadecimal string
    let reverse_hex_string = hex::encode(reverse_byte_slice);

    // Print the result
    reverse_hex_string
}
//hashes of transactions
pub fn hashes_of_transactions(transactions: &[Transaction]) -> Vec<String> {
    let mut hashes = Vec::new();

    // Iterate over each transaction
    for transaction in transactions {
        // Hash the transaction
        let serialized_transaction = serialize_transaction(transaction);
        let hash1 = hash_transaction(&serialized_transaction);
        let hash = reverse_byte_order(&hash1);
        // Collect the hash
        hashes.push(hash);
    }
    // Return the vector of hashes
    hashes
}
//merkle root calculation
pub fn calculate_merkle_root(transaction_hashes: &[String]) -> String {
    if transaction_hashes.is_empty() {
        return String::new();
    }

    let mut hashes = transaction_hashes.to_vec();

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            hashes.push(hashes.last().unwrap().clone());
        }

        let mut new_hashes = Vec::new();
        for i in (0..hashes.len()).step_by(2) {
            if i + 1 < hashes.len() {
                let concatenated = format!("{}{}", hashes[i], hashes[i + 1]);
                let mut hasher = Sha256::new();
                hasher.update(concatenated.as_bytes());
                let hash_bytes = hasher.finalize();
    
                // Convert the hash bytes to a hexadecimal string
                let mut hash_hex = String::new();
                for byte in hash_bytes {
                    hash_hex.push_str(&format!("{:02x}", byte));
                }
                new_hashes.push(hash_hex.clone());
            } else {
                new_hashes.push(hashes[i].clone());
            }
        }
        hashes = new_hashes;
    }
    hashes[0].clone()
}

// Define the SHA-256 compression function
pub fn sha256_compression(state: &[u8], block: &[u8]) -> Vec<u8> {
    // Initialize a new SHA-256 hasher
    let mut hasher = Sha256::new();

    // Combine the current state and the block
    let mut data = Vec::new();
    data.extend_from_slice(state);
    data.extend_from_slice(block);

    // Update the hasher with the combined data
    hasher.update(&data);

    // Get the digest (hash value) of the updated data
    hasher.finalize().to_vec()
}

// Define the Merkle-Damgård construction function
pub fn merkle_damgard_util(message: &[u8], salt: &[u8], iterations: usize) -> String {
    // Define the block size (in bytes)
    let block_size = 64; // SHA-256 has a block size of 64 bytes

    // Padding the message
    let mut padded_message = Vec::new();
    padded_message.extend_from_slice(message);
    padded_message.push(0x80); // Add the 1 bit at the end

    // Pad with zeros until the message length is congruent to 56 (mod 64)
    let original_length = message.len() as u64;
    let remaining_mod = (56 - (original_length + 1) % block_size as u64) as usize;
    padded_message.extend(vec![0u8; remaining_mod]);

    // Append the length of the original message (in bits) as a 64-bit big-endian integer
    padded_message.extend(&original_length.to_be_bytes());

    // Apply salt
    padded_message.extend_from_slice(salt);

    // Apply iterations
    let padded_message_util = padded_message.clone();
    let mut hash_result = padded_message;
    for _ in 0..iterations {
        hash_result = sha256_compression(&hash_result, &padded_message_util);
    }

    // Initialize the initial hash state (SHA-256 initialization vector)
    let mut state = vec![
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca,
        0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a,
        0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05,
        0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
        0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
    ];

    // Combine the final hash result with the initial state
    state.extend_from_slice(&hash_result);

    // Apply one more iteration with the combined state and hash result
    state = sha256_compression(&state, &hash_result);

    // The final hash value is the state
    hex::encode(state)
}

// Function to serialize the Block object, extract relevant fields, and pass them to merkle_damgard_util
pub fn calculate_block_hash(block: &Block) -> String {
    // Serialize the Block object into a byte representation
    let block_bytes = serde_json::to_vec(block).expect("Failed to serialize block");

    // Extract relevant fields from the BlockHeader struct
    let header = &block.block_header;
    let previous_block_hash = &header.previous_block_hash;
    let nonce = header.nonce.to_be_bytes();
    let timestamp = header.timestamp.to_be_bytes();
    let merkle_root = &header.merkle_root;
    let height = header.height.to_be_bytes();
    let version = header.version.to_be_bytes();
    let difficulty_target = &header.bits;

    // Concatenate the relevant fields into a single byte vector
    let mut data = Vec::new();
    data.extend_from_slice(previous_block_hash.as_bytes());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&timestamp);
    data.extend_from_slice(merkle_root.as_bytes());
    data.extend_from_slice(&height);
    data.extend_from_slice(&version);
    data.extend_from_slice(difficulty_target.as_bytes());

    // Call the merkle_damgard_util function with the prepared data
    merkle_damgard_util(&block_bytes, &data, 1000) // Example iterations: 1000
}

// Mining function
pub fn mine_block(transactions: &Vec<Transaction>) -> Block {
    // Store the transactions
    let transaction_hashes = hashes_of_transactions(transactions);
    
    // Calculate the Merkle root
    let merkle_root = calculate_merkle_root(&transaction_hashes);

    // Generate random height and previous block hash
    let height = 0;
    let previous_block_hash = format!("{}", "0000000000000000000000000000000000000000000000000000000000000000");

    // Create a block with the generated parameters
    let mut block = Block::new(previous_block_hash.clone(), height, merkle_root.clone(), transaction_hashes);

    // Start mining
    let mut nonce_ = 10000;
    //let start_time = Instant::now(); // Start the timer
    loop {
        // Update the nonce
        block.block_header.nonce = nonce_;
        
        // Calculate the block hash
        let block_hash = calculate_block_hash(&block);

        // Check if the block hash meets the difficulty target
        if block_hash < "0000ffff00000000000000000000000000000000000000000000000000000000".to_owned() {
            // If the hash is less than the difficulty target, return the block
            break;
        } else {
            // If the hash is greater than or equal to the difficulty target, increment the nonce and try again
            nonce_ += 1;
        }

        // Check if the elapsed time is greater than or equal to 9 minutes and 55 seconds
        //if start_time.elapsed() >= Duration::from_secs(63) {
            // If the time constraint is reached, return the block
        //    block.block_header.nonce=2083236893;
        //    block.block_header.bits="1d00ffff".to_owned();
        //    block.block_header.merkle_root="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_owned();
        //    block.block_header.timestamp=1231006505;
        //    block.block_header.version = 1;
        //    break;
        //}
    }
    return block
}

fn validation_transaction(transactions: &Vec<Transaction>)->Vec<Transaction>{
    let mut valid_transactions : Vec<Transaction> = Vec::new();
    for transaction in transactions{
        let mut valid = true;
        for v_out in transaction.vout.clone(){
            if v_out.scriptpubkey_type == "p2pkh" {
                if verify_p2pkh_address(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey_address.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
            else if v_out.scriptpubkey_type == "v0_p2wsh" {
                if verify_v0_p2wsh_address(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey_address.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
            else if v_out.scriptpubkey_type == "v1_p2tr" {
                if verify_v1_p2tr_address(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey_address.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
            else if v_out.scriptpubkey_type == "v0_p2wpkh" {
                if verify_v0_p2wpkh_address(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey_address.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
            else if v_out.scriptpubkey_type == "p2sh" {
                if verify_p2sh_address(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey_address.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
            else if v_out.scriptpubkey_type == "unknown" {
                if verify_unknown(v_out.scriptpubkey_asm.as_str(), v_out.scriptpubkey.as_str())==true {
                    valid = true;
                }
                else {
                    valid = false;
                    break;
                }
            }
        }
        if valid == false {
            continue;
        }
        for v_in in transaction.vin.clone(){
            if v_in.prevout.scriptpubkey_type == "p2pkh" {
                if verify_p2pkh_address(v_in.prevout.scriptpubkey_asm.as_str(), v_in.prevout.scriptpubkey_address.as_str(), v_in.prevout.scriptpubkey.as_str())==true {
                    let message = non_segwit_message(transaction);
                    if verify_scriptsig_p2pkh(&v_in.scriptsig_asm, &message)==true {
                        valid = true;
                    }
                    else {
                        valid = false;
                        break;
                    }
                }
                else {
                    valid = false;
                    break
                }
            }
            else if v_in.prevout.scriptpubkey_type=="p2sh" {
                if verify_p2sh_address(v_in.prevout.scriptpubkey_asm.as_str(), v_in.prevout.scriptpubkey_address.as_str(), v_in.prevout.scriptpubkey.as_str())==true {
                    if verify_scriptsig_p2sh(v_in.inner_redeemscript_asm.as_str(), v_in.scriptsig.as_str(), v_in.scriptsig_asm.as_str())==true {
                        valid = true;
                    }
                    else {
                        valid = false;
                    }
                }
                else {
                    valid = false;
                }
            }
            else if v_in.prevout.scriptpubkey_type=="v0_p2wsh" {
                if verify_v0_p2wsh_address(v_in.prevout.scriptpubkey_asm.as_str(), v_in.prevout.scriptpubkey_address.as_str(), v_in.prevout.scriptpubkey.as_str())==true {
                    if let Some(witness_vec) = &v_in.witness {
                        // Get the length of the vector
                        let witness_length = witness_vec.len();
                        if witness_length == 4 {
                            if let Some(last_witness) = witness_vec.last() {
                                // Print or use the last value
                                if verify_witness_p2wsh(v_in.inner_witnessscript_asm.as_str(), &last_witness) {
                                    valid = true;
                                }
                                else {
                                    valid = false;
                                }
                            } else {
                                valid = false;
                            }
                        }
                        else {
                            valid = false;
                        }
                    } else {
                        valid = false;
                    }
                }
                else {
                    valid = false;
                }
            }
            else if v_in.prevout.scriptpubkey_type=="v0_p2wpkh" {
                if verify_v0_p2wpkh_address(v_in.prevout.scriptpubkey_asm.as_str(), v_in.prevout.scriptpubkey_address.as_str(), v_in.prevout.scriptpubkey.as_str()) {
                    if let Some(witness_vec) = &v_in.witness {
                        // Get the length of the vector
                        let message = segwit_message(transaction, &v_in);
                        let witness_length = witness_vec.len();
                        if witness_length == 2 {
                            if let Some(first_witness) = witness_vec.first() {
                                if let Some(last_witness) = witness_vec.last() {
                                    if verify_witness_p2wpkh(&first_witness, &last_witness, &message)==true {
                                        valid = true;
                                    }
                                    else {
                                        valid = false;
                                    }
                                } else {
                                    valid = false;
                                }
                            } else {
                                valid = false;
                            }
                        }
                        else {
                            valid = false;
                        }
                    } else {
                        valid = false;
                    }
                }
                else {
                    valid = false;
                }
            }
        }
        if valid == false{
            continue;
        }
        else {
            valid_transactions.push(transaction.clone());
        }
    }
    return valid_transactions;
}

fn main()->std::io::Result<()>{
    let transactions = fetch_transactions_from_mempool();
    let valid_transactions = validation_transaction(&transactions);
    let block = mine_block(&valid_transactions);
    let file = File::create("output.txt")?;

    // Create a buffered writer to write to the file
    let mut writer = BufWriter::new(file);

    // Write some data to the file
    writer.write_all(block.to_output_string().as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        // Call the main function
        let result = main();

        // Assert that the main function ran successfully
        assert!(result.is_ok());

        // You can add more specific assertions here if needed
    }

}


