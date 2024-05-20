extern crate hex;
extern crate bs58;
extern crate sha2;
extern crate bech32;
extern crate secp256k1;

use secp256k1::{Secp256k1, PublicKey,Message, ecdsa::Signature, Error};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use bech32::primitives::decode::{CheckedHrpstring, SegwitHrpstring};
use bech32::{hrp, segwit, Hrp, Bech32m};
use std::fmt;


// SHA-256 hash function
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

// Ripemd-160 hash function
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    hasher.finalize().into()
}

// Convert a byte slice to a base58check-encoded string
pub fn to_base58check(bytes: &[u8]) -> String {
    let mut data = vec![0; 1 + bytes.len() + 4];
    data[1..1 + bytes.len()].copy_from_slice(bytes);
    let checksum = &sha256(&sha256(&data[0..1 + bytes.len()]))[0..4];
    data[1 + bytes.len()..].copy_from_slice(checksum);
    bs58::encode(data).into_string()
}

// Function to calculate double SHA256 hash
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&result1);
    hasher.finalize().into()
}

// Base58 encoding
pub fn base58_encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
}

pub enum Opcode {
    OpDup,
    OpHash160,
    OpPushbytes20,
    OpEqualverify,
    OpChecksig,
}

// Implement the Display trait for Opcode
impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opcode::OpDup => write!(f, "76"),
            Opcode::OpHash160 => write!(f, "a9"),
            Opcode::OpPushbytes20 => write!(f, "14"),
            Opcode::OpEqualverify => write!(f, "88"),
            Opcode::OpChecksig => write!(f, "ac"),
        }
    }
}

// Function to assemble scriptPubKey bytecode
pub fn assemble_scriptpubkey(hash160_hex: &str) -> String {
    let op_dup = Opcode::OpDup.to_string();
    let op_hash160 = Opcode::OpHash160.to_string();
    let op_pushbytes_20 = Opcode::OpPushbytes20.to_string();
    let op_equalverify = Opcode::OpEqualverify.to_string();
    let op_checksig = Opcode::OpChecksig.to_string();

    format!(
        "{}{}{}{}{}{}",
        op_dup, op_hash160, op_pushbytes_20, hash160_hex, op_equalverify, op_checksig
    )
}

pub fn verify_p2pkh_address(scriptpubkey_asm: &str, scriptpubkey_address: &str, scriptpubkey: &str)->bool{
    let mut is_valid = false;

    //operation with scriptpubkey_asm----------------------------------------------------------
    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    // Find the index of "OP_PUSHBYTES_32"
    let pushbytes32_index = parts.iter().position(|&x| x == "OP_PUSHBYTES_20");

    // If "OP_PUSHBYTES_32" is found, extract the next element which represents the bytes
    if let Some(index) = pushbytes32_index {
        if let Some(bytes_hex) = parts.get(index + 1) {
            // Convert hexadecimal string to bytes
            let bytecode = assemble_scriptpubkey(&bytes_hex);

            //println!("ScriptPubKey bytecode: {}", bytecode);

            // Derive the scriptPubKey address
            let version_prefix = [0x00]; // Mainnet version byte
            let mut hash160_bytes =
            hex::decode(bytes_hex).expect("Failed to decode hash160 hex string");
            let mut payload = version_prefix.to_vec();
            payload.append(&mut hash160_bytes);
            let checksum = double_sha256(&payload)[..4].to_vec();
            payload.extend_from_slice(&checksum);

            let derived_scriptpubkey_address = base58_encode(&payload);
            //println!("derived_scriptpubkey_address: {}", derived_scriptpubkey_address);

            is_valid = (bytecode == scriptpubkey)&&(derived_scriptpubkey_address == scriptpubkey_address);

        } else {
            println!("Scriptpubkey_asm does not contain bytes after OP_PUSHBYTES_32");
        }
    } else {
        println!("Scriptpubkey_asm does not contain OP_PUSHBYTES_32");
    }

    return is_valid;
}

pub fn verify_v0_p2wsh_address(scriptpubkey_asm: &str, scriptpubkey_address: &str, scriptpubkey: &str)->bool{
    
    let mut is_valid = false;

    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    let hash = parts[2]; // Corrected index to extract the hash
    let derive_scriptpubkey = format!("0020{}", &hash);
    //operation with scriptpubkey_asm----------------------------------------------------------
    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    // Find the index of "OP_PUSHBYTES_32"
    let pushbytes32_index = parts.iter().position(|&x| x == "OP_PUSHBYTES_32");

    // If "OP_PUSHBYTES_32" is found, extract the next element which represents the bytes
    if let Some(index) = pushbytes32_index {
        if let Some(bytes_hex) = parts.get(index + 1) {
            // Convert hexadecimal string to bytes
            let bytes_asm = hex::decode(bytes_hex).expect("Failed to decode bytes hex");

            //bech32 decoding operation of address------------------------------------------------------------------
            let (_hrp, _version, decoded_address) = segwit::decode(scriptpubkey_address).expect("valid address");
            
            is_valid = (decoded_address == bytes_asm)&&(derive_scriptpubkey==scriptpubkey);
        } else {
            println!("Scriptpubkey_asm does not contain bytes after OP_PUSHBYTES_32");
        }
    } else {
        println!("Scriptpubkey_asm does not contain OP_PUSHBYTES_32");
    }

    return is_valid;
}

pub fn verify_v1_p2tr_address(scriptpubkey_asm: &str, scriptpubkey_address: &str, scriptpubkey: &str)->bool{

    let mut is_valid = false;

    //operation with scriptpubkey-----------------------------------------------------------
    let scriptpubkey_bytes = hex::decode(scriptpubkey).expect("Failed to decode scriptpubkey hex");

    // Address derivation
    let pubkey_bytes = &scriptpubkey_bytes[2..34]; // Extract the 32-byte public key
    let pubkey_hash = Ripemd160::digest(&Sha256::digest(pubkey_bytes)); // Compute RIPEMD-160(SHA-256(public key))
    let version_byte = [0x0]; // Version byte for taproot addresses
    let address_bytes: Vec<u8> = [version_byte.to_vec(), pubkey_hash.to_vec()].concat();
    let address_base58_from_scriptpubkey = to_base58check(&address_bytes);

    //operation with scriptpubkey_asm----------------------------------------------------------
    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    // Find the index of "OP_PUSHBYTES_32"
    let pushbytes32_index = parts.iter().position(|&x| x == "OP_PUSHBYTES_32");

    // If "OP_PUSHBYTES_32" is found, extract the next element which represents the bytes
    if let Some(index) = pushbytes32_index {
        if let Some(bytes_hex) = parts.get(index + 1) {
            // Convert hexadecimal string to bytes
            let bytes_asm = hex::decode(bytes_hex).expect("Failed to decode bytes hex");

            //bech32 decoding operation of address------------------------------------------------------------------
            let (_hrp, _version, decoded_address) = segwit::decode(scriptpubkey_address).expect("valid address");
             
            // Perform RIPEMD-160(SHA-256(public key)) hashing
            let pubkey_hash_asm = ripemd160(&sha256(&bytes_asm));

            // Version byte for taproot addresses
            let version_byte = [0x0];

            // Concatenate version byte and pubkey hash
            let address_bytes_asm: Vec<u8> = [version_byte.to_vec(), pubkey_hash_asm.to_vec()].concat();

            // Encode the result using Base58Check encoding
            let address_base58_from_scriptpubkey_asm = to_base58check(&address_bytes_asm);

            is_valid = (address_base58_from_scriptpubkey == address_base58_from_scriptpubkey_asm)&&(decoded_address == bytes_asm);
            //println!("Derived Address: {}", address_base58);
        } else {
            println!("Scriptpubkey_asm does not contain bytes after OP_PUSHBYTES_32");
        }
    } else {
        println!("Scriptpubkey_asm does not contain OP_PUSHBYTES_32");
    }
    return is_valid;
}

pub fn verify_v0_p2wpkh_address(scriptpubkey_asm: &str, scriptpubkey_address: &str, scriptpubkey: &str)->bool{

    let mut is_valid = false;

    //operation eith scriptpubkey----------------------------------------------------------
    let scriptpubkey_bytes = hex::decode(scriptpubkey).expect("Failed to decode scriptpubkey hex");
    let hash_bytes = &scriptpubkey_bytes[2..];
    let hash_hex = hex::encode(hash_bytes);

    //operation with scriptpubkey_asm----------------------------------------------------------
    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    // Find the index of "OP_PUSHBYTES_32"
    let pushbytes32_index = parts.iter().position(|&x| x == "OP_PUSHBYTES_20");

    // If "OP_PUSHBYTES_32" is found, extract the next element which represents the bytes
    if let Some(index) = pushbytes32_index {
        if let Some(bytes_hex) = parts.get(index + 1) {
            // Convert hexadecimal string to bytes
            let bytes_asm = hex::decode(bytes_hex).expect("Failed to decode bytes hex");

            //bech32 decoding operation of address------------------------------------------------------------------
            let (_hrp, _version, decoded_address) = segwit::decode(scriptpubkey_address).expect("valid address");

            is_valid = (bytes_hex == &hash_hex)&&(decoded_address == bytes_asm);
            //println!("Derived Address: {}", address_base58);
        } else {
            println!("Scriptpubkey_asm does not contain bytes after OP_PUSHBYTES_32");
        }
    } else {
        println!("Scriptpubkey_asm does not contain OP_PUSHBYTES_32");
    }

    return is_valid
}

pub fn verify_p2sh_address(scriptpubkey_asm: &str, scriptpubkey_address: &str, scriptpubkey: &str)->bool{

    let mut is_valid = false;

    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    let hash = parts[2]; // Corrected index to extract the hash
    let derive_scriptpubkey = format!("a914{}87", &hash);
    // Split the string by whitespace
    let tokens: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

    // Find the index of "OP_PUSHBYTES_20"
    if let Some(index) = tokens.iter().position(|&x| x == "OP_PUSHBYTES_20") {
        // Extract the redeem script hash from the token following "OP_PUSHBYTES_20"
        if let Some(redeem_script_hash_hex) = tokens.get(index + 1) {
            let redeem_script_hash_bytes = hex::decode(redeem_script_hash_hex).unwrap();

            // Prepend network byte
            let network_byte: u8 = 0x05;
            let mut address_bytes = vec![network_byte];
            address_bytes.extend(redeem_script_hash_bytes.iter());

            // Calculate checksum
            let checksum = double_sha256(&address_bytes);
            address_bytes.extend_from_slice(&checksum[..4]);

            // Encode with Base58Check
            let address_from_asm = base58_encode(&address_bytes);
            is_valid = (address_from_asm==scriptpubkey_address)&&(scriptpubkey == derive_scriptpubkey);
        } else {
            println!("Unable to extract redeem script hash.");
        }
    } else {
        println!("OP_PUSHBYTES_20 not found.");
    }
    
    return is_valid;
}

pub fn verify_unknown(scriptpubkey_asm: &str, scriptpubkey: &str)->bool{
    let parts: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    let hash1 = parts[2]; 
    let hash2 = parts[4];
    let hash3 = parts[6];
    let derive_scriptpubkey = format!("5121{}21{}21{}53ae", &hash1, &hash2, &hash3);
    return derive_scriptpubkey==scriptpubkey;
}

//input verification
pub fn verify_scriptsig_p2pkh(scriptsig_asm: &str,message : &str) -> bool {
    // Parse scriptsig_asm
    let parts: Vec<&str> = scriptsig_asm.split_whitespace().collect();
    if parts.len() != 4 {
        println!("Invalid scriptsig_asm format");
        return false;
    }

    // Extract signature and public key
    let signature_hex = parts[1];
    let public_key_hex = parts[3];

    // Convert signature and public key to bytes
    let signature_bytes = hex::decode(signature_hex).unwrap();
    let public_key_bytes = hex::decode(public_key_hex).unwrap();

    // Create secp256k1 context
    let secp = Secp256k1::verification_only();

    // Convert signature and public key to their respective types
    //let signature = Signature::from_der(&signature_bytes).unwrap();
    let signature = match Signature::from_der(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let public_key = PublicKey::from_slice(&public_key_bytes).unwrap();

    // Define the message (replace this with your actual message bytes)
    let digest = double_sha256(message.as_bytes());
    let message = Message::from_digest(digest);


    // Verify the signature
    if secp.verify_ecdsa(&message,& signature,& public_key).is_ok()  {
        return true;
    } else {
        return false;
    }
}
// pub fn verify_witness_p2wpkh(signature_code: &str , public_key_code: &str, message : &str) -> bool{
//     let signature_bytes = hex::decode(signature_code).unwrap();
//     let public_key_bytes = hex::decode(public_key_code).unwrap();
//     // Create secp256k1 context
//     let secp = Secp256k1::verification_only();s

//     // Convert signature and public key to their respective types
//     let signature = Signature::from_der(&signature_bytes).unwrap();
//     let public_key = PublicKey::from_slice(&public_key_bytes).unwrap();

//     // Define the message (replace this with your actual message bytes)
//     let digest = double_sha256(message.as_bytes());
//     let message = Message::from_digest(digest);
//     // Verify the signature
//     if secp.verify_ecdsa(&message,& signature,& public_key).is_ok()  {
//         return true;
//     } else {
//         return false;
//     }
// }
pub fn verify_witness_p2wpkh(signature_code: &str, public_key_code: &str, message: &str) -> bool {
    // Decode hex strings into bytes
    let signature_bytes = hex::decode(signature_code);
    let public_key_bytes = hex::decode(public_key_code);

    // Check if decoding was successful, if not return false
    let (signature_bytes, public_key_bytes) = match (signature_bytes, public_key_bytes) {
        (Ok(sig), Ok(pub_key)) => (sig, pub_key),
        _ => return false,
    };

    // Create secp256k1 context
    let secp = Secp256k1::verification_only();

    // Convert signature and public key to their respective types
    let signature = match Signature::from_der(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let public_key = match PublicKey::from_slice(&public_key_bytes) {
        Ok(pub_key) => pub_key,
        Err(_) => return false,
    };

    // Calculate message digest
    let digest = double_sha256(message.as_bytes());
    let message = Message::from_digest_slice(&digest);

    // Verify the signature
    if let Ok(_) = secp.verify_ecdsa(&message.unwrap(), &signature, &public_key) {
        true
    } else {
        false
    }
}
//input p2sh
pub fn verify_scriptsig_p2sh(inner_redeemscript_asm: &str, scriptsig: &str, scriptsig_asm: &str)->bool{
    let redeemscript_last_part = inner_redeemscript_asm.split_whitespace().last().unwrap_or("");
    scriptsig.ends_with(redeemscript_last_part)&&scriptsig_asm.ends_with(redeemscript_last_part)
}
//input p2wsh
pub fn verify_witness_p2wsh(witness_script_asm: &str, witness_field_last_string: &str)->bool{
    let parts: Vec<&str> = witness_script_asm.split_whitespace().collect();
    // Check if parts at index 2 and index 4 exist and extract them
    if parts.len() >= 5 {
        let substring_2 = parts[2];
        let substring_4 = parts[4];
        
        // Check if the substrings are present in the last string of the witness field
        if witness_field_last_string.contains(substring_2) && witness_field_last_string.contains(substring_4) {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_p2pkh_address_valid1() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 dd6892bcbea5d56471d097923d1a81b773678d12 OP_EQUALVERIFY OP_CHECKSIG";
        let scriptpubkey_address = "1MBhcGWFxc434JW7qQQXanXAjsSjPQgJLh";
        let scriptpubkey = "76a914dd6892bcbea5d56471d097923d1a81b773678d1288ac";

        // Assert that the function returns true for a valid case
        assert!(verify_p2pkh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_p2pkh_address_valid2() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 6406723503f32089c16ad27f7acd0d15879b811d OP_EQUALVERIFY OP_CHECKSIG";
        let scriptpubkey_address = "1A7tJ4umxSBMfcJ4Cjh9sAeMkPKkSWx4DF";
        let scriptpubkey = "76a9146406723503f32089c16ad27f7acd0d15879b811d88ac";

        // Assert that the function returns true for a valid case
        assert!(verify_p2pkh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_v0_p2wsh_address_valid1() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_0 OP_PUSHBYTES_32 b5dc65e4c0f3a2fa836d379077034f0b18e675a49d242250d328adf822da500c";
        let scriptpubkey_address = "bc1qkhwxtexq7w304qmdx7g8wq60pvvwvadyn5jzy5xn9zklsgk62qxqr8jfah";
        let scriptpubkey = "0020b5dc65e4c0f3a2fa836d379077034f0b18e675a49d242250d328adf822da500c";

        // Assert that the function returns true for a valid case
        assert!(verify_v0_p2wsh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_v0_p2wsh_address_valid2() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_0 OP_PUSHBYTES_32 13bddba520865eba7745979edc231f5f4ad08e2d296db835f72cb2c384402b42";
        let scriptpubkey_address = "bc1qzw7ahffqse0t5a69j70dcgclta9dpr3d99kmsd0h9jev8pzq9dpqgpam8f";
        let scriptpubkey = "002013bddba520865eba7745979edc231f5f4ad08e2d296db835f72cb2c384402b42";

        // Assert that the function returns true for a valid case
        assert!(verify_v0_p2wsh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_v1_p2tr_address_valid1() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_PUSHNUM_1 OP_PUSHBYTES_32 dcbdb702f0831950fb0780047fbe7220d48103d128ad9f67f70e98ec7550f2a6";
        let scriptpubkey_address = "bc1pmj7mwqhssvv4p7c8sqz8l0njyr2gzq739zke7elhp6vwca2s72nq02vyyd";
        let scriptpubkey = "5120dcbdb702f0831950fb0780047fbe7220d48103d128ad9f67f70e98ec7550f2a6";

        // Assert that the function returns true for a valid case
        assert!(verify_v1_p2tr_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_v1_p2tr_address_valid2() {
        // Sample input data for an invalid case
        let scriptpubkey_asm = "OP_PUSHNUM_1 OP_PUSHBYTES_32 d4791f2aba1e55e57ab67b096de868d2c8a759b0033fba609a2c6c75867ed455";
        let scriptpubkey_address = "bc1p63u37246re27274k0vykm6rg6ty2wkdsqvlm5cy693k8tpn7632s8n5pdp";
        let scriptpubkey = "5120d4791f2aba1e55e57ab67b096de868d2c8a759b0033fba609a2c6c75867ed455"; 

        // Assert that the function returns false for an invalid case
        assert!(verify_v1_p2tr_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_v0_p2wpkh_address_valid1() {
        // Define test data with invalid scriptPubKey
        let scriptpubkey_asm = "OP_0 OP_PUSHBYTES_20 8e56a5479728f7786a6a8fc7cc0f3535cea91b52";
        let scriptpubkey_address = "bc1q3et223uh9rmhs6n23lrucre4xh82jx6jnukpcl";
        let scriptpubkey = "00148e56a5479728f7786a6a8fc7cc0f3535cea91b52"; 

        // Call the function under test
        let result = verify_v0_p2wpkh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey);

        // Assert the result is false
        assert!(result);
    }

    #[test]
    fn test_verify_v0_p2wpkh_address_valid2() {
        // Define test data with invalid scriptPubKey
        let scriptpubkey_asm = "OP_0 OP_PUSHBYTES_20 7a665de7a370f4c9b372ab1fae587500a5bcbdb4";
        let scriptpubkey_address = "bc1q0fn9mearwr6vnvmj4v06ukr4qzjme0d565dzcx";
        let scriptpubkey = "00147a665de7a370f4c9b372ab1fae587500a5bcbdb4"; 

        // Call the function under test
        let result = verify_v0_p2wpkh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey);

        // Assert the result is false
        assert!(result);
    }

    #[test]
    fn test_verify_p2sh_address_valid1() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_HASH160 OP_PUSHBYTES_20 20756d2dd9f0cc05fe200794251642ff9e760085 OP_EQUAL";
        let scriptpubkey_address = "34eeDckhVvGkbnTzGx6qbz2AkmyV9syc8R";
        let scriptpubkey = "a91420756d2dd9f0cc05fe200794251642ff9e76008587";

        // Assert that the function returns true for a valid case
        assert!(verify_p2sh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_p2sh_address_valid2() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_HASH160 OP_PUSHBYTES_20 88b45cfaf3fc202f120e194d469d699158b3b8c3 OP_EQUAL";
        let scriptpubkey_address = "3E9qtVFH8AnbzJCVXRhsXP4rzuwsmzpmpL";
        let scriptpubkey = "a91488b45cfaf3fc202f120e194d469d699158b3b8c387";

        // Assert that the function returns true for a valid case
        assert!(verify_p2sh_address(scriptpubkey_asm, scriptpubkey_address, scriptpubkey));
    }

    #[test]
    fn test_verify_unknown1() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_PUSHNUM_1 OP_PUSHBYTES_33 0271cf3589a4ff65dd3daa10e1c16bb573eafa46874575bd9ed215bf0fc215824d OP_PUSHBYTES_33 02214adba0ff718eb695b55694ba4fbf921cd587f62fdba757f5b93f646af9586a OP_PUSHBYTES_33 022222222222222222222222222222222222222222222222222222222222222222 OP_PUSHNUM_3 OP_CHECKMULTISIG";
        let scriptpubkey = "51210271cf3589a4ff65dd3daa10e1c16bb573eafa46874575bd9ed215bf0fc215824d2102214adba0ff718eb695b55694ba4fbf921cd587f62fdba757f5b93f646af9586a2102222222222222222222222222222222222222222222222222222222222222222253ae";

        // Assert that the function returns true for a valid case
        assert!(verify_unknown(scriptpubkey_asm, scriptpubkey));
    }

    #[test]
    fn test_verify_unknown2() {
        // Sample input data for a valid case
        let scriptpubkey_asm = "OP_PUSHNUM_1 OP_PUSHBYTES_33 0254de7a5999477d61249bf62e5e628b868508a32a83f5c2a6d6bc4fe55f79bccd OP_PUSHBYTES_33 0205bc4a558880b31291e37c52bbc6f99499b6d5bd2bc027a150ec1a9134f0371a OP_PUSHBYTES_33 022222222222222222222222222222222222222222222222222222222222222222 OP_PUSHNUM_3 OP_CHECKMULTISIG";
        let scriptpubkey = "51210254de7a5999477d61249bf62e5e628b868508a32a83f5c2a6d6bc4fe55f79bccd210205bc4a558880b31291e37c52bbc6f99499b6d5bd2bc027a150ec1a9134f0371a2102222222222222222222222222222222222222222222222222222222222222222253ae";

        // Assert that the function returns true for a valid case
        assert!(verify_unknown(scriptpubkey_asm, scriptpubkey));
    }
    
    #[test]
    fn test_verify_scriptsig_p2sh() {
        // Test when scriptsig ends with the last part of inner_redeemscript_asm
        let inner_redeemscript_asm = "OP_0 OP_PUSHBYTES_20 d14f30dc97f4f21f7c7a91feedd51cc018e92210";
        let scriptsig = "160014d14f30dc97f4f21f7c7a91feedd51cc018e92210";
        let scriptsig_asm ="OP_PUSHBYTES_22 0014d14f30dc97f4f21f7c7a91feedd51cc018e92210";
        assert_eq!(verify_scriptsig_p2sh(inner_redeemscript_asm, scriptsig, scriptsig_asm), true);
    }

    #[test]
    fn test_check_substrings_presence() {
        // Test case with substrings present in the witness field
        let witness_script_asm = "OP_PUSHNUM_2 OP_PUSHBYTES_33 02701d42ec373c1e033c45168e848b73166573dfe5bad959febbcabc4a8853ba91 OP_PUSHBYTES_33 03038de3a46925b1bbdf705f5c3b71da5c1863e77ae6699d28d42751554536e97a OP_PUSHNUM_2 OP_CHECKMULTISIG";
        let witness_field_last_string = "522102701d42ec373c1e033c45168e848b73166573dfe5bad959febbcabc4a8853ba912103038de3a46925b1bbdf705f5c3b71da5c1863e77ae6699d28d42751554536e97a52ae";

        assert!(verify_witness_p2wsh(witness_script_asm, witness_field_last_string));
    }
}


