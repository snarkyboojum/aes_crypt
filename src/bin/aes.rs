extern crate aes_crypt;
use aes_crypt::{cipher, expand_key, inverse_cipher, KeyLength, Rounds, BLOCK_SIZE};
use std::fs;

fn main() {
    // TODO: key length should be paramaterised at runtime/instantiation
    let key_length: KeyLength = KeyLength::OneTwentyEight;

    let file_name = "data/small.txt";
    let key_name = "data/key.txt";
    println!("Reading data and key: {}, {}", file_name, key_name);

    let file_bytes: Vec<u8> = fs::read(file_name).expect("Couldn't read data file");
    let key_bytes: Vec<u8> = fs::read(key_name).expect("Couldn't read key");
    /*
    println!(
        "Length of key and data is: {}, {} bytes",
        key_bytes.len(),
        file_bytes.len()
    );
    */
    assert_eq!(key_bytes.len(), key_length as usize / 8);

    // run key expansion / build key schedule
    let mut key_schedule = [0u32; 4 * (Rounds::Ten as usize + 1)];
    expand_key(&key_bytes, &mut key_schedule, key_length);

    for (_i, block) in file_bytes.chunks(BLOCK_SIZE).enumerate() {
        //println!("Processing block: {}", i);

        // TODO: pad or do something else for partial blocks?
        if block.len() < 16 {
            println!("Processing partial block.. not implemented yet :)");
            break;
        } else {
            // run the cipher block-wise
            println!(
                "Unencrypted data block: {}",
                std::str::from_utf8(&block).unwrap()
            );
            let cipher_text = cipher(block, &key_schedule);
            println!("Input to cipher: {:#02x?}", block);
            println!("Cipher text: {:#02x?}", cipher_text);

            // run inverse cipher block-wise
            let output = inverse_cipher(&cipher_text, &key_schedule);
            println!("Decrypted cipher text: {:#02x?}", output);
            println!(
                "Decrypted data block: {}",
                std::str::from_utf8(&output).unwrap()
            );
        }
    }
}
