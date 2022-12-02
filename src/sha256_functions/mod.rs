use std::io::{BufReader, BufRead};
use std::fs::File;
use std::error::Error;
use sha2::{Sha256, Digest};
use crate::password_functions::add_password;

const SHA256_HEX_STRING_LENGTH: usize = 64;

#[allow(dead_code)]
pub fn match_sha256(args: &String) -> Result<String, Box<dyn Error>> {
    let not_found = "No password found";
    let hash_to_crack = args.trim();

    // length check, sha256 should be 64 characters / 256 bits
    if hash_to_crack.len() != SHA256_HEX_STRING_LENGTH {
        return Err("sha256 hash is not valid".into());
    }

    // open file
    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file); // create reader
    for line in reader.lines() { // start loop
        let line = line?;
        let common_password = line.trim();

        // get the hash of the common password
        let mut hash = Sha256::new();
        hash.update(common_password.as_bytes()); // as bytes, very important
        let my_hash_bytes = hash.finalize(); // finalize, get result

        // convert the hash(bytes) to a string
        let mut my_hash_string = String::new();
        for byte in my_hash_bytes.iter() {
            my_hash_string.push_str(&format!("{:02x}", byte));
        }


        // The matching SUCCESS
        if hash_to_crack == my_hash_string {
                    println!("Password found: {}", &common_password);
                    return Ok(String::from(common_password))
            }
    }
    // FAIL
    println!("password not found in wordlist :(");
    Ok(not_found.to_string())
}

#[allow(dead_code)]
pub fn hash_sha256(args: &String) -> Result<String, Box<dyn Error>> {
    let password_to_hash = args.trim();

    //Catch error for no input
    if password_to_hash.len() == 0 {
        return Err("Nothing to hash.".into());
    }

    // Create a byte array from the password
    let mut hash = Sha256::new();
    hash.update(password_to_hash.as_bytes());
    let my_hash_bytes = hash.finalize();

    // convert the hash(bytes) to a string
    let mut hashed_password = String::new();
    for byte in my_hash_bytes.iter() {
        hashed_password.push_str(&format!("{:02x}", byte));
    };

    // open the wordlist and read it
    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);

    // initialize a boolean to check if the password is in the wordlist
    let mut password_exists = false;

    // loop through the wordlist
    for line in reader.lines() {
        // get the line
        let line = line?;
        // get the password
        let hashed_password = line.trim();
        // check if the password is in the wordlist
        if password_to_hash == hashed_password {
            password_exists = true;
        }
    };
    if !password_exists { // if the password is not in the wordlist, add it
        add_password(password_to_hash.to_string())
    }

    println!("Hashed password: {:#?}", hashed_password);
    Ok(hashed_password.to_string())
}
