use std::io::{BufReader, BufRead};
use std::fs::File;
use std::error::Error;
use sha1::Digest;
pub mod sha1_constants;
use crate::sha1_functions::sha1_constants::SHA1_HEX_STRING_LENGTH;
use crate::password_functions::add_password;

pub fn match_sha1(args: &String) -> Result<String, Box<dyn Error>> {
        let not_found = "No password found";
        let hash_to_crack = args.trim();

        // hash length validation
        if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
            return Err("sha1 hash is not valid".into());
        }

        //open the wordlist and read
        let wordlist_file = File::open("wordlist.txt")?;
        let reader = BufReader::new(&wordlist_file);

        // loop through passwords and look for a match
        for line in reader.lines() {
            let line = line?;
            let common_password = line.trim(); // clean the comparisons

            // compare with a hashed version of known passwords
            if hash_to_crack == &hex::encode(sha1::Sha1::digest(common_password.as_bytes())) {
                println!("Password found: {}", &common_password);
                return Ok(String::from(common_password));
            }
        }
        println!("password not found in wordlist :(");
        Ok(not_found.to_string())
    }

pub fn hash_sha1(args: &String) -> Result<String, Box<dyn Error>> {
    let password_to_hash = args.trim();
    //Catch error for no input
    if password_to_hash.len() == 0 {
        return Err("Nothing to hash.".into());
    }

    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);

    //initialize bool for detecting known passwords
    let mut password_exists: bool = false;

    // loop and see if the password is in our database
    //TODO  could this run async as some kind of background task?
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        if password_to_hash == common_password {
            password_exists = true;
        }
    };

    if !password_exists{
        add_password(password_to_hash.to_string())
    }

    let hashed_password = &hex::encode(sha1::Sha1::digest(password_to_hash.as_bytes()));
    println!("Hashed password: {}", hashed_password);
    return  Ok(String::from(hashed_password));

}
