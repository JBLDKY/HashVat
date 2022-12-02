use std::fs::OpenOptions;
use std::io::Write;

// Function for adding an unknown password
pub fn add_password(password: String){
    let mut wordlist = OpenOptions::new().append(true).open("wordlist.txt").unwrap();
    wordlist.write_all(password.as_bytes()).expect("write failed");
    wordlist.write_all("\n".as_bytes()).expect("write failed");
    println!("Data appended successfully");
}
