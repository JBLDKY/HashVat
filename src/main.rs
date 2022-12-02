use sha1::Digest;
// use sha2::{Sha256, Sha512, digest};
use sha256::{digest};
use std::{error::Error, fs::{File, OpenOptions}, io::{Write, BufRead, BufReader},};
use eframe::egui;
// SHA1 hashes are always 40 in length
const SHA1_HEX_STRING_LENGTH: usize = 40;

// Crack a hash
fn crack(args: &String) -> Result<String, Box<dyn Error>> {
    let not_found = "No password found";
    let hash_to_crack = args.trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        return Err("sha1 hash is not valid".into());
    }

    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        if hash_to_crack == &hex::encode(sha1::Sha1::digest(common_password.as_bytes())) {
            // println!("Password found: {}", &common_password);
            return  Ok(String::from(common_password));
        }
}
println!("password not found in wordlist :(");
Ok(not_found.to_string())
}

fn add_password(password: String){
   let mut wordlist = OpenOptions::new().append(true).open("wordlist.txt").unwrap();   
   wordlist.write_all(password.as_bytes()).expect("write failed");
   wordlist.write_all("\n".as_bytes()).expect("write failed");
    println!("Data appended successfully");
}

fn sha1(args: &String) -> Result<String, Box<dyn Error>> {
    let password_to_hash = args.trim();
    //Catch error for no input
    if password_to_hash.len() == 0 {
        return Err("Nothing to hash.".into());
    }

    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);
    let mut password_exists = false;
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


fn crack_sha256(args: &String) -> Result<String, Box<dyn Error>> {
    let not_found = "No password found";
    let hash_to_crack = args.trim();
    // if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
    //     return Err("sha256 hash is not valid".into());
    // }
    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        if hash_to_crack == &digest(common_password.as_bytes()) {
            // println!("Password found: {}", &common_password);
            return  Ok(String::from(common_password));
        }
}

println!("password not found in wordlist :(");
Ok(not_found.to_string())
}


fn hash_sha256(args: &String) -> Result<String, Box<dyn Error>> {
    let password_to_hash = args.trim();
    //Catch error for no input
    if password_to_hash.len() == 0 {
        return Err("Nothing to hash.".into());
    }

    let wordlist_file = File::open("wordlist.txt")?;
    let reader = BufReader::new(&wordlist_file);
    let mut password_exists = false;
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

    let hashed_password = &digest(password_to_hash.as_bytes());
    println!("Hashed password: {}", hashed_password);
    return  Ok(String::from(hashed_password));

}



#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
fn main() {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Crackpass",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    );
}

struct MyApp {
    sha1_hash: String,
    pass: String,
    sha256_hash: String,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            sha1_hash: "7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53".to_owned(),
            pass: "".to_owned(),
            sha256_hash: "8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9".to_owned(),
            // SHA256_pass: "".to_owned(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Crackpass");
            ui.label("");

            // CRACK A SHA1 PASSWORD
            ui.horizontal(|ui| {
                ui.label("sha1");
                if ui.button("crack").clicked() {
                    let response = crack(&self.sha1_hash);
                    self.pass = match response {
                        Ok(v) => v.to_string(),
                        Err(e) => e.to_string(),
                    };
                };
            });

            ui.text_edit_singleline(&mut self.sha1_hash);
            ui.label("");


            //CRACK WITH SHA256
            ui.horizontal(|ui| {
                ui.label("sha256");
                if ui.button("crack").clicked() {
                    let response =crack_sha256(&self.sha256_hash);
                    self.pass = match response {
                        Ok(v) => v.to_string(),
                        Err(e) => e.to_string(),
                    };
                };
            });

            ui.text_edit_singleline(&mut self.sha256_hash);
            ui.label("");


            ui.horizontal(|ui| {
            //HASH WITH SHA256
                ui.label("Cleartext");
                if ui.button("sha256").clicked() {
                    let response = hash_sha256(&self.pass);
                    self.sha256_hash = match response {
                        Ok(v) => v.to_string(),
                        Err(e) => e.to_string(),
                    };
                };
                //HASH WITH SHA1
                if ui.button("sha1").clicked() {
                    let response = sha1(&self.pass);
                    self.sha1_hash = match response {
                        Ok(v) => v.to_string(),
                        Err(e) => e.to_string(),
                    };
                };
            });




            ui.text_edit_singleline(&mut self.pass);
        });
    }
}
