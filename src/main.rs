use eframe::egui;
pub mod sha1_functions;
use crate::sha1_functions::{match_sha1, hash_sha1};
pub mod password_functions;
pub mod sha256_functions;
use std::thread;
use crate::sha256_functions::{match_sha256, hash_sha256};


#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
fn main() {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "HashVat",
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
            ui.heading("HashVat");
            ui.label("");

            // CRACK A SHA1 PASSWORD
            ui.horizontal(|ui| {
                ui.label("sha1");
                if ui.button("crack").clicked() {
                    let response = match_sha1(&self.sha1_hash);
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
                //label
                ui.label("sha256");

                //button
                if ui.button("crack").clicked() {
                    let new_thread = thread::spawn(move || {
                        let response = match_sha256(&self.sha256_hash);
                        self.pass = match response {
                            Ok(v) => v.to_string(),
                            Err(e) => e.to_string(),
                        };
                    });

                    let response = match_sha256(&self.sha256_hash);
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
                    let response = hash_sha1(&self.pass);
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
