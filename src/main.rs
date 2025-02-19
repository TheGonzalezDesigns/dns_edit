use std::fs;
use std::env;
use std::io::{stdin, stdout, Write};

fn main() {
    let mut file_path = String::new();

    print!("File path:\t");
    let _ = stdout().flush();
    stdin().read_line(&mut file_path).expect("Bad input");
    file_path = file_path.trim().to_string();

    let contents = fs::read_to_string(&file_path).expect("Failed to read file");

    println!("\nContents:\n{contents}");
}
