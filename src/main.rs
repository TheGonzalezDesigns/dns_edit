use std::fs;
use std::env;
use std::io::{stdin, stdout, Write};
use std::collections::HashMap;

fn main() {
    let mut file_path = String::new();

    print!("File path:\t");
    let _ = stdout().flush();
    stdin().read_line(&mut file_path).expect("Bad input");
    file_path = file_path.trim().to_string();

    let contents = fs::read_to_string(&file_path).expect("Failed to read file");

    let mut n = 0;
    let mut dns: HashMap<&str, Vec<&str>> = HashMap::new();

    for line in contents.lines() {
        if !(line.starts_with('#') || line.is_empty()) {
            println!("#{n}\t| {line}");
            n += 1;
            if line.contains(' ') {
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    let names = parts.collect::<Vec<&str>>();
                    dns.insert(ip, names);
                }
            }
        }
    }

    println!("{:?}", dns);
}
