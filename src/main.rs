use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::env;

fn main() {
    let file_path = String::from("/etc/hosts");
    let content = fs::read_to_string(&file_path).expect("Failed to read file");

    let mut dns: HashMap<&str, &str> = HashMap::new();

    for (n, line) in content.lines().enumerate() {
        if !(line.is_empty() || line.starts_with('#')) {
            if line.contains(' ') || line.contains('\t') {
                //println!("line: {line}");
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    let names = parts.collect::<Vec<&str>>();
                    for name in names.iter() {
                        dns.insert(name, ip);
                    }
                }
            }
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&dns).expect("Failed to serialize the dns")
    );

    let mut raw_args: Vec<String> = env::args().collect::<Vec<String>>();
    if raw_args.len() > 1 {
        raw_args.remove(0);
    }
    let args = raw_args.join(" ");
    println!("Args: {args}");
}
