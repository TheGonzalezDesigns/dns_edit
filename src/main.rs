use std::fs;
use std::collections::HashMap;

fn main() {
    let file_path = String::from("/etc/hosts");
    let contents = fs::read_to_string(&file_path).expect("Failed to read file");

    let mut dns: HashMap<&str, (usize, Vec<&str>)> = HashMap::new();

    for (n, line) in contents.lines().enumerate() {
        if !(line.starts_with('#') || line.is_empty()) {
            if line.contains(' ') || line.contains('\t') {
                //println!("line: {line}");
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    let names = parts.collect::<Vec<&str>>();
                    dns.insert(ip, (n, names));
                }
            }
        }
    }

    println!("{:?}", dns);
}
