use std::fs;
use std::collections::HashMap;
use serde::Serialize;

#[derive(Serialize)]
struct Entry<'a> {
    line_number: usize,
    names: Vec<&'a str>
}

impl<'a> Entry<'a> {
   pub fn new(line_number: usize, names: Vec<&'a str>) -> Self {
        Entry {
            line_number,
            names
        }
   }
}

type Comment<'a> = &'a str;

#[derive(Serialize)]
enum DNSEntry<'a> {
    Entry(Entry<'a>),
    Comment(Comment<'a>),
    Space
}

impl <'a> DNSEntry<'a> {
    pub fn entry(line_number: usize, names: Vec<&'a str>) -> Self {
        let entry = Entry::new(line_number, names);
        DNSEntry::Entry(entry)
    }
    pub fn comment(comment: &'a str) -> Self {
        DNSEntry::Comment(comment)
    }

    pub fn space() -> Self {
        DNSEntry::Space
    }
}

fn main() {
    let file_path = String::from("/etc/hosts");
    let contents = fs::read_to_string(&file_path).expect("Failed to read file");

    let mut dns: HashMap<&str, Entry> = HashMap::new();

    for (n, line) in contents.lines().enumerate() {
        if !(line.is_empty() || line.starts_with('#')) {
            if line.contains(' ') || line.contains('\t') {
                //println!("line: {line}");
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    let names = parts.collect::<Vec<&str>>();
                    let entry = Entry::new(n, names);
                    dns.insert(ip, entry);
                }
            }
        }
    }

    println!("{}", serde_json::to_string_pretty(&dns).expect("Failed to serialize the dns"));
}
