use std::io::{stdin, stdout, Write};

fn main() {
    let mut input = String::new();

    println!("Enter some text:");
    let _ = stdout().flush();

    stdin().read_line(&mut input).expect("Bad input");

        if let Some('\n')=input.chars().next_back() {
                    input.pop();
                        }
            if let Some('\r')=input.chars().next_back() {
                        input.pop();
                            }

    println!("Text: {input}");
}
