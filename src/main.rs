use serde_json::{self, json};
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    match encoded_value.chars().next().unwrap() {
        'i' => {
            let (_, left) = encoded_value.split_at(1);
            if let Some((digits, _)) = left.split_once('e') {
                    return digits.into()
            }
        }
        '0'..='9' => {
            if let Some((digits, s)) = encoded_value.split_once(':') {
                let len = digits.parse().unwrap();
                return serde_json::Value::Number(s[..len].parse::<i64>().unwrap().into())
            }
        }
        'l' => {

        }
        'd' => {

        }
        _ => unimplemented!()
    }

    json!(null)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
