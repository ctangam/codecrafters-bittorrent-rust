use serde_json::{self, json};
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next().unwrap() {
        'i' => {
            let (_, left) = encoded_value.split_at(1);
            if let Some((digits, remainder)) = left.split_once('e') {
                    return (digits.parse::<i64>().unwrap().into(), remainder)
            }
        }
        '0'..='9' => {
            if let Some((digits, s)) = encoded_value.split_once(':') {
                let len = digits.parse().unwrap();
                return (s[..len].into(), &s[len..])
            }
        }
        'l' => {
            let mut values = Vec::new();
            let mut remainder = &encoded_value[1..];
            while !remainder.is_empty() && remainder.chars().next() != Some('e') {
                let (value, left) = decode_bencoded_value(remainder);
                values.push(value);
                remainder = left;
            }
            return (values.into(), &remainder[1..])
        }
        'd' => {

        }
        _ => unimplemented!()
    }

    (json!(null), encoded_value)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let (decoded_value, remainder) = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
