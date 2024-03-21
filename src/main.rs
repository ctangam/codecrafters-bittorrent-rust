use anyhow::Context;
use clap::{Parser, Subcommand};
use hex::encode_upper;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::{collections::HashMap, env, io::Read, path::{Path, PathBuf}, vec};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command
}

#[derive(Debug, Subcommand)]
enum Command {
    Decode {
        value: String
    },

    Info {
        torrent: PathBuf
    }
}

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next() {
        Some('i') => {
            let (_, left) = encoded_value.split_at(1);
            if let Some((digits, remainder)) = left.split_once('e') {
                return (digits.parse::<i64>().unwrap().into(), remainder);
            }
        }
        Some('0'..='9') => {
            if let Some((digits, s)) = encoded_value.split_once(':') {
                let len = digits.parse().unwrap();
                return (s[..len].into(), &s[len..]);
            }
        }
        Some('l') => {
            let mut values = Vec::new();
            let mut remainder = &encoded_value[1..];
            while !remainder.is_empty() && remainder.chars().next() != Some('e') {
                let (value, left) = decode_bencoded_value(remainder);
                values.push(value);
                remainder = left;
            }
            return (values.into(), &remainder[1..]);
        }
        Some('d') => {
            let mut dict = serde_json::Map::new();
            let mut remainder = &encoded_value[1..];
            while !remainder.is_empty() && remainder.chars().next() != Some('e') {
                let (key, left) = decode_bencoded_value(remainder);
                let key = match key {
                    serde_json::Value::String(k) => k,
                    k => {
                        panic!("dict keys must be strings, not {k:?}");
                    }
                };
                let (value, left) = decode_bencoded_value(left);
                dict.insert(key, value);
                remainder = left;
            }
            return (dict.into(), &remainder[1..]);
        }
        _ => unimplemented!(),
    }

    (json!(null), encoded_value)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> anyhow::Result<()>{
    let args = Args::parse();

    match args.command {
        Command::Decode { value } => {
            let v = decode_bencoded_value(&value).0;
            println!("{v}");
        },
        Command::Info { torrent } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent = serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            println!("Tracker URL: {}", tor.announce);
            let length = if let Keys::Single { length } = tor.info.keys {
                length
            } else {
                todo!();
            };
            println!("Length: {length}");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Torrent {
    announce: String,
    info: Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Info {
    name: String,

    #[serde(rename = "piece length")]
    plength: usize,

    pieces: hashes::Hashes,

    #[serde(flatten)]
    keys: Keys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Keys {
    Single { length: usize },

    Multipy { files: Vec<File> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct File {
    length: usize,
    path: Vec<String>,
}

mod hashes {

    use serde::{
        de::{self, Visitor},
        Deserialize, Serialize,
    };
    use std::fmt;

    #[derive(Debug, Clone)]
    pub struct Hashes(Vec<[u8; 20]>);
    struct HashesVisitor;

    impl<'de> Visitor<'de> for HashesVisitor {
        type Value = Hashes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte string whose length is a multiple of 20")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() % 20 != 0 {
                Err(E::custom("length not a multiple of 20"))
            } else {
                Ok(Hashes(
                    v.chunks_exact(20)
                        .map(|c| c.try_into().expect("guaranteed to be length 20"))
                        .collect(),
                ))
            }
        }
    }

    impl<'de> Deserialize<'de> for Hashes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(HashesVisitor)
        }
    }

    impl Serialize for Hashes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let single_slice = self.0.concat();
            serializer.serialize_bytes(&single_slice)
        }
    }
}
