use anyhow::Context;
use bytes::{BufMut, BytesMut};
use clap::{Parser, Subcommand};

use serde_json::{self, json};
use std::{io::Write, path::PathBuf};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpSocket,
};

use bittorrent_starter_rust::{
    torrent::{self, Torrent},
    tracker::{TrackerRequest, TrackerResponse},
};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "snake_case")]
enum Command {
    Decode { value: String },

    Info { torrent: PathBuf },

    Peers { torrent: PathBuf },

    Handshake { torrent: PathBuf, peer: String },
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Decode { value } => {
            let v = decode_bencoded_value(&value).0;
            println!("{v}");
        }
        Command::Info { torrent } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            println!("Tracker URL: {}", tor.announce);
            let length = if let torrent::Keys::Single { length } = tor.info.keys {
                length
            } else {
                todo!();
            };
            println!("Length: {length}");
            let info_hash = tor.info_hash();
            println!("Info Hash: {}", hex::encode(info_hash));
            println!("Piece Length: {}", tor.info.plength);
            println!("Piece Hashes:");
            for hash in &tor.info.pieces.0 {
                println!("{}", hex::encode(hash))
            }
        }
        Command::Peers { torrent } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            let length = if let torrent::Keys::Single { length } = tor.info.keys {
                length
            } else {
                todo!();
            };
            let info_hash = tor.info_hash();

            let params = TrackerRequest {
                peer_id: "00112233445566778899".into(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: length,
                compact: 1,
            };
            let encoded = serde_urlencoded::to_string(params).context("url encode params")?;
            let query_url = format!(
                "{}?{}&info_hash={}",
                tor.announce,
                encoded,
                urlencode(&info_hash)
            );
            let res = reqwest::get(query_url).await.context("query tracker")?;
            let res = res.bytes().await.context("fetch tracker res")?;
            let tracker_info: TrackerResponse =
                serde_bencode::from_bytes(&res).context("parse tracker res")?;
            for (ip, port) in tracker_info.peers.0 {
                println!("{ip}:{port}")
            }
        }
        Command::Handshake { torrent, peer } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;

            let info_hash = tor.info_hash();

            let mut buf = BytesMut::with_capacity(68);
            buf.put_u8(19);
            buf.put(&b"BitTorrent protocol"[..]);
            buf.put_slice(&[0u8; 8]);
            buf.put_slice(&info_hash);
            buf.put(&b"00112233445566778899"[..]);

            let socket = TcpSocket::new_v4().context("new socket")?;
            let mut stream = socket
                .connect(peer.parse().context("peer parse")?)
                .await
                .context("connect peer")?;
            stream.write(&buf).await.context("send handshake")?;

            let mut buf = [0; 128];

            // Wait for the socket to be readable
            stream.readable().await?;

            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            if let Ok(len) = stream.try_read(&mut buf) {
                println!("Peer ID: {}", hex::encode(&buf[48..len]))
            }
        }
    }

    Ok(())
}

fn urlencode(bytes: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * bytes.len());

    for &b in bytes {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[b]));
    }

    encoded
}
