use anyhow::Context;
use clap::{Parser, Subcommand};

use futures_util::{SinkExt, StreamExt};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{self, json};
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    net::SocketAddrV4,
    path::PathBuf,
    sync::{Arc, Mutex},
    vec,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{self, Sender},
};

use bittorrent_starter_rust::{
    magnet::Magnet,
    peer::{ExtendedMsg, Handshake, InnerID, Message, MessageFramer, MessageTag, Piece, Request},
    torrent::{self, Torrent},
    tracker::{TrackerRequest, TrackerResponse},
    BLOCK_MAX,
};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "snake_case")]
enum Command {
    Decode {
        value: String,
    },

    Info {
        torrent: PathBuf,
    },

    Peers {
        torrent: PathBuf,
    },

    Handshake {
        torrent: PathBuf,
        peer: String,
    },

    DownloadPiece {
        #[arg(short)]
        output: PathBuf,
        torrent: PathBuf,
        piece_id: usize,
    },

    Download {
        #[arg(short)]
        output: PathBuf,
        torrent: PathBuf,
    },

    MagnetParse {
        magnet_link: String,
    },

    MagnetHandshake {
        magnet_link: String,
    },
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
            let length = if let torrent::Keys::SingleFile { length } = tor.info.keys {
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
            let length = if let torrent::Keys::SingleFile { length } = tor.info.keys {
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
            for addr in tracker_info.peers.0 {
                println!("{}:{}", addr.ip(), addr.port())
            }
        }
        Command::Handshake { torrent, peer } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;

            let info_hash = tor.info_hash();

            let mut peer = TcpStream::connect(peer.parse::<SocketAddrV4>().context("peer parse")?)
                .await
                .context("connect peer")?;

            let mut handshake = Handshake::new(info_hash, *b"00112233445566778899");
            {
                let handshake_bytes = handshake.as_bytes_mut();
                peer.write_all(handshake_bytes)
                    .await
                    .context("send handshake")?;
                peer.read_exact(handshake_bytes)
                    .await
                    .context("read handshake")?;
            }

            println!("Peer ID: {}", hex::encode(&handshake.peer_id));
        }
        Command::DownloadPiece {
            output,
            torrent,
            piece_id,
        } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            let length = if let torrent::Keys::SingleFile { length } = tor.info.keys {
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

            let peer = tracker_info.peers.0[0];
            let mut peer = TcpStream::connect(peer).await.context("connect peer")?;

            let mut handshake = Handshake::new(info_hash, *b"00112233445566778899");
            {
                let handshake_bytes = handshake.as_bytes_mut();
                peer.write_all(handshake_bytes)
                    .await
                    .context("send handshake")?;
                peer.read_exact(handshake_bytes)
                    .await
                    .context("read handshake")?;
            }

            let mut peer = tokio_util::codec::Framed::new(peer, MessageFramer);
            let bitfield = peer
                .next()
                .await
                .expect("bitfield msg")
                .context("read bitfield")?;
            assert_eq!(bitfield.tag, MessageTag::Bitfield);

            peer.send(Message {
                tag: MessageTag::Interested,
                payload: Vec::new(),
            })
            .await
            .context("send interested message")?;

            let unchoke = peer
                .next()
                .await
                .expect("unchoke msg")
                .context("read unchoke")?;
            assert_eq!(unchoke.tag, MessageTag::Unchoke);
            assert!(unchoke.payload.is_empty());

            let piece_size = if piece_id == tor.info.pieces.0.len() - 1 {
                let md = length % tor.info.plength;
                if md == 0 {
                    tor.info.plength
                } else {
                    md
                }
            } else {
                tor.info.plength
            };

            let nblocks = (piece_size + BLOCK_MAX - 1) / BLOCK_MAX;
            let mut all_blocks = Vec::with_capacity(piece_size);
            for block in 0..nblocks {
                let block_size = if block == nblocks - 1 {
                    let md = piece_size % BLOCK_MAX;
                    if md == 0 {
                        BLOCK_MAX
                    } else {
                        md
                    }
                } else {
                    BLOCK_MAX
                };

                let mut request = Request::new(
                    piece_id as u32,
                    (block * BLOCK_MAX) as u32,
                    block_size as u32,
                );
                peer.send(Message {
                    tag: MessageTag::Request,
                    payload: request.as_bytes_mut().to_vec(),
                })
                .await
                .with_context(|| format!("send request for block {block}"))?;

                let piece = peer
                    .next()
                    .await
                    .expect("receive piece msg")
                    .context("invalid piece msg")?;
                let piece = Piece::ref_from_bytes(&piece.payload)
                    .expect("always get all Piece response fields from peer");
                all_blocks.extend(piece.block())
            }

            let piece_hash = &tor.info.pieces.0[piece_id];
            let mut hasher = Sha1::new();
            hasher.update(&all_blocks);
            let hash: [u8; 20] = hasher
                .finalize()
                .try_into()
                .expect("GenericArray<_, 20> == [_; 20]");
            assert_eq!(&hash, piece_hash);

            tokio::fs::write(&output, all_blocks)
                .await
                .context("write out downloaded piece")?;
            println!("Piece {piece_id} downloaded to {}.", output.display());
        }
        Command::Download { output, torrent } => {
            let dot_torrent = std::fs::read(torrent).context("read torrent file")?;
            let tor: Torrent =
                serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            let length = if let torrent::Keys::SingleFile { length } = tor.info.keys {
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

            let npiece = tor.info.pieces.0.len();
            let npeer = tracker_info.peers.0.len();
            println!("{npiece} pieces to download from {npeer} peers.");

            let queue = tor.info.pieces.0.into_iter().enumerate().collect();
            let queue = Arc::new(Mutex::new(queue));
            let (tx, mut rx) = mpsc::channel(npeer);
            for peer in tracker_info.peers.0 {
                let queue = queue.clone();
                let new_tx = tx.clone();
                tokio::spawn(download_piece(
                    npiece,
                    tor.info.plength,
                    length,
                    info_hash,
                    peer,
                    queue,
                    new_tx,
                ));
            }
            drop(tx);

            let mut all_pieces = vec![Vec::new(); npiece];
            while let Some((piece_id, piece)) = rx.recv().await {
                println!("Piece {piece_id} received.");
                all_pieces[piece_id] = piece;
            }
            let all_pieces = all_pieces.concat();

            println!("All pieces received.");
            tokio::fs::write(&output, all_pieces)
                .await
                .context("write out downloaded piece")?;
            println!("Downloaded to {}.", output.display());
        }
        Command::MagnetParse { magnet_link } => {
            let magnet = Magnet::parse(&magnet_link);
            println!("Tracker URL: {}", magnet.tracker_url.unwrap());
            println!("Info Hash: {}", hex::encode(magnet.info_hash));
        }
        Command::MagnetHandshake { magnet_link } => {
            let magnet = Magnet::parse(&magnet_link);
            let tracker_url = magnet.tracker_url.unwrap();
            let info_hash = magnet.info_hash;

            let peer_id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            let params = TrackerRequest {
                peer_id: peer_id.clone(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: 999,
                compact: 1,
            };
            let encoded = serde_urlencoded::to_string(params).context("url encode params")?;
            let query_url = format!(
                "{}?{}&info_hash={}",
                tracker_url,
                encoded,
                urlencode(&info_hash)
            );
            let res = reqwest::get(query_url).await.context("query tracker")?;
            let res = res.bytes().await.context("fetch tracker res")?;
            let tracker_info: TrackerResponse =
                serde_bencode::from_bytes(&res).context("parse tracker res")?;
            for addr in &tracker_info.peers.0 {
                println!("{}:{}", addr.ip(), addr.port())
            }

            let peer = tracker_info.peers.0[0];
            let mut peer = TcpStream::connect(peer).await.context("connect peer")?;

            let mut handshake = Handshake::new(info_hash, peer_id.as_bytes().try_into().unwrap());
            let support = {
                let handshake_bytes = handshake.as_bytes_mut();
                peer.write_all(handshake_bytes)
                    .await
                    .context("send handshake")?;
                peer.read_exact(handshake_bytes)
                    .await
                    .context("read handshake")?;

                let handshake = Handshake::ref_from_bytes(handshake_bytes);
                println!("reserved: {}", hex::encode(&handshake.reserved[5..6]));
                handshake.reserved[5] & 0x10 == 0x10
            };

            println!("Peer ID: {}", hex::encode(&handshake.peer_id));

            let mut peer = tokio_util::codec::Framed::new(peer, MessageFramer);
            let bitfield = peer
                .next()
                .await
                .expect("bitfield msg")
                .context("read bitfield")?;
            assert_eq!(bitfield.tag, MessageTag::Bitfield);

            if support {
                let mut payload = vec![0];
                let data: ExtendedMsg = ExtendedMsg {
                    m: InnerID {
                        ut_metadata: 0,
                    },
                };
                let data = serde_bencode::to_bytes(&data)?;
                payload.extend_from_slice(&data);
                peer.send(Message {
                    tag: MessageTag::Extended,
                    payload,
                })
                .await
                .context("send extended message")?;

                let extension_handshake = peer
                    .next()
                    .await
                    .expect("extension handshake msg")
                    .context("read extension handshake")?;
                assert_eq!(extension_handshake.tag, MessageTag::Extended);
                assert_eq!(extension_handshake.payload[0], 0);

                let data: ExtendedMsg = serde_bencode::from_bytes(&extension_handshake.payload[1..])?;
                println!("Peer Metadata Extension ID: {}", data.m.ut_metadata);
            }
        }
    }

    Ok(())
}

async fn download_piece(
    npiece: usize,
    plength: usize,
    length: usize,
    info_hash: [u8; 20],
    peer_addr: SocketAddrV4,
    task_queue: Arc<Mutex<Vec<(usize, [u8; 20])>>>,
    tx: Sender<(usize, Vec<u8>)>,
) -> anyhow::Result<()> {
    let mut peer = init_peer(peer_addr, info_hash).await?;

    loop {
        let task = {
            let mut task_queue = task_queue.lock().unwrap();
            task_queue.pop()
        };

        if let Some((piece_id, piece_hash)) = task {
            println!("Downloading piece {piece_id} of {npiece} from {peer_addr}...");

            let all_blocks = download(piece_id, npiece, length, plength, &mut peer).await?;
            let mut hasher = Sha1::new();
            hasher.update(&all_blocks);
            let hash: [u8; 20] = hasher
                .finalize()
                .try_into()
                .expect("GenericArray<_, 20> == [_; 20]");
            if piece_hash == hash {
                tx.send((piece_id, all_blocks)).await?;
                println!("Piece {piece_id} downloaded.");
            } else {
                let mut task_queue = task_queue.lock().unwrap();
                task_queue.push((piece_id, piece_hash));
                println!("Piece {piece_id} download from {peer_addr} failed.");
            }
        } else {
            return Ok(());
        }
    }
}

async fn download(
    piece_id: usize,
    npiece: usize,
    length: usize,
    plength: usize,
    peer: &mut tokio_util::codec::Framed<TcpStream, MessageFramer>,
) -> Result<Vec<u8>, anyhow::Error> {
    let piece_size = if piece_id == npiece - 1 {
        let md = length % plength;
        if md == 0 {
            plength
        } else {
            md
        }
    } else {
        plength
    };
    let nblocks = (piece_size + BLOCK_MAX - 1) / BLOCK_MAX;
    let mut all_blocks = Vec::with_capacity(piece_size);
    for block in 0..nblocks {
        let block_size = if block == nblocks - 1 {
            let md = piece_size % BLOCK_MAX;
            if md == 0 {
                BLOCK_MAX
            } else {
                md
            }
        } else {
            BLOCK_MAX
        };

        let mut request = Request::new(
            piece_id as u32,
            (block * BLOCK_MAX) as u32,
            block_size as u32,
        );
        peer.send(Message {
            tag: MessageTag::Request,
            payload: request.as_bytes_mut().to_vec(),
        })
        .await
        .with_context(|| format!("send request for block {block}"))?;

        let piece = peer
            .next()
            .await
            .expect("receive piece msg")
            .context("invalid piece msg")?;
        let piece = Piece::ref_from_bytes(&piece.payload)
            .expect("always get all Piece response fields from peer");
        all_blocks.extend(piece.block())
    }

    Ok(all_blocks)
}

async fn init_peer(
    peer_addr: SocketAddrV4,
    info_hash: [u8; 20],
) -> Result<tokio_util::codec::Framed<TcpStream, MessageFramer>, anyhow::Error> {
    let mut peer = TcpStream::connect(peer_addr)
        .await
        .context("connect peer")?;
    let mut handshake = Handshake::new(info_hash, *b"00112233445566778899");
    {
        let handshake_bytes = handshake.as_bytes_mut();
        peer.write_all(handshake_bytes)
            .await
            .context("send handshake")?;
        peer.read_exact(handshake_bytes)
            .await
            .context("read handshake")?;
    }
    let mut peer = tokio_util::codec::Framed::new(peer, MessageFramer);
    let _bitfield = peer
        .next()
        .await
        .expect("bitfield msg")
        .context("read bitfield")?;
    peer.send(Message {
        tag: MessageTag::Interested,
        payload: Vec::new(),
    })
    .await
    .context("send interested message")?;
    let unchoke = peer
        .next()
        .await
        .expect("unchoke msg")
        .context("read unchoke")?;
    assert_eq!(unchoke.tag, MessageTag::Unchoke);
    assert!(unchoke.payload.is_empty());
    Ok(peer)
}

fn urlencode(bytes: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * bytes.len());

    for &b in bytes {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[b]));
    }

    encoded
}
