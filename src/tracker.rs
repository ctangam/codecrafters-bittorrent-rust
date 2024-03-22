use serde::{Deserialize, Serialize};

use self::peers::Peers;

#[derive(Debug, Clone, Serialize)]
pub struct TrackerRequest {
    // pub info_hash: String,

    pub peer_id: String,

    pub port: u16,

    pub uploaded: usize,

    pub downloaded: usize,

    pub left: usize,

    pub compact: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    pub interval: usize,

    pub peers: Peers,
}

mod peers {

    use serde::{
        de::{self, Visitor},
        Deserialize, Serialize,
    };
    use std::{fmt, net::Ipv4Addr};

    #[derive(Debug, Clone)]
    pub struct Peers(pub Vec<(Ipv4Addr, u16)>);
    struct PeersVisitor;

    impl<'de> Visitor<'de> for PeersVisitor {
        type Value = Peers;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte string whose length is a multiple of 6")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() % 6 != 0 {
                Err(E::custom("length not a multiple of 6"))
            } else {
                Ok(Peers(
                    v.chunks_exact(6)
                        .map(|c| {
                            let addr = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                            let port = u16::from_be_bytes([c[4], c[5]]);
                            (addr, port)
                        })
                        .collect(),
                ))
            }
        }
    }

    impl<'de> Deserialize<'de> for Peers {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(PeersVisitor)
        }
    }

    impl Serialize for Peers {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let single_slice = self
                .0
                .iter()
                .flat_map(|(addr, port)| {
                    let mut bytes: Vec<u8> = Vec::with_capacity(6);
                    bytes.extend_from_slice(&addr.octets());
                    bytes.extend_from_slice(&port.to_be_bytes());
                    bytes
                })
                .collect::<Vec<u8>>();
            serializer.serialize_bytes(&single_slice)
        }
    }
}
