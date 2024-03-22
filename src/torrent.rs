use serde::{Deserialize, Serialize};
use sha1::{Sha1, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

impl Torrent {
    pub fn info_hash(&self) -> [u8; 20] {
        let info_encode = serde_bencode::to_bytes(&self.info).expect("bencode info");
        let mut hasher = Sha1::new();
        hasher.update(&info_encode);
        hasher.finalize().try_into().expect("should pass")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub name: String,

    #[serde(rename = "piece length")]
    pub plength: usize,

    pub pieces: hashes::Hashes,

    #[serde(flatten)]
    pub keys: Keys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Keys {
    Single { length: usize },

    Multipy { files: Vec<File> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
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
    pub struct Hashes(pub Vec<[u8; 20]>);
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