use reqwest::Url;

pub struct Magnet {
    pub info_hash: [u8; 20],
    pub name: Option<String>,
    pub tracker_url: Option<String>,
}

impl Magnet {
    pub fn new(info_hash: [u8; 20], name: String, tracker_url: String) -> Self {
        Self {
            info_hash,
            name: Some(name),
            tracker_url: Some(tracker_url),
        }
    }

    pub fn parse(magnet: &str) -> Self {
        let index = magnet.find("urn:btih:").unwrap();
        let mut info_hash = [0u8; 20];

        hex::decode_to_slice(&magnet[index + 9..index + 49], &mut info_hash).unwrap();

        let name = magnet
            .find("dn=")
            .map(|index| magnet[index + 3..].to_string());

        let tracker_url = magnet.find("tr=").map(|index| {
            urlencoding::decode(&magnet[index + 3..])
                .unwrap()
                .to_string()
        });

        Self {
            info_hash,
            name,
            tracker_url,
        }
    }
}
