pub mod app;
pub mod handle;

use risc0_zkvm::Receipt;
use serde::{Serialize, Deserialize};
use spacedb::{NodeHasher, Sha256Hasher};
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::slabel::SLabel;
use spacedb::Sha256Hasher as sha256;
use spacedb::subtree::SubTree;
use crate::handle::{Handle, SSLabel};

pub extern crate spaces_protocol;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandleRequest {
    pub handle: Handle,
    pub script_pubkey: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JsonCert {
    #[serde(flatten)]
    pub request: HandleRequest,
    pub anchor: String,
    #[serde(with = "witness_ser")]
    pub witness: JsonWitness,
}

#[derive(Clone)]
pub enum JsonWitness {
    SubTree(SubTree<Sha256Hasher>),
    Receipt(Receipt),
}

mod witness_ser {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use bincode::config;
    use risc0_zkvm::Receipt;
    use serde::{de, Deserializer, Serializer};
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::{SerializeStruct, SerializeTuple};
    use spacedb::Sha256Hasher;
    use spacedb::subtree::SubTree;
    use super::*;

    const TAG_SUBTREE: u8 = 0;
    const TAG_RECEIPT: u8 = 1;

    fn enc_subtree(v: &SubTree<Sha256Hasher>) -> Result<Vec<u8>, String> {
        bincode::encode_to_vec(v, config::standard())
            .map_err(|e| format!("encode subtree: {e}"))
    }
    fn dec_subtree(b: &[u8]) -> Result<SubTree<Sha256Hasher>, String> {
        bincode::decode_from_slice(b, config::standard())
            .map(|(v, _len)| v)
            .map_err(|e| format!("decode subtree: {e}"))
    }
    fn enc_receipt(v: &Receipt) -> Result<Vec<u8>, String> {
        bincode::serde::encode_to_vec(v, config::standard())
            .map_err(|e| format!("encode receipt: {e}"))
    }
    fn dec_receipt(b: &[u8]) -> Result<Receipt, String> {
        bincode::serde::decode_from_slice(b, config::standard())
            .map(|(v, _len)| v)
            .map_err(|e| format!("decode receipt: {e}"))
    }

    pub fn serialize<S>(w: &JsonWitness, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let (typ, bytes) = match w {
                JsonWitness::SubTree(st) => ("subtree", enc_subtree(st).map_err(serde::ser::Error::custom)?),
                JsonWitness::Receipt(rc) => ("receipt", enc_receipt(rc).map_err(serde::ser::Error::custom)?),
            };
            let mut st = s.serialize_struct("Witness", 2)?;
            st.serialize_field("type", typ)?;
            st.serialize_field("data", &BASE64_STANDARD.encode(bytes))?;
            st.end()
        } else {
            let (tag, bytes) = match w {
                JsonWitness::SubTree(st) => (TAG_SUBTREE, enc_subtree(st).map_err(serde::ser::Error::custom)?),
                JsonWitness::Receipt(rc) => (TAG_RECEIPT, enc_receipt(rc).map_err(serde::ser::Error::custom)?),
            };
            let mut tup = s.serialize_tuple(2)?;
            tup.serialize_element(&tag)?;
            tup.serialize_element(&bytes)?;
            tup.end()
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<JsonWitness, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            #[derive(Deserialize)]
            struct Tmp { #[serde(rename = "type")] typ: String, data: String }
            let tmp = Tmp::deserialize(d)?;
            let bytes = BASE64_STANDARD.decode(&tmp.data).map_err(de::Error::custom)?;
            match tmp.typ.as_str() {
                "subtree" => dec_subtree(&bytes).map(JsonWitness::SubTree).map_err(de::Error::custom),
                "receipt" => dec_receipt(&bytes).map(JsonWitness::Receipt).map_err(de::Error::custom),
                other => Err(de::Error::custom(format!("unknown witness type: {other}"))),
            }
        } else {
            struct TupVisitor;
            impl<'de> Visitor<'de> for TupVisitor {
                type Value = JsonWitness;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "(tag_u8, bytes)")
                }
                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let tag: u8 = seq.next_element()?.ok_or_else(|| de::Error::custom("missing tag"))?;
                    let bytes: Vec<u8> = seq.next_element()?.ok_or_else(|| de::Error::custom("missing bytes"))?;
                    match tag {
                        TAG_SUBTREE => dec_subtree(&bytes).map(JsonWitness::SubTree).map_err(de::Error::custom),
                        TAG_RECEIPT => dec_receipt(&bytes).map(JsonWitness::Receipt).map_err(de::Error::custom),
                        _ => Err(de::Error::custom("unknown tag")),
                    }
                }
            }
            d.deserialize_tuple(2, TupVisitor)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Batch {
    pub space: SLabel,
    pub entries: Vec<BatchEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchEntry {
    pub sub_label: SSLabel,
    pub script_pubkey: ScriptBuf,
}

impl Batch {
    pub fn new(space: SLabel) -> Self {
        Batch {
            space,
            entries: Vec::new(),
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries)
    }

    pub fn to_zk_input(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let space_hash = sha256::hash(self.space.as_ref());
        bytes.extend_from_slice(&space_hash);

        for entry in &self.entries {
            let subspace_hash = sha256::hash(entry.sub_label.as_slabel().as_ref());
            bytes.extend_from_slice(&subspace_hash);

            let script_hash = sha256::hash(entry.script_pubkey.as_bytes());
            bytes.extend_from_slice(&script_hash);
        }

        bytes
    }
}
