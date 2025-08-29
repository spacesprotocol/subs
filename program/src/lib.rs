extern crate alloc;
extern crate core;

pub mod guest;

pub struct BatchReader<'a>(pub &'a [u8]);

pub struct Entry<'a> {
    pub handle: &'a [u8],
    pub script_pubkey: &'a [u8],
}

pub struct BodyIterator<'a> {
    data: &'a [u8],
}

impl<'a> BatchReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BatchReader(data)
    }

    pub fn space_hash(&self) -> &'a [u8] {
        &self.0[..32]
    }

    pub fn iter(&self) -> BodyIterator<'a> {
        BodyIterator {
            data: &self.0[32..],
        }
    }
}

impl<'a> Iterator for BodyIterator<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 64 {
            return None;
        }

        let subspace_hash = &self.data[..32];
        let script_pubkey_hash = &self.data[32..64];
        self.data = &self.data[64..];

        Some(Entry {
            handle: subspace_hash,
            script_pubkey: script_pubkey_hash,
        })
    }
}
