use core::{fmt::{Display, Formatter}, str::FromStr};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeError};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::{errors::Error, slabel::{NameErrorKind, SLabel}};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle((SSLabel, SLabel));

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SSLabel(SLabel);

pub trait Sha256Hashable {
    fn sha256(&self) -> Hash;
}

impl Handle {
    pub fn new(subspace: SSLabel, space: SLabel) -> Self {
        Self((subspace, space))
    }

    pub fn subspace(&self) -> &SSLabel {
        &self.0.0
    }

    pub fn subspace_mut(&mut self) -> &mut SSLabel {
        &mut self.0.0
    }

    pub fn space(&self) -> &SLabel {
        &self.0.1
    }

    pub fn space_mut(&mut self) -> &mut SLabel {
        &mut self.0.1
    }
}

impl SSLabel {
    pub fn as_slabel(&self) -> &SLabel {
        &self.0
    }

    pub fn into_slabel(self) -> SLabel {
        self.0
    }
}

impl FromStr for Handle {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sub, space) = s.split_once('@').ok_or(Error::Name(NameErrorKind::NotCanonical))?;
        if sub.is_empty() || space.is_empty() {
            return Err(Error::Name(NameErrorKind::NotCanonical));
        }
        Ok(Handle((
            SSLabel::from_str(sub)?,
            SLabel::from_str(&format!("@{}", space))?,
        )))
    }
}

impl Display for Handle {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let sub = self.0.0.to_string();
        let space = self.0.1.to_string();
        write!(f, "{}{}", sub, space)
    }
}

impl Serialize for Handle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            (&self.0).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Handle::from_str(&s).map_err(|_| D::Error::custom("invalid handle"))
        } else {
            let tup: (SSLabel, SLabel) = Deserialize::deserialize(deserializer)?;
            Ok(Handle(tup))
        }
    }
}


impl Display for SSLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let s = self.0.to_string_unprefixed().map_err(|_| core::fmt::Error)?;
        write!(f, "{}", s)
    }
}

impl FromStr for SSLabel {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SSLabel(SLabel::from_str_unprefixed(s)?))
    }
}

impl Serialize for SSLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SSLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            SSLabel::from_str(&s).map_err(|_| D::Error::custom("invalid subspace"))
        } else {
            let lbl: SLabel = Deserialize::deserialize(deserializer)?;
            Ok(SSLabel(lbl))
        }
    }
}

impl Sha256Hashable for SLabel {
    fn sha256(&self) -> Hash {
        Sha256Hasher::hash(&self.as_ref())
    }
}

impl Sha256Hashable for SSLabel {
    fn sha256(&self) -> Hash {
        Sha256Hasher::hash(&self.as_slabel().as_ref())
    }
}


impl Sha256Hashable for Vec<u8> {
    fn sha256(&self) -> Hash {
        Sha256Hasher::hash(&self)
    }
}
