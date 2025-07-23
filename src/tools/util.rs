use serde::{Deserialize, Deserializer, de};
use std::fmt;
use std::marker::PhantomData;

#[derive(Deserialize, Debug)]
#[serde(transparent)]
pub struct ArgsData(pub VecMap<String, u128>);

pub struct VecMap<K, V> {
    pub vec: Vec<(K, V)>,
}

impl<'de, K: Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de> for VecMap<K, V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor<K, V>(PhantomData<(K, V)>);

        impl<'de, K, V> de::Visitor<'de> for Visitor<K, V>
        where
            K: de::Deserialize<'de>,
            V: de::Deserialize<'de>,
        {
            type Value = VecMap<K, V>;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("a map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut vec = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) = map.next_entry()? {
                    vec.push(entry);
                }
                Ok(VecMap { vec })
            }
        }

        deserializer.deserialize_map(Visitor(PhantomData))
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for VecMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.vec.iter().map(|entry| (&entry.0, &entry.1)))
            .finish()
    }
}
