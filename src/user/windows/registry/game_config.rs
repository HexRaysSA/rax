//! Read-only REGF mount for a loose GameOS title's configuration.
use super::{BasicChild, Key, KeyTree, Lookup, Registry, Value, invalid, tree};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, OnceLock};

const NAME: &str = "GAMECONFIG";
const ROOT: &str = "\\Registry\\Machine\\GAMECONFIG";
const GAMECORE: &str = r"\Registry\Machine\Software\Microsoft\GameCore";
#[cfg(test)]
const APP_INFO: &str = "\\Registry\\Machine\\Software\\Microsoft\\GameCore\\AppInfo";
const MAX_HIVE_BYTES: usize = 1 << 20;
const HIVE_BASE: usize = 0x1000;
const BIG_DATA_THRESHOLD: usize = 0x3fd8;

impl Registry {
    /// The retained GameOS SOFTWARE hive has no packaged COM catalog.
    pub(crate) fn gameos_analysis_missing_key(path: &[u16]) -> bool {
        const PACKAGED_COM: &str = r"\Registry\Machine\SOFTWARE\Classes\PackagedCom";
        path.len() == PACKAGED_COM.len() && strip_component(path, PACKAGED_COM).is_some()
    }

    pub(crate) fn mount_game_config(&mut self, image: &Path) -> io::Result<()> {
        let path = image.with_file_name("microsoft_gameconfig.bin");
        let metadata = match path.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Err(invalid("GameOS game config is not a regular file"));
        }
        if metadata.len() > MAX_HIVE_BYTES as u64 {
            return Err(invalid("GameOS game config exceeds 1 MiB"));
        }
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take((MAX_HIVE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        self.game_config = Some(parse(&bytes)?);
        Ok(())
    }

    pub(crate) fn is_portable_machine_subkey(&self, path: &[u16]) -> bool {
        (self.game_config.is_some() && strip_component(path, NAME).is_some())
            || strip_component(path, r"Software\Microsoft\GameCore")
                .and_then(|relative| self.gameos_launch_subkey(relative))
                .is_some()
    }

    pub(crate) fn mount_gameos_launch_info(&mut self) -> io::Result<()> {
        let mut children = Vec::new();
        if let Some(identity) = self.game_config.as_deref().and_then(package_identity) {
            children.push((
                "AppInfo".encode_utf16().collect(),
                KeyTree {
                    values: vec![reg_sz("PackageIdentity", &identity)],
                    children: Vec::new(),
                },
            ));
        }
        self.gameos_launch_info = Some(tree::build(
            portable_case_table(),
            GAMECORE.encode_utf16().collect(),
            KeyTree {
                values: vec![reg_sz("SandboxId", "RAX-OFFLINE")],
                children,
            },
            0,
            &mut Default::default(),
            &mut Default::default(),
            None,
        )?);
        Ok(())
    }

    fn gameos_launch_subkey(&self, relative: &[u16]) -> Option<Arc<Key>> {
        match self.gameos_launch_info.as_ref()?.relative(relative) {
            Lookup::Present(key) => Some(key),
            _ => None,
        }
    }

    pub(super) fn gameos_launch_key(&self, path: &[u16]) -> Option<Arc<Key>> {
        self.gameos_launch_subkey(strip_component(path, GAMECORE)?)
    }

    pub(super) fn game_config_lookup(&self, path: &[u16]) -> Lookup {
        match (&self.game_config, strip_component(path, ROOT)) {
            (Some(root), Some([])) => Lookup::Present(root.clone()),
            (Some(root), Some(relative)) => root.relative(relative),
            _ => Lookup::Unselected,
        }
    }
}

fn reg_sz(name: &str, text: &str) -> Value {
    Value {
        name: name.encode_utf16().collect(),
        kind: 1, // REG_SZ
        data: text
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}

fn config_string(key: &Key, name: &str) -> Option<String> {
    let value = key.value(&name.encode_utf16().collect::<Vec<_>>())?;
    if value.kind != 1 || value.data.len() % 2 != 0 || value.data.len() > 16_386 {
        return None;
    }
    let units: Vec<_> = value
        .data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16(units.strip_suffix(&[0])?).ok()?;
    (!text.is_empty() && !text.contains('\0')).then_some(text)
}

fn package_identity(config: &Key) -> Option<String> {
    let name = config_string(config, "Name")?;
    let version = config_string(config, "Version")?;
    let publisher = config_string(config, "Publisher")?;
    if !(3..=50).contains(&name.len())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return None;
    }
    let version: Vec<_> = version
        .split('.')
        .map(str::parse::<u16>)
        .collect::<Result<_, _>>()
        .ok()?;
    let [major, minor, build, revision] = version[..] else {
        return None;
    };
    let publisher_id = publisher_id(&publisher);
    // The loose GameConfig contains no package architecture or resource ID.
    Some(format!(
        "{name}_{major}.{minor}.{build}.{revision}_neutral__{publisher_id}"
    ))
}

fn publisher_id(publisher: &str) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut digest = Sha256::new();
    for unit in publisher.encode_utf16() {
        digest.update(unit.to_le_bytes());
    }
    let hash = digest.finalize();
    let prefix = u64::from_be_bytes(hash[..8].try_into().unwrap());
    let bits = u128::from(prefix) << 1;
    (0..13)
        .rev()
        .map(|group| char::from(ALPHABET[((bits >> (5 * group)) & 31) as usize]))
        .collect()
}

fn strip_component<'a>(path: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let head = path.get(..prefix.len())?;
    if !head
        .iter()
        .zip(prefix.bytes())
        .all(|(&unit, byte)| u8::try_from(unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(&byte)))
    {
        return None;
    }
    match &path[prefix.len()..] {
        [] => Some(&[]),
        [92, tail @ ..] => Some(tail),
        _ => None,
    }
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn name(bytes: &[u8], compressed: bool) -> Option<Vec<u16>> {
    if compressed {
        return Some(bytes.iter().map(|&byte| u16::from(byte)).collect());
    }
    if bytes.len() % 2 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect(),
    )
}

struct Hive<'a> {
    cells: BTreeMap<u32, &'a [u8]>,
    minor: u32,
    seen_keys: BTreeSet<u32>,
    children_by_path: BTreeMap<Vec<u16>, Vec<BasicChild>>,
    values: usize,
    value_bytes: usize,
}

impl<'a> Hive<'a> {
    fn new(bytes: &'a [u8]) -> Option<(Self, u32)> {
        let header = bytes.get(..HIVE_BASE)?;
        let minor = u32_at(header, 0x18)?;
        if bytes.len() > MAX_HIVE_BYTES
            || !header.starts_with(b"regf")
            || u32_at(header, 4)? != u32_at(header, 8)?
            || u32_at(header, 0x14)? != 1
            || !matches!(minor, 3..=6)
            || u32_at(header, 0x1c)? != 0
            || u32_at(header, 0x20)? != 1
            || u32_at(header, 0x2c)? != 1
        {
            return None;
        }
        let checksum = header[..0x1fc].chunks_exact(4).fold(0, |sum, word| {
            sum ^ u32::from_le_bytes([word[0], word[1], word[2], word[3]])
        });
        let checksum = match checksum {
            0 => 1,
            u32::MAX => u32::MAX - 1,
            checksum => checksum,
        };
        if checksum != u32_at(header, 0x1fc)? {
            return None;
        }
        let length = u32_at(header, 0x28)? as usize;
        if length > MAX_HIVE_BYTES - HIVE_BASE {
            return None;
        }
        let bins = bytes.get(HIVE_BASE..HIVE_BASE + length)?;
        let mut cells = BTreeMap::new();
        let mut start = 0;
        while start < bins.len() {
            let header = bins.get(start..start + 0x20)?;
            let size = u32_at(header, 8)? as usize;
            if !header.starts_with(b"hbin")
                || u32_at(header, 4)? as usize != start
                || size < HIVE_BASE
                || size > bins.len() - start
                || size % HIVE_BASE != 0
            {
                return None;
            }
            let bin = bins.get(start..start + size)?;
            let mut position = 0x20;
            while position < bin.len() {
                let signed_size = u32_at(bin, position)? as i32;
                let size = signed_size.unsigned_abs() as usize;
                if size < 8 || size % 8 != 0 || size > bin.len() - position {
                    return None;
                }
                let payload = bin.get(position + 4..position + size)?;
                if signed_size < 0 {
                    cells.insert((start + position) as u32, payload);
                }
                position += size;
            }
            start += size;
        }
        Some((
            Self {
                cells,
                minor,
                seen_keys: BTreeSet::new(),
                children_by_path: BTreeMap::new(),
                values: 0,
                value_bytes: 0,
            },
            u32_at(header, 0x24)?,
        ))
    }

    fn key(&mut self, offset: u32, path: &[u16], depth: usize) -> Option<(BasicChild, KeyTree)> {
        if depth > tree::MAX_TREE_DEPTH
            || self.seen_keys.len() >= tree::MAX_TREE_KEYS
            || !self.seen_keys.insert(offset)
        {
            return None;
        }
        let cell = *self.cells.get(&offset)?;
        let flags = u16_at(cell, 2)?;
        if !cell.starts_with(b"nk") || flags & 0x10 != 0 || u32_at(cell, 0x18)? != 0 {
            return None;
        }
        let key_name = name(
            cell.get(0x4c..0x4c + usize::from(u16_at(cell, 0x48)?))?,
            flags & 0x20 != 0,
        )?;
        let last_write = u64::from_le_bytes(cell.get(4..12)?.try_into().ok()?);
        let path = if depth == 0 {
            path.to_vec()
        } else {
            tree::child_path(path, &key_name).ok()?
        };
        let values = self.key_values(u32_at(cell, 0x28)?, u32_at(cell, 0x24)? as usize)?;
        let count = u32_at(cell, 0x14)? as usize;
        let mut offsets = Vec::new();
        if count != 0 {
            if count >= tree::MAX_TREE_KEYS {
                return None;
            }
            self.children(u32_at(cell, 0x1c)?, &mut offsets, count, true)?;
            if count != offsets.len() {
                return None;
            }
        }
        let (metadata, children) = offsets
            .into_iter()
            .map(|child| {
                let (info, tree) = self.key(child, &path, depth + 1)?;
                let child = (info.name.clone(), tree);
                Some((info, child))
            })
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .unzip();
        self.children_by_path.insert(path, metadata);
        Some((
            BasicChild {
                name: key_name,
                last_write,
            },
            KeyTree { values, children },
        ))
    }

    fn children(&self, offset: u32, output: &mut Vec<u32>, limit: usize, root: bool) -> Option<()> {
        let cell = *self.cells.get(&offset)?;
        let count = usize::from(u16_at(cell, 2)?);
        if count == 0 || count > limit.checked_sub(output.len())? {
            return None;
        }
        let stride = match cell.get(..2)? {
            b"ri" if root => {
                for entry in cell.get(4..4 + 4 * count)?.chunks_exact(4) {
                    self.children(u32_at(entry, 0)?, output, limit, false)?;
                }
                return Some(());
            }
            b"li" => 4,
            b"lf" | b"lh" => 8,
            _ => return None,
        };
        for entry in cell.get(4..4 + stride * count)?.chunks_exact(stride) {
            output.push(u32_at(entry, 0)?);
        }
        Some(())
    }

    fn key_values(&mut self, offset: u32, count: usize) -> Option<Vec<Value>> {
        self.values = self.values.checked_add(count)?;
        if self.values > super::MAX_VALUES {
            return None;
        }
        if count == 0 {
            return Some(Vec::new());
        }
        let offsets = self.cells.get(&offset)?.get(..count * 4)?;
        offsets
            .chunks_exact(4)
            .map(|entry| {
                let value = *self.cells.get(&u32_at(entry, 0)?)?;
                if !value.starts_with(b"vk") {
                    return None;
                }
                let name_size = usize::from(u16_at(value, 2)?);
                let raw_length = u32_at(value, 4)?;
                let length = (raw_length & 0x7fff_ffff) as usize;
                // Account for repeated references as well as unique bytes in
                // the hive. Compressed names may expand 2:1 in memory.
                self.value_bytes = self.value_bytes.checked_add(length + 2 * name_size)?;
                if self.value_bytes > MAX_HIVE_BYTES {
                    return None;
                }
                let data = if raw_length >> 31 != 0 {
                    value.get(8..12)?.get(..length)?
                } else if length == 0 {
                    &[]
                } else {
                    if self.minor >= 5 && length > BIG_DATA_THRESHOLD {
                        return None;
                    }
                    self.cells.get(&u32_at(value, 8)?)?.get(..length)?
                };
                Some(Value {
                    name: name(value.get(20..20 + name_size)?, u16_at(value, 16)? & 1 != 0)?,
                    kind: u32_at(value, 12)?,
                    data: data.to_vec(),
                })
            })
            .collect()
    }
}

fn portable_case_table() -> Arc<[u16]> {
    // Use invariant one-unit uppercase mappings, preserving unpaired UTF-16 units.
    static TABLE: OnceLock<Arc<[u16]>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            (0..=u16::MAX)
                .map(|unit| {
                    let Some(ch) = char::from_u32(u32::from(unit)) else {
                        return unit;
                    };
                    let mut upper = ch.to_uppercase();
                    let first = upper.next().unwrap_or(ch);
                    if upper.next().is_none() {
                        u16::try_from(first as u32).unwrap_or(unit)
                    } else {
                        unit
                    }
                })
                .collect()
        })
        .clone()
}

fn parse(bytes: &[u8]) -> io::Result<Arc<Key>> {
    let (mut hive, root) =
        Hive::new(bytes).ok_or_else(|| invalid("invalid GameOS REGF header or bins"))?;
    let root_path: Vec<_> = ROOT.encode_utf16().collect();
    let (_, config) = hive
        .key(root, &root_path, 0)
        .ok_or_else(|| invalid("unsupported or invalid GameOS REGF key data"))?;
    let mut values = super::ValueBudget::default();
    let mut root = tree::build(
        portable_case_table(),
        root_path,
        config,
        0,
        &mut values,
        &mut Default::default(),
        None,
    )?;
    attach_children(&mut root, &mut hive.children_by_path, &mut values)?;
    Ok(root)
}

fn attach_children(
    key: &mut Arc<Key>,
    children_by_path: &mut BTreeMap<Vec<u16>, Vec<BasicChild>>,
    values: &mut super::ValueBudget,
) -> io::Result<()> {
    let key = Arc::get_mut(key).ok_or_else(|| invalid("shared unpublished GameOS key"))?;
    let metadata = children_by_path
        .remove(&key.path)
        .ok_or_else(|| invalid("missing GameOS key metadata"))?;
    key.enumeration =
        super::key_enumeration::bounded(&key.upcase, Some(metadata), key.children, values)?;
    if let Some(children) = &mut key.subkeys {
        for child in children.values_mut() {
            attach_children(child, children_by_path, values)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_com_catalog_absence_applies_only_to_the_observed_key() {
        let name = r"\REGISTRY\MACHINE\Software\Classes\PackagedCom";
        assert!(Registry::gameos_analysis_missing_key(
            &name.encode_utf16().collect::<Vec<_>>()
        ));
        for suffix in ["Extra", r"\ClassIndex"] {
            assert!(!Registry::gameos_analysis_missing_key(
                &name
                    .encode_utf16()
                    .chain(suffix.encode_utf16())
                    .collect::<Vec<_>>()
            ));
        }
    }

    #[test]
    fn derives_analysis_package_full_name_from_config_strings() {
        let path = |text: &str| text.encode_utf16().collect::<Vec<_>>();
        let mut registry = Registry {
            game_config: Some(tree::build(
                parse(&fixture()).unwrap().upcase.clone(),
                path(ROOT),
                KeyTree {
                    values: [
                        ("Name", "Microsoft.Windows.Photos"),
                        ("Version", "2020.20090.1002.0"),
                        ("Publisher", "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"),
                    ].map(|(name, value)| Value {
                        name: path(name),
                        kind: 1,
                        data: value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect(),
                    }).to_vec(),
                    children: Vec::new(),
                },
                0,
                &mut Default::default(),
                &mut Default::default(),
                None,
            ).unwrap()),
            ..Default::default()
        };
        assert!(registry.key(&path(APP_INFO)).is_none());
        registry.mount_gameos_launch_info().unwrap();
        let app_info = registry.key(&path(&APP_INFO.to_ascii_lowercase())).unwrap();
        assert_eq!(
            config_string(&app_info, "PackageIdentity").as_deref(),
            Some("Microsoft.Windows.Photos_2020.20090.1002.0_neutral__8wekyb3d8bbwe")
        );
        assert!(app_info.value(&path("InstallIdentity")).is_none());
    }

    #[test]
    fn analysis_sandbox_id_is_available_without_a_title_config() {
        let path = |text: &str| text.encode_utf16().collect::<Vec<_>>();
        let mut registry = Registry::default();
        assert!(registry.key(&path(GAMECORE)).is_none());
        registry.mount_gameos_launch_info().unwrap();
        let root = registry.key(&path(GAMECORE)).unwrap();
        assert_eq!(
            config_string(&root, "SandboxId").as_deref(),
            Some("RAX-OFFLINE")
        );
        assert!(registry.is_portable_machine_subkey(&path(r"Software\Microsoft\GameCore")));
        assert!(registry.key(&path(APP_INFO)).is_none());
    }

    fn put(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 2 * HIVE_BASE];
        bytes[..4].copy_from_slice(b"regf");
        for (at, value) in [
            (4, 1),
            (8, 1),
            (0x14, 1),
            (0x18, 3),
            (0x20, 1),
            (0x24, 0x20),
            (0x28, 0x1000),
            (0x2c, 1),
        ] {
            put(&mut bytes, at, value);
        }
        put(
            &mut bytes,
            0x1fc,
            u32::from_le_bytes(*b"regf") ^ 3 ^ 0x20 ^ 0x1000 ^ 1,
        );
        let bin = &mut bytes[HIVE_BASE..];
        bin[..4].copy_from_slice(b"hbin");
        put(bin, 8, 0x1000);
        put(bin, 0x20, (-0x58i32) as u32);
        bin[0x24..0x28].copy_from_slice(b"nk\x20\0");
        put(bin, 0x24 + 0x14, 1);
        put(bin, 0x24 + 0x1c, 0xa0);
        put(bin, 0x24 + 0x24, 1);
        put(bin, 0x24 + 0x28, 0x78);
        bin[0x24 + 0x48] = 4;
        bin[0x24 + 0x4c..0x24 + 0x50].copy_from_slice(b"ROOT");
        put(bin, 0x78, (-8i32) as u32);
        put(bin, 0x7c, 0x80);
        put(bin, 0x80, (-0x20i32) as u32);
        bin[0x84..0x88].copy_from_slice(b"vk\x07\0");
        put(bin, 0x88, 0x8000_0004);
        put(bin, 0x8c, 0x1234_5678);
        put(bin, 0x90, 4);
        put(bin, 0x94, 1);
        bin[0x98..0x9f].copy_from_slice(b"TitleId");
        put(bin, 0xa0, (-0x10i32) as u32);
        bin[0xa4..0xa8].copy_from_slice(b"li\x01\0");
        put(bin, 0xa8, 0xb0);
        put(bin, 0xb0, (-0x58i32) as u32);
        bin[0xb4..0xb8].copy_from_slice(b"nk\x20\0");
        put(bin, 0xb8, 0xabcd);
        bin[0xb4 + 0x48] = 4;
        bin[0xb4 + 0x4c..0xb4 + 0x50].copy_from_slice(b"Leaf");
        put(bin, 0x108, 0xef8);
        bytes
    }

    #[test]
    fn game_config_mount_reads_inline_values_without_enabling_other_hives() {
        let registry = Registry {
            game_config: Some(parse(&fixture()).unwrap()),
            ..Default::default()
        };
        let path = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        let key = registry
            .key(&path(r"\registry\machine\gameconfig"))
            .unwrap();
        let value = key.value(&path("TITLEID")).unwrap();
        assert_eq!(value.kind, 4);
        assert_eq!(value.data, 0x1234_5678u32.to_le_bytes());
        assert_eq!(
            key.child_metadata().unwrap(),
            &[BasicChild {
                name: path("Leaf"),
                last_write: 0xabcd,
            }]
        );
        assert!(
            registry
                .key(&path(r"\Registry\Machine\GAMECONFIG\LEAF"))
                .is_some()
        );
        assert!(matches!(
            registry.lookup(&path(r"\Registry\Machine\GAMECONFIG\Missing")),
            Lookup::Missing
        ));
        assert!(matches!(
            registry.lookup(&path(r"\Registry\Machine\GAMECONFIGURATION")),
            Lookup::Unselected
        ));
        assert!(registry.upcase_table().is_empty());
    }

    #[test]
    fn game_config_rejects_out_of_cell_references_and_dirty_hives() {
        let mut bytes = fixture();
        put(&mut bytes, HIVE_BASE + 0x7c, 0x84);
        assert!(parse(&bytes).is_err());
        let mut bytes = fixture();
        put(&mut bytes, HIVE_BASE + 0xa8, 0x20);
        assert!(parse(&bytes).is_err());
        let mut bytes = fixture();
        put(&mut bytes, 4, 2);
        assert!(parse(&bytes).is_err());
        assert!(parse(&fixture()[..2 * HIVE_BASE - 1]).is_err());
    }
}
