//! Semantic versions, for monotonic installs.
//!
//! A device installs only a version greater than the one it runs, unless the
//! job says `downgrade` (only the owner's `rollback` override does). So a
//! renamed or replayed old image, or a stale job, cannot take a device back.

use std::cmp::Ordering;
use std::fmt;

/// `MAJOR.MINOR.PATCH[-PRE][+BUILD]`. Build metadata is ignored, as semver
/// says; pre-release identifiers order as semver says (`0.9.0-rc.1 < 0.9.0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pre: Vec<Ident>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alpha(String),
}

impl Version {
    /// Parses a bare version, or one [`crate::normalize_version`] can reduce
    /// to one (`v0.9.0`, `firmware_v0.9.0`, `vaktus/v0.9.0`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = crate::normalize_version(raw);
        let bad = || format!("{raw:?} is not a version (X.Y.Z)");
        let s = s.split_once('+').map_or(s, |(v, _build)| v);
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut number = || -> Result<u64, String> {
            let p = parts.next().ok_or_else(bad)?;
            if p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return Err(bad());
            }
            p.parse().map_err(|_| bad())
        };
        let (major, minor, patch) = (number()?, number()?, number()?);
        if parts.next().is_some() {
            return Err(bad());
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|id| {
                    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        Err(bad())
                    } else if id.bytes().all(|b| b.is_ascii_digit()) {
                        id.parse().map(Ident::Num).map_err(|_| bad())
                    } else {
                        Ok(Ident::Alpha(id.to_string()))
                    }
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A pre-release precedes its release.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = match (a, b) {
                            (Ident::Num(a), Ident::Num(b)) => a.cmp(b),
                            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
                            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
                            (Ident::Alpha(a), Ident::Alpha(b)) => a.cmp(b),
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                Ident::Num(n) => write!(f, "{n}")?,
                Ident::Alpha(s) => f.write_str(s)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn release_names_reduce_to_versions() {
        for s in [
            "0.9.0",
            "v0.9.0",
            "firmware_v0.9.0",
            "vaktus/v0.9.0",
            "0.9.0+build.7",
        ] {
            assert_eq!(v(s), v("0.9.0"), "{s}");
        }
        assert_eq!(v("1.2.3-rc.1").to_string(), "1.2.3-rc.1");
    }

    #[test]
    fn non_versions_are_refused() {
        for s in [
            "",
            "latest",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.2.x",
            "1.2.3-",
            "1.2.3-a..b",
        ] {
            assert!(Version::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn versions_order_as_semver_says() {
        let ordered = [
            "0.8.0",
            "0.9.0-alpha",
            "0.9.0-alpha.1",
            "0.9.0-alpha.beta",
            "0.9.0-beta.2",
            "0.9.0-beta.11",
            "0.9.0-rc.1",
            "0.9.0",
            "0.9.1",
            "0.10.0",
            "1.0.0",
        ];
        for w in ordered.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        assert_eq!(v("0.9.0").cmp(&v("v0.9.0+meta")), Ordering::Equal);
    }
}
