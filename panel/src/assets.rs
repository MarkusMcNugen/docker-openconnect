//! The stylesheet, script, fonts and images the pages use, built into the
//! program. Each is served at /assets/<name> and linked with its content hash
//! in the query, so browsers may cache it for a year: a new build changes the
//! link. The stylesheet links the fonts by names that carry their version.

use sha2::{Digest, Sha256};

/// One embedded file.
pub struct Asset {
    pub name: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
    /// The first 12 hex digits of the SHA-256 of `bytes`.
    pub hash: String,
}

/// Every embedded file.
pub struct Assets {
    files: Vec<Asset>,
}

const FILES: [(&str, &str, &[u8]); 6] = [
    (
        "app.css",
        "text/css; charset=utf-8",
        include_bytes!("../assets/app.css"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/app.js"),
    ),
    (
        "logo.svg",
        "image/svg+xml",
        include_bytes!("../assets/logo.svg"),
    ),
    (
        "logo-outline.svg",
        "image/svg+xml",
        include_bytes!("../assets/logo-outline.svg"),
    ),
    // Geist and Geist Mono (SIL Open Font License 1.1), the variable fonts of
    // release 1.9.2 as published, every weight in one file each.
    (
        "geist-1.9.2.woff2",
        "font/woff2",
        include_bytes!("../assets/fonts/geist-1.9.2.woff2"),
    ),
    (
        "geist-mono-1.9.2.woff2",
        "font/woff2",
        include_bytes!("../assets/fonts/geist-mono-1.9.2.woff2"),
    ),
];

macro_rules! flags {
    ($($code:literal),* $(,)?) => {
        &[$((
            concat!("flag-", $code, ".svg"),
            include_bytes!(concat!("../assets/flags/", $code, ".svg")) as &[u8],
        )),*]
    };
}

/// Country flags (flag-icons, MIT license), as flag-<code>.svg with the
/// lower-case ISO 3166 code; flag-xx.svg stands for an unknown country.
const FLAGS: &[(&str, &[u8])] = flags![
    "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs",
    "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn",
    "co", "cp", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dg", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb",
    "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw",
    "gy", "hk", "hm", "hn", "hr", "ht", "hu", "ic", "id", "ie", "il", "im", "in", "io", "iq", "ir",
    "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky",
    "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me",
    "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw",
    "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
    "pa", "pc", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa",
    "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl",
    "sm", "sn", "so", "sr", "ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj",
    "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "um", "un", "us", "uy",
    "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xk", "xx", "ye", "yt", "za", "zm",
    "zw",
];

impl Assets {
    pub fn new() -> Assets {
        let flags = FLAGS
            .iter()
            .map(|&(name, bytes)| (name, "image/svg+xml", bytes));
        let files = FILES
            .iter()
            .copied()
            .chain(flags)
            .map(|(name, content_type, bytes)| Asset {
                name,
                content_type,
                bytes,
                hash: Sha256::digest(bytes)
                    .iter()
                    .take(6)
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            })
            .collect();
        Assets { files }
    }

    /// The embedded file with this name.
    pub fn get(&self, name: &str) -> Option<&Asset> {
        self.files.iter().find(|asset| asset.name == name)
    }

    /// The link to an embedded file, with its hash; a name that is not
    /// embedded links to itself, and the request for it is answered 404.
    pub fn url(&self, name: &str) -> String {
        match self.get(name) {
            Some(asset) => format!("/assets/{}?v={}", asset.name, asset.hash),
            None => format!("/assets/{name}"),
        }
    }

    /// The link to the flag of the country with this ISO code, in either
    /// case; a code without a flag links the flag of an unknown country.
    pub fn flag(&self, code: &str) -> String {
        let name = format!("flag-{}.svg", code.to_ascii_lowercase());
        match self.get(&name) {
            Some(flag) => format!("/assets/{}?v={}", flag.name, flag.hash),
            None => self.url("flag-xx.svg"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_carry_the_content_hash() {
        let assets = Assets::new();
        let link = assets.url("app.css");
        let hash = &assets.get("app.css").unwrap().hash;
        assert_eq!(hash.len(), 12);
        assert_eq!(link, format!("/assets/app.css?v={hash}"));
        assert!(assets.get("missing.css").is_none());
    }

    #[test]
    fn every_file_the_stylesheet_links_is_embedded() {
        let assets = Assets::new();
        let css = String::from_utf8_lossy(assets.get("app.css").unwrap().bytes).into_owned();
        let linked: Vec<&str> = css
            .split("url(\"/assets/")
            .skip(1)
            .map(|rest| &rest[..rest.find('"').unwrap()])
            .collect();
        assert_eq!(linked, ["geist-1.9.2.woff2", "geist-mono-1.9.2.woff2"]);
        for name in linked {
            assert_eq!(assets.get(name).unwrap().content_type, "font/woff2");
        }
    }

    #[test]
    fn every_country_has_a_flag_and_an_unknown_code_the_blank_one() {
        let assets = Assets::new();
        assert!(assets.flag("CN").starts_with("/assets/flag-cn.svg?v="));
        assert_eq!(assets.flag("zz"), assets.url("flag-xx.svg"));
        assert_eq!(
            assets.get("flag-us.svg").unwrap().content_type,
            "image/svg+xml"
        );
    }
}
