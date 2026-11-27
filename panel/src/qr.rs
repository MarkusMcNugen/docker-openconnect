//! QR codes for setting up an authenticator app, drawn as SVG.

use qrcodegen::{QrCode, QrCodeEcc};

/// The light margin around a code, in modules, as the QR standard asks.
const QUIET_ZONE: i32 = 4;

/// `text` as a QR code at medium error correction: an SVG of one path of
/// dark modules over a light square. It carries classes for the stylesheet
/// and no style of its own, and a label for screen readers.
pub fn svg(text: &str) -> Result<String, String> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium)
        .map_err(|error| format!("the QR code could not be made: {error}"))?;
    let size = code.size();
    let side = size + 2 * QUIET_ZONE;
    let mut path = String::new();
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if !code.get_module(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < size && code.get_module(x, y) {
                x += 1;
            }
            let run = x - start;
            path.push_str(&format!(
                "M{},{}h{run}v1h-{run}z",
                start + QUIET_ZONE,
                y + QUIET_ZONE
            ));
        }
    }
    Ok(format!(
        "<svg class=\"qr\" viewBox=\"0 0 {side} {side}\" role=\"img\" \
         aria-label=\"QR code of your authenticator key\" shape-rendering=\"crispEdges\">\
         <rect class=\"qr-light\" width=\"{side}\" height=\"{side}\"/>\
         <path class=\"qr-dark\" d=\"{path}\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/OpenConnect%20admin:alex?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                       &issuer=OpenConnect%20admin&algorithm=SHA1&digits=6&period=30";

    /// The modules a path covers, from its `M x,y h w v1 h-w z` runs.
    fn covered(path: &str) -> Vec<(i32, i32)> {
        let mut cells = Vec::new();
        for run in path.split('M').filter(|run| !run.is_empty()) {
            let (start, rest) = run.split_once('h').unwrap();
            let (x, y) = start.split_once(',').unwrap();
            let width: i32 = rest.split_once('v').unwrap().0.parse().unwrap();
            let (x, y): (i32, i32) = (x.parse().unwrap(), y.parse().unwrap());
            cells.extend((x..x + width).map(|column| (column, y)));
        }
        cells
    }

    #[test]
    fn the_path_covers_exactly_the_dark_modules() {
        let drawn = svg(URI).unwrap();
        let path = drawn
            .split("d=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let code = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
        let mut dark = Vec::new();
        for y in 0..code.size() {
            for x in 0..code.size() {
                if code.get_module(x, y) {
                    dark.push((x + QUIET_ZONE, y + QUIET_ZONE));
                }
            }
        }
        assert_eq!(covered(path), dark);
    }

    #[test]
    fn the_drawing_has_a_quiet_zone_and_starts_with_a_finder_pattern() {
        let code = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
        let side = code.size() + 2 * QUIET_ZONE;
        let drawn = svg(URI).unwrap();
        assert!(
            drawn.contains(&format!("viewBox=\"0 0 {side} {side}\"")),
            "{drawn}"
        );
        assert!(drawn.contains("d=\"M4,4h7v1h-7z"), "{drawn}");
        assert!(!drawn.contains("style"), "{drawn}");
    }

    #[test]
    fn text_too_long_for_any_code_is_an_error() {
        assert!(svg(&"x".repeat(4000)).is_err());
    }
}
