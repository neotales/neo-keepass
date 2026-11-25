// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Entry, Field, Hotp, HotpParameters, KeePassXcOtp, OtpAlgorithm, OtpDigits, OtpEncoder, OtpKind,
    OtpSecret, OtpUri, OtpUriParams, ProtectedValue,
};

#[test]
fn hotp_rfc4226_vectors() {
    let secret = b"12345678901234567890";
    let parameters = HotpParameters {
        secret,
        algorithm: OtpAlgorithm::Sha1,
        digits: OtpDigits::Six,
        counter: 0,
    };
    assert_eq!(Hotp::generate(&parameters), "755224");
    assert_eq!(
        Hotp::generate(&HotpParameters {
            counter: 1,
            ..parameters
        }),
        "287082"
    );
}

#[test]
fn keepassxc_modern_otp_field_round_trips() {
    let uri = OtpUri::parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30").unwrap();
    let mut entry = Entry::new("alice");
    KeePassXcOtp::write(&mut entry, &uri);
    assert!(KeePassXcOtp::is_present(&entry));
    let loaded = KeePassXcOtp::read(&entry).unwrap();
    assert_eq!(loaded.secret, "JBSWY3DPEHPK3PXP");
    assert!(!format!("{loaded:?}").contains("JBSWY3DPEHPK3PXP"));
    assert!(format!("{loaded}").contains("JBSWY3DPEHPK3PXP"));
    assert!(KeePassXcOtp::remove(&mut entry));
}

#[test]
fn base32_decodes_strict_and_padded_whitespace_secrets() {
    let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(secret.expose(), b"Hello!\xde\xad\xbe\xef");

    let padded = OtpSecret::from_base32("  MFRG GZDF MZTW Q=== \n").unwrap();
    assert_eq!(padded.expose(), b"abcdefgh");

    assert!(OtpSecret::from_base32("JBSWY3DPEHPK3PX!").is_err());
    assert!(OtpSecret::from_base32("JBSW=3DPEHPK3PXP").is_err());
    assert!(OtpSecret::from_base32("MFRGGZDFMZTWQ==").is_err());
    assert!(OtpUri::parse("otpauth://totp/a?secret=not-base32!&period=30").is_err());
}

#[test]
fn totp_defaults_period_allows_benign_params_and_supports_steam() {
    let parsed = OtpUri::parse(
        "otpauth://totp/Example:alice?secret=JBSW%20Y3DP==&issuer=Example&image=https://example.test/icon.png",
    );
    // %20 is not valid Base32, test standard whitespace/padding and benign image param:
    assert!(parsed.is_err());

    let parsed = OtpUri::parse(
        "otpauth://totp/Example:alice?secret=MFRGGZDFMZTWQ===&issuer=Example&image=https://example.test/icon.png",
    )
    .unwrap();
    assert_eq!(parsed.period, Some(30));
    assert_eq!(parsed.issuer.as_deref(), Some("Example"));
    assert_eq!(
        parsed.image.as_deref(),
        Some("https://example.test/icon.png")
    );
    assert_eq!(parsed.secret, "MFRGGZDFMZTWQ");
    assert_eq!(parsed.encoder, OtpEncoder::Standard);

    let steam =
        OtpUri::parse("otpauth://totp/Steam:alice?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
    assert_eq!(steam.encoder, OtpEncoder::Steam);
    assert_eq!(steam.digits, OtpDigits::Five);
    assert_eq!(steam.period, Some(30));
    let code = steam.generate_code(59).unwrap();
    assert_eq!(code.len(), 5);
    assert!(
        code.chars()
            .all(|ch| "23456789BCDFGHJKMNPQRTVWXY".contains(ch)),
        "steam code must use Steam Guard alphabet: {code:?}"
    );
}

#[test]
fn read_entry_fallback_supports_unprotected_otp_and_keepass2_timeotp() {
    let mut unprotected = Entry::new("unprotected");
    unprotected.set_field(Field::new(
        "otp",
        "otpauth://totp/unprotected?secret=JBSWY3DPEHPK3PXP",
    ));
    assert!(!KeePassXcOtp::is_present(&unprotected));
    assert!(KeePassXcOtp::read(&unprotected).is_err());
    let loaded = KeePassXcOtp::read_entry_fallback(&unprotected).unwrap();
    assert_eq!(loaded.period, Some(30));
    assert_eq!(loaded.secret, "JBSWY3DPEHPK3PXP");

    let mut kp2 = Entry::new("kp2");
    kp2.set_field(Field {
        key: "TimeOtp-Secret-Base32".into(),
        value: ProtectedValue::from_text("MFRG GZDF MZTW Q==="),
        protected: true,
        protect_in_memory: true,
    });
    kp2.set_field(Field::new("TimeOtp-Algorithm", "HMAC-SHA-256"));
    kp2.set_field(Field::new("TimeOtp-Length", "8"));
    kp2.set_field(Field::new("TimeOtp-Period", "45"));
    let loaded_kp2 = KeePassXcOtp::read_entry_fallback(&kp2).unwrap();
    assert_eq!(loaded_kp2.kind, OtpKind::Totp);
    assert_eq!(loaded_kp2.algorithm, OtpAlgorithm::Sha256);
    assert_eq!(loaded_kp2.digits, OtpDigits::Eight);
    assert_eq!(loaded_kp2.period, Some(45));
    assert_eq!(loaded_kp2.secret, "MFRGGZDFMZTWQ");
}

#[test]
fn format_uri_builder_round_trips_totp_hotp_and_steam() {
    let totp = OtpUri::format_uri(OtpUriParams {
        kind: OtpKind::Totp,
        account: "Example:alice",
        issuer: Some("Example"),
        secret: "MFRGGZDFMZTWQ===",
        algorithm: OtpAlgorithm::Sha256,
        digits: OtpDigits::Eight,
        counter: None,
        period: None,
        encoder: OtpEncoder::Standard,
    })
    .unwrap();
    let parsed_totp = OtpUri::parse(&totp).unwrap();
    assert_eq!(parsed_totp.period, Some(30));
    assert_eq!(parsed_totp.digits, OtpDigits::Eight);
    assert_eq!(parsed_totp.algorithm, OtpAlgorithm::Sha256);

    let hotp = OtpUri::format_uri(OtpUriParams {
        kind: OtpKind::Hotp,
        account: "Example:bob",
        issuer: None,
        secret: "JBSWY3DPEHPK3PXP",
        algorithm: OtpAlgorithm::Sha1,
        digits: OtpDigits::Six,
        counter: Some(7),
        period: None,
        encoder: OtpEncoder::Standard,
    })
    .unwrap();
    let parsed_hotp = OtpUri::parse(&hotp).unwrap();
    assert_eq!(parsed_hotp.kind, OtpKind::Hotp);
    assert_eq!(parsed_hotp.counter, Some(7));

    let steam = OtpUri::format_uri(OtpUriParams {
        kind: OtpKind::Totp,
        account: "Steam:alice",
        issuer: Some("Steam"),
        secret: "JBSWY3DPEHPK3PXP",
        algorithm: OtpAlgorithm::Sha1,
        digits: OtpDigits::Five,
        counter: None,
        period: Some(30),
        encoder: OtpEncoder::Steam,
    })
    .unwrap();
    let parsed_steam = OtpUri::parse(&steam).unwrap();
    assert_eq!(parsed_steam.encoder, OtpEncoder::Steam);
    assert_eq!(parsed_steam.digits, OtpDigits::Five);
}
