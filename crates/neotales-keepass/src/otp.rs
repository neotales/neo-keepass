use std::collections::BTreeMap;
use std::fmt;

use hmac::{KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KdbxError, KdbxFailureKind};
use crate::model::Entry;

/// HMAC algorithm used by an OTP secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Number of digits in an OTP code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtpDigits {
    /// Five characters (Steam Guard).
    Five,
    /// Six digits.
    Six,
    /// Eight digits.
    Eight,
}

impl OtpDigits {
    fn count(self) -> u32 {
        match self {
            Self::Five => 5,
            Self::Six => 6,
            Self::Eight => 8,
        }
    }
}

/// OTP code formatting encoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OtpEncoder {
    /// Standard numeric digits (RFC 4226 / RFC 6238).
    #[default]
    Standard,
    /// Steam Guard 5-character alphanumeric alphabet.
    Steam,
}

/// Zeroizing OTP secret bytes.
///
/// [`Debug`](std::fmt::Debug) is hand-written and reports the decoded length
/// and nothing else. These are the shared TOTP/HOTP seed bytes: every code the
/// generator produces is an HMAC under this value, so printing it hands an
/// attacker a long-lived factor that survives every password rotation and every
/// compromise of the surrounding vault. The `Vec<u8>` is a plain buffer rather
/// than a `Zeroizing` one, so unlike [`crate::model::ChaCha20MemoryProtection`]
/// there is no wrapper whose `Debug` had to be outmanoeuvred — a derive would
/// simply have printed the bytes. The length is worth keeping: a seed that
/// decoded to zero bytes, or to the handful of lengths a truncated Base32
/// encoding produces, is a real configuration error, and the length is the only
/// part of the value that is not the secret.
pub struct OtpSecret(Vec<u8>);

impl OtpSecret {
    /// Decodes Base32, allowing standard trailing `=` padding and ASCII whitespace.
    ///
    /// # Errors
    ///
    /// Returns malformed-input for invalid characters, invalid padding, or non-zero
    /// trailing bits.
    pub fn from_base32(value: &str) -> Result<Self, KdbxError> {
        Ok(Self(decode_base32(value)?))
    }
    /// Returns the secret length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for OtpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for OtpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The seed bytes are never printed. See the type documentation.
        formatter
            .debug_struct("OtpSecret")
            .field("len", &self.0.len())
            .finish()
    }
}

/// HOTP parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotpParameters<'a> {
    /// Shared secret bytes.
    pub secret: &'a [u8],
    /// HMAC algorithm.
    pub algorithm: OtpAlgorithm,
    /// Code width.
    pub digits: OtpDigits,
    /// Initial counter.
    pub counter: u64,
}
/// TOTP parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpParameters<'a> {
    /// Shared secret bytes.
    pub secret: &'a [u8],
    /// HMAC algorithm.
    pub algorithm: OtpAlgorithm,
    /// Code width.
    pub digits: OtpDigits,
    /// Time step in seconds.
    pub period: u64,
}

/// HOTP RFC 4226 generator.
///
/// [`Debug`](std::fmt::Debug) is derived, and this is provably safe:
/// `Hotp` is a unit struct. The secret is passed to
/// [`Hotp::generate`] as an argument and is never stored here, so there is
/// nothing for a derive to print.
#[derive(Debug)]
pub struct Hotp;
/// TOTP RFC 6238 generator.
///
/// [`Debug`](std::fmt::Debug) is derived for the same reason as [`Hotp`]: a
/// unit struct, with the secret supplied per call to [`Totp::generate`].
#[derive(Debug)]
pub struct Totp;

impl Hotp {
    /// Generates one code.
    #[must_use]
    pub fn generate(parameters: &HotpParameters<'_>) -> String {
        generate(
            parameters.secret,
            parameters.counter,
            parameters.algorithm,
            parameters.digits,
        )
    }
    /// Verifies a code within an optional forward window.
    #[must_use]
    pub fn verify(code: &str, parameters: &HotpParameters<'_>, lookahead: u64) -> bool {
        (0..=lookahead).any(|offset| {
            constant_time_eq(
                code.as_bytes(),
                generate(
                    parameters.secret,
                    parameters.counter.saturating_add(offset),
                    parameters.algorithm,
                    parameters.digits,
                )
                .as_bytes(),
            )
        })
    }
}
impl Totp {
    /// Generates a code for a Unix timestamp.
    #[must_use]
    pub fn generate(parameters: &TotpParameters<'_>, timestamp: u64) -> String {
        let counter = if parameters.period == 0 {
            0
        } else {
            timestamp / parameters.period
        };
        generate(
            parameters.secret,
            counter,
            parameters.algorithm,
            parameters.digits,
        )
    }
    /// Generates a Steam Guard 5-character TOTP code for a Unix timestamp.
    #[must_use]
    pub fn generate_steam(secret: &[u8], timestamp: u64) -> String {
        let counter = timestamp / 30;
        generate_with_encoder(
            secret,
            counter,
            OtpAlgorithm::Sha1,
            OtpDigits::Five,
            OtpEncoder::Steam,
        )
    }
    /// Verifies a code in past/future windows.
    #[must_use]
    pub fn verify(
        code: &str,
        parameters: &TotpParameters<'_>,
        timestamp: u64,
        window: u64,
    ) -> bool {
        let Some(period) = (parameters.period > 0).then_some(parameters.period) else {
            return false;
        };
        let counter = timestamp / period;
        (counter.saturating_sub(window)..=counter.saturating_add(window)).any(|value| {
            constant_time_eq(
                code.as_bytes(),
                generate(
                    parameters.secret,
                    value,
                    parameters.algorithm,
                    parameters.digits,
                )
                .as_bytes(),
            )
        })
    }
}

fn generate(secret: &[u8], counter: u64, algorithm: OtpAlgorithm, digits: OtpDigits) -> String {
    generate_with_encoder(secret, counter, algorithm, digits, OtpEncoder::Standard)
}

fn generate_with_encoder(
    secret: &[u8],
    counter: u64,
    algorithm: OtpAlgorithm,
    digits: OtpDigits,
    encoder: OtpEncoder,
) -> String {
    const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
    let message = counter.to_be_bytes();
    let digest = match algorithm {
        OtpAlgorithm::Sha1 => hmac_sha1(secret, &message),
        OtpAlgorithm::Sha256 => hmac_sha256(secret, &message),
        OtpAlgorithm::Sha512 => hmac_sha512(secret, &message),
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    match encoder {
        OtpEncoder::Standard => format!(
            "{:0width$}",
            value % 10_u32.pow(digits.count()),
            width = digits.count() as usize
        ),
        OtpEncoder::Steam => {
            let mut code = String::with_capacity(5);
            let mut remaining = value;
            for _ in 0..5 {
                code.push(STEAM_ALPHABET[(remaining % 26) as usize] as char);
                remaining /= 26;
            }
            code
        }
    }
}
fn hmac_sha1(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
fn hmac_sha256(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
fn hmac_sha512(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}
fn normalize_base32(value: &str) -> Result<Zeroizing<String>, KdbxError> {
    let mut cleaned = Zeroizing::new(String::with_capacity(value.len()));
    for byte in value.bytes() {
        if !byte.is_ascii_whitespace() {
            cleaned.push(byte as char);
        }
    }
    let trimmed = cleaned.trim_end_matches('=');
    let pad = cleaned.len() - trimmed.len();
    if trimmed.is_empty() || trimmed.contains('=') {
        return Err(KdbxError::malformed("invalid OTP Base32"));
    }
    if pad > 0 && ((trimmed.len() + pad) % 8 != 0 || !matches!(pad, 1 | 3 | 4 | 6)) {
        return Err(KdbxError::malformed("invalid OTP Base32"));
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn decode_base32(value: &str) -> Result<Vec<u8>, KdbxError> {
    let trimmed = normalize_base32(value)?;
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for character in trimmed.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a',
            b'2'..=b'7' => character - b'2' + 26,
            _ => return Err(KdbxError::malformed("invalid OTP Base32 character")),
        } as u32;
        buffer = (buffer << 5) | digit;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if bits > 0 && buffer != 0 {
        return Err(KdbxError::malformed(
            "OTP Base32 has non-zero trailing bits",
        ));
    }
    Ok(output)
}

/// Structured parameters for building an [`OtpUri`].
///
/// [`fmt::Debug`] is hand-written and redacts `secret`.
#[derive(Clone)]
pub struct OtpUriParams<'a> {
    /// URI algorithm family (`Totp` or `Hotp`).
    pub kind: OtpKind,
    /// Account label.
    pub account: &'a str,
    /// Optional issuer label.
    pub issuer: Option<&'a str>,
    /// Base32-encoded shared secret.
    pub secret: &'a str,
    /// HMAC algorithm.
    pub algorithm: OtpAlgorithm,
    /// Code width.
    pub digits: OtpDigits,
    /// HOTP counter (required for `Hotp`).
    pub counter: Option<u64>,
    /// TOTP period in seconds (defaults to 30 for `Totp` when `None`).
    pub period: Option<u64>,
    /// Output encoder (`Standard` or `Steam`).
    pub encoder: OtpEncoder,
}

impl fmt::Debug for OtpUriParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OtpUriParams")
            .field("kind", &self.kind)
            .field("account", &self.account)
            .field("issuer", &self.issuer)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("counter", &self.counter)
            .field("period", &self.period)
            .field("encoder", &self.encoder)
            .finish()
    }
}

/// A parsed `otpauth://` URI.
///
/// The encoded secret is zeroized when this value is dropped and is redacted
/// from [`fmt::Debug`]. [`fmt::Display`] deliberately emits the complete URI,
/// including the secret, so applications must not log that representation.
#[derive(Clone, Eq, PartialEq)]
pub struct OtpUri {
    /// URI algorithm family.
    pub kind: OtpKind,
    /// Account label.
    pub account: String,
    /// Optional issuer.
    pub issuer: Option<String>,
    /// Optional icon image URL/URI.
    pub image: Option<String>,
    /// Strict, unpadded Base32 secret. This owned buffer is zeroized on drop.
    pub secret: String,
    /// HMAC algorithm.
    pub algorithm: OtpAlgorithm,
    /// Code width.
    pub digits: OtpDigits,
    /// Code formatting encoder.
    pub encoder: OtpEncoder,
    /// HOTP counter.
    pub counter: Option<u64>,
    /// TOTP period.
    pub period: Option<u64>,
}
/// OTP URI type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtpKind {
    /// Counter-based HOTP.
    Hotp,
    /// Time-based TOTP.
    Totp,
}
impl OtpUri {
    /// Parses a strict `otpauth` URI.
    ///
    /// # Errors
    ///
    /// Returns malformed-input for unsupported schemes, parameters, or values.
    pub fn parse(value: &str) -> Result<Self, KdbxError> {
        let rest = value
            .strip_prefix("otpauth://")
            .ok_or_else(|| KdbxError::malformed("OTP URI must use otpauth"))?;
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let kind = match label.split('/').next().unwrap_or_default() {
            "totp" => OtpKind::Totp,
            "hotp" => OtpKind::Hotp,
            _ => return Err(KdbxError::malformed("unsupported OTP URI type")),
        };
        let mut values = BTreeMap::new();
        for (raw_key, raw_value) in query.split('&').filter_map(|part| part.split_once('=')) {
            let key = raw_key;
            let value = raw_value;
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(KdbxError::malformed("duplicate OTP URI parameter"));
            }
        }
        let raw_secret = Zeroizing::new(
            values
                .remove("secret")
                .ok_or_else(|| KdbxError::malformed("OTP URI secret is required"))?,
        );
        OtpSecret::from_base32(raw_secret.as_str())?;
        let secret = normalize_base32(raw_secret.as_str())?;
        let issuer = values.remove("issuer");
        let image = values.remove("image");
        let encoder = match values.remove("encoder").as_deref() {
            None | Some("default") | Some("standard") => OtpEncoder::Standard,
            Some("steam") => OtpEncoder::Steam,
            Some(_) => return Err(KdbxError::malformed("unsupported OTP encoder")),
        };
        if encoder == OtpEncoder::Steam && kind != OtpKind::Totp {
            return Err(KdbxError::malformed("Steam encoder requires TOTP"));
        }
        let counter = values
            .remove("counter")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| KdbxError::malformed("invalid OTP counter"))
            })
            .transpose()?;
        let parsed_period = values
            .remove("period")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| KdbxError::malformed("invalid OTP period"))
            })
            .transpose()?;
        let algorithm = match values.remove("algorithm").as_deref() {
            None | Some("SHA1") => OtpAlgorithm::Sha1,
            Some("SHA256") => OtpAlgorithm::Sha256,
            Some("SHA512") => OtpAlgorithm::Sha512,
            Some(_) => return Err(KdbxError::malformed("unsupported OTP algorithm")),
        };
        let digits = match (encoder, values.remove("digits").as_deref()) {
            (OtpEncoder::Steam, None | Some("5")) => OtpDigits::Five,
            (OtpEncoder::Standard, None | Some("6")) => OtpDigits::Six,
            (OtpEncoder::Standard, Some("8")) => OtpDigits::Eight,
            _ => return Err(KdbxError::malformed("unsupported OTP digits")),
        };
        if kind == OtpKind::Hotp && counter.is_none() {
            return Err(KdbxError::malformed("HOTP URI counter is required"));
        }
        let period = match kind {
            OtpKind::Totp => {
                let effective = parsed_period.unwrap_or(30);
                if effective == 0 {
                    return Err(KdbxError::malformed("TOTP URI period must be positive"));
                }
                Some(effective)
            }
            OtpKind::Hotp => parsed_period,
        };
        if !values.is_empty() {
            return Err(KdbxError::malformed("unknown OTP URI parameter"));
        }
        Ok(Self {
            kind,
            account: label
                .split_once('/')
                .map(|(_, account)| account.to_owned())
                .unwrap_or_default(),
            issuer,
            image,
            secret: secret.as_str().to_owned(),
            algorithm,
            digits,
            encoder,
            counter,
            period,
        })
    }

    /// Builds and validates an [`OtpUri`] from structured parameters.
    ///
    /// # Errors
    ///
    /// Returns malformed-input if the secret, label, or OTP parameter combination
    /// is invalid.
    pub fn from_params(params: OtpUriParams<'_>) -> Result<Self, KdbxError> {
        fn valid_label_part(value: &str) -> bool {
            !value
                .chars()
                .any(|c| c.is_control() || matches!(c, '?' | '&' | '#'))
        }
        if !valid_label_part(params.account) || params.account.contains('/') {
            return Err(KdbxError::malformed("invalid OTP URI account label"));
        }
        if let Some(issuer) = params.issuer {
            if !valid_label_part(issuer) {
                return Err(KdbxError::malformed("invalid OTP URI issuer"));
            }
        }
        OtpSecret::from_base32(params.secret)?;
        let secret = normalize_base32(params.secret)?;
        match params.kind {
            OtpKind::Hotp => {
                if params.encoder == OtpEncoder::Steam {
                    return Err(KdbxError::malformed("Steam encoder requires TOTP"));
                }
                if params.counter.is_none() {
                    return Err(KdbxError::malformed("HOTP URI counter is required"));
                }
                if params.digits == OtpDigits::Five {
                    return Err(KdbxError::malformed("unsupported OTP digits"));
                }
                Ok(Self {
                    kind: OtpKind::Hotp,
                    account: params.account.to_owned(),
                    issuer: params.issuer.map(str::to_owned),
                    image: None,
                    secret: secret.as_str().to_owned(),
                    algorithm: params.algorithm,
                    digits: params.digits,
                    encoder: OtpEncoder::Standard,
                    counter: params.counter,
                    period: None,
                })
            }
            OtpKind::Totp => {
                let period = params.period.unwrap_or(30);
                if period == 0 {
                    return Err(KdbxError::malformed("TOTP URI period must be positive"));
                }
                let digits = match params.encoder {
                    OtpEncoder::Steam => {
                        if params.digits != OtpDigits::Five {
                            return Err(KdbxError::malformed("unsupported OTP digits"));
                        }
                        OtpDigits::Five
                    }
                    OtpEncoder::Standard => {
                        if params.digits == OtpDigits::Five {
                            return Err(KdbxError::malformed("unsupported OTP digits"));
                        }
                        params.digits
                    }
                };
                Ok(Self {
                    kind: OtpKind::Totp,
                    account: params.account.to_owned(),
                    issuer: params.issuer.map(str::to_owned),
                    image: None,
                    secret: secret.as_str().to_owned(),
                    algorithm: params.algorithm,
                    digits,
                    encoder: params.encoder,
                    counter: None,
                    period: Some(period),
                })
            }
        }
    }

    /// Formats a validated `otpauth://` URI string inside a [`Zeroizing`] buffer.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_params`].
    pub fn format_uri(params: OtpUriParams<'_>) -> Result<Zeroizing<String>, KdbxError> {
        let uri = Self::from_params(params)?;
        Ok(Zeroizing::new(uri.to_string()))
    }

    /// Generates an OTP code for this URI (`timestamp` is used for TOTP; HOTP uses `self.counter`).
    ///
    /// # Errors
    ///
    /// Returns malformed-input when the Base32 secret is invalid or HOTP lacks a counter.
    pub fn generate_code(&self, timestamp: u64) -> Result<Zeroizing<String>, KdbxError> {
        let secret = OtpSecret::from_base32(&self.secret)?;
        let counter = match self.kind {
            OtpKind::Totp => {
                let period = self.period.unwrap_or(30);
                if period == 0 {
                    return Err(KdbxError::malformed("TOTP URI period must be positive"));
                }
                timestamp / period
            }
            OtpKind::Hotp => self
                .counter
                .ok_or_else(|| KdbxError::malformed("HOTP URI counter is required"))?,
        };
        Ok(Zeroizing::new(generate_with_encoder(
            secret.expose(),
            counter,
            self.algorithm,
            self.digits,
            self.encoder,
        )))
    }
}

/// KeePassXC `otp` field adapter.
///
/// [`Debug`](std::fmt::Debug) is derived, and this is provably safe: the
/// adapter is a unit struct. The `OtpUri` it reads or writes holds the seed and
/// has its own hand-written `Debug` that redacts it, so nothing is retained here
/// for a derive to print.
#[derive(Debug)]
pub struct KeePassXcOtp;
impl KeePassXcOtp {
    /// Returns whether a protected modern `otp` field exists.
    #[must_use]
    pub fn is_present(entry: &Entry) -> bool {
        entry.field("otp").is_some_and(|field| field.protected)
    }
    /// Reads and parses a protected modern `otp` field.
    ///
    /// # Errors
    ///
    /// Returns an error when the field is absent, unprotected, or invalid.
    pub fn read(entry: &Entry) -> Result<OtpUri, KdbxError> {
        let field = entry.field("otp").ok_or_else(|| {
            KdbxError::new(
                KdbxFailureKind::InvalidArgument,
                "KeePassXC OTP field is absent",
            )
        })?;
        if !field.protected {
            return Err(KdbxError::new(
                KdbxFailureKind::InvalidArgument,
                "KeePassXC OTP field is not protected",
            ));
        }
        let value = field.value.reveal_text()?;
        OtpUri::parse(value.as_str())
    }
    /// Reads an entry's OTP configuration, supporting both protected and unprotected
    /// `"otp"` fields as well as KeePass 2.x `TimeOtp-*` fallback fields when `"otp"` is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when neither `"otp"` nor `TimeOtp-Secret-Base32` is present,
    /// or when the OTP parameters are malformed.
    pub fn read_entry_fallback(entry: &Entry) -> Result<OtpUri, KdbxError> {
        if let Some(field) = entry.field("otp") {
            let value = field.value.reveal_text()?;
            return OtpUri::parse(value.as_str());
        }
        let secret_field = entry.field("TimeOtp-Secret-Base32").ok_or_else(|| {
            KdbxError::new(
                KdbxFailureKind::InvalidArgument,
                "KeePassXC OTP field is absent",
            )
        })?;
        let raw_secret = secret_field.value.reveal_text()?;
        OtpSecret::from_base32(raw_secret.as_str())?;
        let secret = normalize_base32(raw_secret.as_str())?;

        let algorithm = if let Some(alg_field) = entry.field("TimeOtp-Algorithm") {
            let alg_text = alg_field.value.reveal_text()?;
            match alg_text.as_str().trim().to_ascii_uppercase().as_str() {
                "HMAC-SHA-1" | "SHA1" | "SHA-1" => OtpAlgorithm::Sha1,
                "HMAC-SHA-256" | "SHA256" | "SHA-256" => OtpAlgorithm::Sha256,
                "HMAC-SHA-512" | "SHA512" | "SHA-512" => OtpAlgorithm::Sha512,
                _ => return Err(KdbxError::malformed("unsupported OTP algorithm")),
            }
        } else {
            OtpAlgorithm::Sha1
        };
        let digits = if let Some(len_field) = entry.field("TimeOtp-Length") {
            let len_text = len_field.value.reveal_text()?;
            match len_text.as_str().trim() {
                "6" => OtpDigits::Six,
                "8" => OtpDigits::Eight,
                _ => return Err(KdbxError::malformed("unsupported OTP digits")),
            }
        } else {
            OtpDigits::Six
        };
        let period = if let Some(period_field) = entry.field("TimeOtp-Period") {
            let period_text = period_field.value.reveal_text()?;
            let parsed: u64 = period_text
                .as_str()
                .trim()
                .parse()
                .map_err(|_| KdbxError::malformed("invalid OTP period"))?;
            if parsed == 0 {
                return Err(KdbxError::malformed("TOTP URI period must be positive"));
            }
            parsed
        } else {
            30
        };
        Ok(OtpUri {
            kind: OtpKind::Totp,
            account: entry.title.clone(),
            issuer: None,
            image: None,
            secret: secret.as_str().to_owned(),
            algorithm,
            digits,
            encoder: OtpEncoder::Standard,
            counter: None,
            period: Some(period),
        })
    }
    /// Writes a protected modern `otp` field.
    pub fn write(entry: &mut Entry, uri: &OtpUri) {
        entry.set_field(crate::model::Field {
            key: "otp".into(),
            value: crate::model::ProtectedValue::from_text(uri.to_string()),
            protected: true,
            protect_in_memory: false,
        });
    }
    /// Removes the modern OTP field, returning whether it existed.
    pub fn remove(entry: &mut Entry) -> bool {
        let before = entry.fields.len();
        entry.fields.retain(|field| field.key != "otp");
        before != entry.fields.len()
    }
}
impl fmt::Debug for OtpUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OtpUri")
            .field("kind", &self.kind)
            .field("account", &self.account)
            .field("issuer", &self.issuer)
            .field("image", &self.image)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("encoder", &self.encoder)
            .field("counter", &self.counter)
            .field("period", &self.period)
            .finish()
    }
}

impl Drop for OtpUri {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Display for OtpUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm = match self.algorithm {
            OtpAlgorithm::Sha1 => "SHA1",
            OtpAlgorithm::Sha256 => "SHA256",
            OtpAlgorithm::Sha512 => "SHA512",
        };
        write!(
            formatter,
            "otpauth://{}/{}?secret={}&algorithm={}&digits={}",
            if self.kind == OtpKind::Totp {
                "totp"
            } else {
                "hotp"
            },
            self.account,
            self.secret,
            algorithm,
            self.digits.count()
        )?;
        if let Some(issuer) = &self.issuer {
            write!(formatter, "&issuer={issuer}")?;
        }
        if let Some(image) = &self.image {
            write!(formatter, "&image={image}")?;
        }
        if self.encoder == OtpEncoder::Steam {
            write!(formatter, "&encoder=steam")?;
        }
        if let Some(counter) = self.counter {
            write!(formatter, "&counter={counter}")?;
        }
        if let Some(period) = self.period {
            write!(formatter, "&period={period}")?;
        }
        Ok(())
    }
}
