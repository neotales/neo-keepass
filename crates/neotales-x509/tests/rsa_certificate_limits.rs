//! Public-parser coverage for canonical OpenSSH RSA certificates and size limits.

use neotales_x509::ssh_cert::{CertificateError, SSH_RSA, SSH_RSA_CERT_V01, parse_certificate};

fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut output = u32::try_from(bytes.len())
        .expect("test SSH strings fit in u32")
        .to_be_bytes()
        .to_vec();
    output.extend_from_slice(bytes);
    output
}

fn mpint_bytes(magnitude: &[u8]) -> Vec<u8> {
    let mut positive = magnitude.to_vec();
    if positive.first().is_some_and(|byte| byte & 0x80 != 0) {
        positive.insert(0, 0);
    }
    ssh_string(&positive)
}

fn modulus_with_bits(bits: usize) -> Vec<u8> {
    let mut magnitude = vec![0xff; bits.div_ceil(8)];
    let top_bits = bits % 8;
    if top_bits != 0 {
        magnitude[0] = (1 << top_bits) - 1;
    }
    magnitude
}

fn rsa_public_blob(modulus_bits: usize, modulus_mpint: Option<&[u8]>) -> Vec<u8> {
    let mut blob = ssh_string(SSH_RSA.as_bytes());
    blob.extend_from_slice(&mpint_bytes(&[1, 0, 1]));
    if let Some(encoded) = modulus_mpint {
        blob.extend_from_slice(encoded);
    } else {
        blob.extend_from_slice(&mpint_bytes(&modulus_with_bits(modulus_bits)));
    }
    blob
}

fn certificate(
    subject_bits: usize,
    ca_bits: usize,
    subject_modulus_mpint: Option<&[u8]>,
    ca_modulus_mpint: Option<&[u8]>,
) -> Vec<u8> {
    let mut encoded = ssh_string(SSH_RSA_CERT_V01.as_bytes());
    encoded.extend_from_slice(&ssh_string(b"nonce"));
    encoded.extend_from_slice(&mpint_bytes(&[1, 0, 1]));
    if let Some(encoded_modulus) = subject_modulus_mpint {
        encoded.extend_from_slice(encoded_modulus);
    } else {
        encoded.extend_from_slice(&mpint_bytes(&modulus_with_bits(subject_bits)));
    }
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    encoded.extend_from_slice(&ssh_string(b"key-id"));
    encoded.extend_from_slice(&ssh_string(&ssh_string(b"host.example")));
    encoded.extend_from_slice(&0_u64.to_be_bytes());
    encoded.extend_from_slice(&u64::MAX.to_be_bytes());
    encoded.extend_from_slice(&ssh_string(&[]));
    encoded.extend_from_slice(&ssh_string(&[]));
    encoded.extend_from_slice(&ssh_string(&[]));
    encoded.extend_from_slice(&ssh_string(&rsa_public_blob(ca_bits, ca_modulus_mpint)));
    let mut signature = ssh_string(b"rsa-sha2-256");
    signature.extend_from_slice(&ssh_string(&[0]));
    encoded.extend_from_slice(&ssh_string(&signature));
    encoded
}

#[test]
fn public_certificate_parser_accepts_canonical_16384_and_16383_bit_rsa_keys() {
    for bits in [16_384, 16_383] {
        let encoded = certificate(bits, bits, None, None);
        parse_certificate(&encoded).expect("subject and CA modulus should fit the RSA policy");
    }
}

#[test]
fn public_certificate_parser_rejects_rsa_moduli_over_16384_bits() {
    let too_large = mpint_bytes(&modulus_with_bits(16_385));
    for (subject, ca) in [
        (Some(too_large.as_slice()), None),
        (None, Some(too_large.as_slice())),
    ] {
        assert_eq!(
            parse_certificate(&certificate(16_384, 16_384, subject, ca)),
            Err(CertificateError::InvalidPublicKey)
        );
    }
}

#[test]
fn public_certificate_parser_rejects_noncanonical_and_negative_rsa_mpints() {
    let normal = modulus_with_bits(16_384);
    let mut redundant_sign = vec![0, 0x7f];
    redundant_sign.extend_from_slice(normal.get(1..).expect("RSA modulus has many bytes"));
    let noncanonical = ssh_string(&redundant_sign);
    let mut negative = normal;
    negative[0] = 0x80;
    let negative = ssh_string(&negative);

    for (subject, ca) in [
        (Some(noncanonical.as_slice()), None),
        (None, Some(noncanonical.as_slice())),
    ] {
        assert_eq!(
            parse_certificate(&certificate(16_384, 16_384, subject, ca)),
            Err(CertificateError::Wire(
                neotales_x509::ssh_cert::WireError::InvalidMpint
            ))
        );
    }
    for (subject, ca) in [
        (Some(negative.as_slice()), None),
        (None, Some(negative.as_slice())),
    ] {
        assert_eq!(
            parse_certificate(&certificate(16_384, 16_384, subject, ca)),
            Err(CertificateError::InvalidPublicKey)
        );
    }
}
