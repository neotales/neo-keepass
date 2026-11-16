//! Public conversion coverage for an intentionally unbalanced RSA test key.

use neotales_x509::ssh_keypair::{SshKeyError, SshKeyToX509, ssh_keypair_to_x509};

const PRIVATE_PKCS1: &str = include_str!("data/rsa-unbalanced-pkcs1.pem");
const PUBLIC_SSH: &str = include_str!("data/rsa-unbalanced.pub");

#[test]
fn x509_conversion_rejects_unbalanced_rsa_after_successful_private_key_parsing() {
    let request = SshKeyToX509 {
        common_name: "unbalanced-test-only".to_owned(),
        not_before_unix: 1_700_000_000,
        not_after_unix: 1_700_086_400,
    };

    assert_eq!(
        ssh_keypair_to_x509(PRIVATE_PKCS1, PUBLIC_SSH, &request, None).unwrap_err(),
        SshKeyError::InvalidPrivateKey
    );
}
