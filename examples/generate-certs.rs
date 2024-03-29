use std::fs;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

fn main() -> Result<(), anyhow::Error> {
    let mut ca_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    fs::write("tests/ca-certificate.pem", ca_cert.pem())?;

    let ee_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    let ee_key = KeyPair::generate()?;
    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key)?;
    fs::write("tests/ee-certificate.pem", ee_cert.pem())?;
    fs::write("tests/ee-key.pem", ee_key.serialize_pem())?;

    Ok(())
}
