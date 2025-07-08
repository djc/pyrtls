use std::fs;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

fn main() -> Result<(), anyhow::Error> {
    let mut ca_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    fs::write("tests/ca-certificate.pem", ca_cert.pem())?;
    let ca = Issuer::new(ca_params, ca_key);

    let ee_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    let ee_key = KeyPair::generate()?;
    let ee_cert = ee_params.signed_by(&ee_key, &ca)?;
    fs::write("tests/ee-certificate.pem", ee_cert.pem())?;
    fs::write("tests/ee-key.pem", ee_key.serialize_pem())?;

    Ok(())
}
