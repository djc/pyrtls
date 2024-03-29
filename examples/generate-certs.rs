use std::fs;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};

fn main() -> Result<(), anyhow::Error> {
    let mut ca_params = CertificateParams::new(vec!["localhost".to_owned()]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params)?;
    let ca_cert_pem = ca_cert.serialize_pem()?;
    fs::write("tests/ca-certificate.pem", ca_cert_pem)?;

    let ee_params = CertificateParams::new(vec!["localhost".to_owned()]);
    let ee_cert = Certificate::from_params(ee_params)?;
    let ee_cert_pem = ee_cert.serialize_pem_with_signer(&ca_cert)?;
    fs::write("tests/ee-certificate.pem", ee_cert_pem)?;
    let ee_key_pem = ee_cert.serialize_private_key_pem();
    fs::write("tests/ee-key.pem", ee_key_pem)?;

    Ok(())
}
