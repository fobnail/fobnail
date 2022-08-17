use alloc::vec::Vec;
use der::{
    asn1::{BitString, SetOfVec},
    oid::db::rfc4519::{ORGANIZATION_NAME, SERIAL_NUMBER},
    Any, Encode, Tag,
};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use trussed::{
    api::reply::{SerializeKey, Sign},
    types::{KeyId, KeySerialization, Mechanism, Signature, SignatureSerialization},
};
use x509::{
    attr::AttributeTypeAndValue,
    name::{DistinguishedName, RdnSequence, RelativeDistinguishedName},
    request::{CertReq, CertReqInfo, Version},
};

fn asn1_encode_sign<'r, T, E>(
    trussed: &mut T,
    signing_key: KeyId,
    object: &E,
    buf: &'r mut [u8],
) -> Result<(&'r [u8], Signature), ()>
where
    T: trussed::client::CryptoClient,
    E: Encode,
{
    let mut encoder = der::Encoder::new(buf);
    encoder.encode(object).map_err(|e| error!("{}", e))?;
    let encoded = encoder.finish().map_err(|e| error!("{}", e))?;

    let Sign { signature } = trussed::try_syscall!(trussed.sign(
        Mechanism::Ed255,
        signing_key,
        encoded,
        SignatureSerialization::Raw,
    ))
    .map_err(|e| error!("Failed to sign CSR: {:?}", e))?;

    Ok((encoded, signature))
}

pub fn make_csr<T>(trussed: &mut T, key: KeyId, device_id: u64) -> Result<Vec<u8>, ()>
where
    T: trussed::client::CryptoClient,
{
    let SerializeKey {
        serialized_key: key_pub,
    } = trussed::try_syscall!(trussed.serialize_key(Mechanism::Ed255, key, KeySerialization::Raw))
        .map_err(|e| error!("Trussed key serialization failed: {:?}", e))?;

    let device_id_str = format!("{:X}", device_id);

    let organization = AttributeTypeAndValue {
        oid: ORGANIZATION_NAME,
        value: Any::new(Tag::Utf8String, b"Fobnail").unwrap(),
    };

    let serial_number = AttributeTypeAndValue {
        oid: SERIAL_NUMBER,
        value: Any::new(Tag::PrintableString, device_id_str.as_bytes()).unwrap(),
    };

    let mut buf = Vec::new();
    buf.resize(
        // Buffer must hold public key (always 32 bytes for ed25519) + signature (always 64 bytes)
        32 + 64
        // Add some space for other data
        + 128,
        0,
    );

    // Construct subject DN. Follow OpenSSL behaviour - put each RDN in a
    // separate set:
    //
    // SEQUENCE
    // SET
    //  SEQUENCE
    //   OBJECT            :organizationName
    //   UTF8STRING        :Fobnail
    // SET
    //  SEQUENCE
    //   OBJECT            :serialNumber
    //   UTF8STRING        :S534081NQW10

    let subject: DistinguishedName = RdnSequence(vec![
        RelativeDistinguishedName(vec![organization].try_into().unwrap()),
        RelativeDistinguishedName(vec![serial_number].try_into().unwrap()),
    ]);

    // This part of CSR must be signed.
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        attributes: SetOfVec::new(),
        public_key: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                // Ed25519
                oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
                parameters: None,
            },
            subject_public_key: &key_pub,
        },
    };

    let (_encoded_info, signature) = asn1_encode_sign(trussed, key, &info, &mut buf)
        .map_err(|()| error!("CSR signing failed"))?;

    let req = CertReq {
        info,
        algorithm: AlgorithmIdentifier {
            // Ed25519
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
            parameters: None,
        },
        signature: BitString::from_bytes(&signature).unwrap(),
    };

    let mut encoder = der::Encoder::new(&mut buf);
    encoder.encode(&req).unwrap();
    let encoded_data_len = encoder.finish().unwrap().len();

    buf.truncate(encoded_data_len);
    Ok(buf)
}
