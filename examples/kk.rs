use std::{fs::File, io::Write, time::Instant};

use cosmian_cover_crypt::{
    api::Covercrypt,
    cc_keygen,
    traits::PkeAc,
    AccessPolicy,
    MasterPublicKey,
    MasterSecretKey,
    AccessStructure,
    EncryptionHint,
    QualifiedAttribute,
};
use rand::{seq::SliceRandom, thread_rng};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm,
};
fn random_attribute() -> String {
    let attrs1 = vec!["REG", "TYP", "LVL", "SEC", "DPT"];
    let attrs2 = vec!["TOP", "MID", "LOW", "INT", "EXT", "FIN", "HR"];
    let mut rng = thread_rng();
    format!("{}::{}", attrs1.choose(&mut rng).unwrap(), attrs2.choose(&mut rng).unwrap())
}

fn generate_policy_string(attribute_count: usize) -> String {
    (0..attribute_count)
        .map(|_| random_attribute())
        .collect::<Vec<_>>()
        .join(" && ")
}

fn populate_access_structure(structure: &mut AccessStructure, hint: EncryptionHint) -> Result<(), Box<dyn std::error::Error>> {
    let attrs1 = vec!["REG", "TYP", "LVL", "SEC", "DPT"];
    let attrs2 = vec!["TOP", "MID", "LOW", "INT", "EXT", "FIN", "HR"];

    for dimension in &attrs1 {
        structure.add_anarchy(dimension.to_string())?;
        for attr in &attrs2 {
            structure.add_attribute(
                QualifiedAttribute {
                    dimension: dimension.to_string(),
                    name: attr.to_string(),
                },
                hint.clone(),
                None,
            )?;
        }
    }

    Ok(())
}

fn run_benchmark(
    cc: &Covercrypt,
    msk: &mut MasterSecretKey,
    mpk: &MasterPublicKey,
    attribute_count: usize,
    repetitions: usize,
    plaintext: &[u8],
    encryption_hint: &str,
) -> (f64, f64, f64, usize, usize, usize, String) {
    let policy_str = generate_policy_string(attribute_count);
    let ap = AccessPolicy::parse(&policy_str).unwrap();

    let start_usk = Instant::now();
    let usk = cc.generate_user_secret_key(msk, &ap).unwrap();
    let usk_time = start_usk.elapsed().as_micros() as f64;

    let mut total_encrypt_time = 0;
    let mut total_decrypt_time = 0;
    let mut total_ciphertext_len = 0;

    for _ in 0..repetitions {
        let start_encrypt = Instant::now();
        let ct = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(cc, mpk, &ap, plaintext)
            .expect("Encryption failed");
        total_encrypt_time += start_encrypt.elapsed().as_nanos();
        total_ciphertext_len += ct.1.len();

        let start_decrypt = Instant::now();
        let decrypted = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(cc, &usk, &ct)
            .expect("Decryption failed");
        total_decrypt_time += start_decrypt.elapsed().as_nanos();
        assert_eq!(decrypted.unwrap().as_slice(), plaintext);
    }

    let avg_encrypt_time = total_encrypt_time as f64 / repetitions as f64 / 1000.0;
    let avg_decrypt_time = total_decrypt_time as f64 / repetitions as f64 / 1000.0;
    let avg_ct_len = total_ciphertext_len as f64 / repetitions as f64;
    let usk_len = usk.serialize().unwrap().len();
    let access_structure_size = msk.access_structure.serialize().unwrap().len();

    (
        avg_encrypt_time,
        avg_decrypt_time,
        usk_time,
        usk_len,
        avg_ct_len as usize,
        access_structure_size,
        policy_str,
    )
}

fn main() {
    let repetitions = 3;
    let plaintext = b"Benchmark test message";

    let mut file = File::create("benchmark_modes_comparison.csv").expect("Cannot create file");
    writeln!(
        file,
        "mode,attr_count,keygen_time_us,usk_time_us,avg_encrypt_time_us,avg_decrypt_time_us,usk_length_bytes,avg_ciphertext_length_bytes,access_structure_size_bytes,policy"
    )
    .unwrap();

    for &hint in &[EncryptionHint::Classic, EncryptionHint::Hybridized] {
        let hint_str = match hint {
            EncryptionHint::Classic => "Classic",
            EncryptionHint::Hybridized => "PostQuantum"
        };

        println!("Running benchmarks for mode: {}", hint_str);

        let cc = Covercrypt::default();

        let start_keygen = Instant::now();
        let (mut msk, mut mpk) = cc_keygen(&cc, false).unwrap();
        let keygen_time = start_keygen.elapsed().as_micros() as f64;
        msk.access_structure = AccessStructure::new();
        populate_access_structure(&mut msk.access_structure, hint.clone()).expect("Populating access structure failed");
        mpk = cc.update_msk(&mut msk).expect("Updating MPK failed");

        for attr_count in 2..=2 {
            println!("  Attributes: {}", attr_count);

            let (
                avg_encrypt_time,
                avg_decrypt_time,
                usk_time,
                usk_len,
                avg_ct_len,
                access_structure_size,
                policy_str,
            ) = run_benchmark(&cc, &mut msk, &mpk, attr_count, repetitions, plaintext, hint_str);

            writeln!(
                file,
                "{},{},{:.2},{:.2},{:.2},{:.2},{},{},{},\"{}\"",
                hint_str,
                attr_count,
                keygen_time,
                usk_time,
                avg_encrypt_time,
                avg_decrypt_time,
                usk_len,
                avg_ct_len,
                access_structure_size,
                policy_str
            )
            .unwrap();
        }
    }

    println!("Benchmark complete. Results saved to benchmark_modes_comparison.csv.");
}
