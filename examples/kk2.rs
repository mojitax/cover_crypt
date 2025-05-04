use std::{fs::File, io::Write, time::Instant, collections::HashSet, collections::HashMap};

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
    bytes_ser_de::Serializable,
    Aes256Gcm,
};

fn generate_fixed_attributes(attrs1_count: usize, attrs2_count: usize) -> Vec<String> {
    let all_attrs1 = vec!["REG", "TYP", "LVL", "SEC", "DPT"];
    let all_attrs2 = vec!["TOP", "MID", "LOW", "INT", "EXT", "FIN", "HR"];

    let mut rng = thread_rng();
    let selected_attrs1: Vec<_> = all_attrs1.choose_multiple(&mut rng, attrs1_count).cloned().collect();
    let selected_attrs2: Vec<_> = all_attrs2.choose_multiple(&mut rng, attrs2_count).cloned().collect();

    let mut attributes = vec![];
    for dimension in &selected_attrs1 {
        for attr in &selected_attrs2 {
            attributes.push(format!("{}::{}", dimension, attr));
        }
    }

    attributes
}

fn populate_access_structure(
    structure: &mut AccessStructure,
    hint: EncryptionHint,
    attrs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut added_dimensions = HashSet::new();

    for attr in attrs {
        let parts: Vec<&str> = attr.split("::").collect();
        if parts.len() != 2 {
            continue;
        }
        let dimension = parts[0].to_string();
        let name = parts[1].to_string();

        if !added_dimensions.contains(&dimension) {
            structure.add_anarchy(dimension.clone())?;
            added_dimensions.insert(dimension.clone());
        }

        structure.add_attribute(
            QualifiedAttribute { dimension, name },
            hint.clone(),
            None,
        )?;
    }

    Ok(())
}


fn generate_unique_policy(
    available_attrs: &[String],
    policy_len: usize,
) -> String {
    let mut rng = thread_rng();
    let mut dim_map: HashMap<String, Vec<String>> = HashMap::new();
    for attr in available_attrs {
        if let Some((dim, val)) = attr.split_once("::") {
            dim_map.entry(dim.to_string())
                .or_default()
                .push(val.to_string());
        }
    }

    let selected_dims: Vec<_> = dim_map.keys().cloned().collect();
    let selected_dims = selected_dims
        .choose_multiple(&mut rng, policy_len.min(dim_map.len()))
        .cloned()
        .collect::<Vec<_>>();

    let mut policy_attrs = vec![];
    for dim in selected_dims {
        if let Some(values) = dim_map.get(&dim) {
            if let Some(attr) = values.choose(&mut rng) {
                policy_attrs.push(format!("{}::{}", dim, attr));
            }
        }
    }

    policy_attrs.join(" && ")
}
fn run_benchmark(
    cc: &Covercrypt,
    msk: &mut MasterSecretKey,
    mpk: &MasterPublicKey,
    policy_len: usize,
    repetitions: usize,
    plaintext: &[u8],
    available_attrs: &[String],
    encryption_hint: &str,
) -> (f64, f64, f64, usize, usize, usize, String) {
    let policy_str =  generate_unique_policy(available_attrs, policy_len);
    println!("  Selected policy: {}", policy_str);
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
fn print_available_attrs(attrs: &[String]) {
    println!("Available attributes ({} total):", attrs.len());
    for (i, attr) in attrs.iter().enumerate() {
        println!("  {:>2}: {}", i + 1, attr);
    }
}
fn main() {
    let repetitions = 3;
    let plaintext = b"Benchmark test message";

    let mut file = File::create("benchmark_modes_comparison.csv").expect("Cannot create file");
    writeln!(
        file,
        "mode,structure_n,policy_len,keygen_time_us,usk_time_us,avg_encrypt_time_us,avg_decrypt_time_us,usk_length_bytes,avg_ciphertext_length_bytes,access_structure_size_bytes,policy"
    )
    .unwrap();

    for &hint in &[EncryptionHint::Classic, EncryptionHint::Hybridized] {
        let hint_str = match hint {
            EncryptionHint::Classic => "Classic",
            EncryptionHint::Hybridized => "PostQuantum",
        };

        println!("Running benchmarks for mode: {}", hint_str);

        for n in 2..=5 {
            println!("Structure size: {} x {}", n, n);
            let available_attrs = generate_fixed_attributes(n, n);
            print_available_attrs(&available_attrs);
            let cc = Covercrypt::default();

            
            let (mut msk, mut mpk) = cc_keygen(&cc, false).unwrap();
            let keygen_time = start_keygen.elapsed().as_micros() as f64;

            msk.access_structure = AccessStructure::new();
            populate_access_structure(&mut msk.access_structure, hint.clone(), &available_attrs)
                .expect("Populating access structure failed");
            let start_keygen = Instant::now();
            mpk = cc.update_msk(&mut msk).expect("Updating MPK failed");
            let keygen_time = start_keygen.elapsed().as_micros() as f64;
            for policy_len in 2..=n {
                println!("  Policy length: {}", policy_len);
                let (
                    avg_encrypt_time,
                    avg_decrypt_time,
                    usk_time,
                    usk_len,
                    avg_ct_len,
                    access_structure_size,
                    policy_str,
                ) = run_benchmark(
                    &cc,
                    &mut msk,
                    &mpk,
                    policy_len,
                    repetitions,
                    plaintext,
                    &available_attrs,
                    hint_str,
                );

                writeln!(
                    file,
                    "{},{},{},{:.2},{:.2},{:.2},{:.2},{},{},{},\"{}\"",
                    hint_str,
                    n,
                    policy_len,
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
    }

    println!("Benchmark complete. Results saved to benchmark_modes_comparison.csv.");
}
