use std::{fs::File, io::{Write, BufRead, BufReader}, time::Instant, collections::HashSet, collections::HashMap};
use std::mem::size_of_val;
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
    let all_attrs1 = vec!["HREG", "HTYP", "HLVL", "HSEC", "HDPT", "HCONT"];
    let all_attrs2 = vec!["HTOP", "HMID", "HLOW", "HINT", "HEXT", "HFIN", "HHR"];

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
    println!("  Access structure: {:?}", structure);
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

    policy_attrs.join(" || ")
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
    let mut policy_str = generate_unique_policy(available_attrs, policy_len);

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
        total_ciphertext_len += ct.0.length();
        //println!("  Ciphertext: {:?}", ct.0);
        //println!("  Ciphertext length: {:?}", ct.0.length());

        //println!("  Ciphertext: {}", ct.1.len());
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
fn analyze_decaps_stats(filename: &str, repetitions: usize) -> std::io::Result<()> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    
    let mut lines: Vec<String> = reader.lines()
        .filter_map(|line| line.ok())
        .collect();
    
    // Pomijamy nagłówek
    if !lines.is_empty() {
        lines.remove(0);
    }
    
    if lines.is_empty() {
        println!("\n⚠️  Brak danych w pliku {}", filename);
        return Ok(());
    }
    
    println!("\n═══════════════════════════════════════════════════════════");
    println!("📊 ANALIZA STATYSTYK DEKAPSULACJI");
    println!("═══════════════════════════════════════════════════════════");
    println!("Liczba repetycji w grupie: {}", repetitions);
    println!("Całkowita liczba pomiarów: {}", lines.len());
    
    // Grupujemy dane po `repetitions` wierszach
    let groups = lines.chunks(repetitions);
    let group_count = (lines.len() + repetitions - 1) / repetitions;
    
    let mut output_file = File::create("decaps_analysis.csv")?;
    writeln!(
        output_file,
        "group_id,mode,avg_keys_checked,avg_checks_performed,avg_before_if_ns,avg_after_if_ns,avg_total_check_ns,avg_checks_before_if,avg_checks_after_if,avg_total_decaps_time_ns"
    )?;
    
    for (group_id, group) in groups.enumerate() {
        let mut mode = String::new();
        let mut sum_keys_checked = 0u64;
        let mut sum_checks_performed = 0u64;
        let mut sum_before_if = 0.0;
        let mut sum_after_if = 0.0;
        let mut sum_total_check = 0.0;
        let mut sum_checks_before_if = 0u64;
        let mut sum_checks_after_if = 0u64;
        let mut sum_total_decaps = 0.0;
        let mut valid_count = 0;
        
        for line in group {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 9 {
                mode = parts[0].trim().to_string();
                sum_keys_checked += parts[1].trim().parse::<u64>().unwrap_or(0);
                sum_checks_performed += parts[2].trim().parse::<u64>().unwrap_or(0);
                sum_before_if += parts[3].trim().parse::<f64>().unwrap_or(0.0);
                sum_after_if += parts[4].trim().parse::<f64>().unwrap_or(0.0);
                sum_total_check += parts[5].trim().parse::<f64>().unwrap_or(0.0);
                sum_checks_before_if += parts[6].trim().parse::<u64>().unwrap_or(0);
                sum_checks_after_if += parts[7].trim().parse::<u64>().unwrap_or(0);
                sum_total_decaps += parts[8].trim().parse::<f64>().unwrap_or(0.0);
                valid_count += 1;
            }
        }
        
        if valid_count > 0 {
            let avg_keys = sum_keys_checked as f64 / valid_count as f64;
            let avg_checks = sum_checks_performed as f64 / valid_count as f64;
            let avg_before = sum_before_if / valid_count as f64;
            let avg_after = sum_after_if / valid_count as f64;
            let avg_total = sum_total_check / valid_count as f64;
            let avg_checks_before = sum_checks_before_if as f64 / valid_count as f64;
            let avg_checks_after = sum_checks_after_if as f64 / valid_count as f64;
            let avg_decaps = sum_total_decaps / valid_count as f64;
            
            println!("\n─────────────────────────────────────────────────────────");
            println!("Grupa #{} (Mode: {})", group_id + 1, mode);
            println!("─────────────────────────────────────────────────────────");
            println!("  Średnia liczba sprawdzonych kluczy: {:.2}", avg_keys);
            println!("  Średnia liczba wykonanych sprawdzeń: {:.2}", avg_checks);
            println!("  Średni czas przed if: {:.2} ns", avg_before);
            println!("  Średni czas po if: {:.2} ns", avg_after);
            println!("  Średni czas całkowitego sprawdzenia: {:.2} ns", avg_total);
            println!("  Średnia liczba sprawdzeń przed if: {:.2}", avg_checks_before);
            println!("  Średnia liczba sprawdzeń po if: {:.2}", avg_checks_after);
            println!("  ⏱️  ŚREDNI CAŁKOWITY CZAS DEKAPSULACJI: {:.2} ns ({:.2} µs)", 
                     avg_decaps, avg_decaps / 1000.0);
            
            writeln!(
                output_file,
                "{},{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}",
                group_id + 1,
                mode,
                avg_keys,
                avg_checks,
                avg_before,
                avg_after,
                avg_total,
                avg_checks_before,
                avg_checks_after,
                avg_decaps
            )?;
        }
    }
    
    println!("\n═══════════════════════════════════════════════════════════");
    println!("✅ Analiza zapisana do pliku: decaps_analysis.csv");
    println!("═══════════════════════════════════════════════════════════\n");
    
    Ok(())
}
fn main() {
    let repetitions = 100;
    let plaintext = b"Benchmark test message";
    let mut file1 = File::create("decaps_timing_stats.csv").expect("Cannot create file");
    writeln!(file1, "mode,keys_checked,checks_performed,avg_before_if_ns,avg_after_if_ns,avg_total_ns,checks_before_if,checks_after_if, total_decaps_time").unwrap();
    let mut file = File::create("benchmark_modes_comparison3.csv").expect("Cannot create file");
    writeln!(
        file,
        "mode,structure_n,policy_len,keygen_time_us,master_key_length,usk_time_us,avg_encrypt_time_us,avg_decrypt_time_us,usk_length_bytes,avg_ciphertext_length_bytes,access_structure_size_bytes,policy"
    )
    .unwrap();

    for &hint in &[EncryptionHint::Classic, EncryptionHint::Hybridized] {
        let hint_str = match hint {
            EncryptionHint::Classic => "Classic",
            EncryptionHint::Hybridized => "PostQuantum",
        };

        println!("Running benchmarks for mode: {}", hint_str);

        for n in 1..=4 {
            println!("Structure size: {} x {}", n, n);
            let available_attrs = generate_fixed_attributes(n, n);
            print_available_attrs(&available_attrs);
            let cc = Covercrypt::default();

            let (mut msk, _) = cc.setup().expect("Setup failed");

            // Zastąp pustą access_structure własną
            msk.access_structure = AccessStructure::new();
            populate_access_structure(&mut msk.access_structure, hint.clone(), &available_attrs)
                .expect("Populating access structure failed");

            let start_keygen = Instant::now();
            // Zaktualizuj MPK na podstawie nowej struktury
            let mpk = cc.update_msk(&mut msk).expect("Updating MPK failed");
            println!("  mpk length: {}", mpk.length());
            let keygen_time = start_keygen.elapsed().as_micros() as f64;
            for policy_len in 1..=n {
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
                    "{},{},{},{:.2},{},{:.2},{:.2},{:.2},{},{},{},\"{}\"",
                    hint_str,
                    n,
                    policy_len,
                    keygen_time,
                    mpk.length(),
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
    if let Err(e) = analyze_decaps_stats("decaps_timing_stats.csv", repetitions) {
        eprintln!("❌ Błąd podczas analizy statystyk: {}", e);}
}
/*

  Access structure: AccessStructure { version: V1, dimensions: {"DPT": Anarchy({"INT": Attribute { id: 7, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "FIN": Attribute { id: 4, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "MID": Attribute { id: 6, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "EXT": Attribute { id: 5, encryption_hint: Hybridized, write_status: EncryptDecrypt }}), "LVL": Anarchy({"MID": Attribute { id: 2, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "FIN": Attribute { id: 0, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "INT": Attribute { id: 3, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "EXT": Attribute { id: 1, encryption_hint: Hybridized, write_status: EncryptDecrypt }}), "SEC": Anarchy({"FIN": Attribute { id: 8, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "MID": Attribute { id: 10, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "EXT": Attribute { id: 9, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "INT": Attribute { id: 11, encryption_hint: Hybridized, write_status: EncryptDecrypt }}), "REG": Anarchy({"MID": Attribute { id: 14, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "INT": Attribute { id: 15, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "EXT": Attribute { id: 13, encryption_hint: Hybridized, write_status: EncryptDecrypt }, "FIN": Attribute { id: 12, encryption_hint: Hybridized, write_status: EncryptDecrypt }})} }



*/