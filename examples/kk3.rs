use std::collections::{HashMap, HashSet};
use rand::{seq::{SliceRandom, IteratorRandom}, thread_rng};
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
use cosmian_crypto_core::{Aes256Gcm};
use cosmian_crypto_core::bytes_ser_de::Serializable;
/// Wygeneruj przestrzeń 5x5: [REG, TYP, LVL, SEC, DPT] × [TOP, MID, LOW, INT, EXT]
fn generate_attributes_grid() -> Vec<String> {
    let dims = vec!["REG", "TYP", "LVL"];
    let vals = vec!["TOP", "MID", "LOW"];
    let mut attrs = vec![];

    for dim in &dims {
        for val in &vals {
            attrs.push(format!("{}::{}", dim, val));
        }
    }

    attrs
}

/// Dodaj atrybuty do struktury dostępu
fn add_attributes_to_structure(
    structure: &mut AccessStructure,
    hint: EncryptionHint,
    attrs: &[String],
) {
    let mut added_dims = HashSet::new();

    for attr in attrs {
        let (dim, name) = attr.split_once("::").unwrap();
        let dimension = dim.to_string();
        let name = name.to_string();

        if !added_dims.contains(&dimension) {
            structure.add_anarchy(dimension.clone()).unwrap();
            added_dims.insert(dimension.clone());
        }

        structure
            .add_attribute(QualifiedAttribute { dimension, name }, hint.clone(), None)
            .unwrap();
    }
}

/// Wybierz `count` atrybutów z różnych wymiarów
fn choose_disjoint_attrs(attributes: &[String], count: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut by_dim: HashMap<String, Vec<String>> = HashMap::new();

    for attr in attributes {
        if let Some((dim, _)) = attr.split_once("::") {
            by_dim.entry(dim.to_string())
                .or_default()
                .push(attr.clone());
        }
    }

    let chosen_dims = by_dim.keys()
        .cloned()
        .choose_multiple(&mut rng, count);

    let mut selected = vec![];
    for dim in chosen_dims {
        if let Some(attrs) = by_dim.get(&dim) {
            if let Some(attr) = attrs.choose(&mut rng) {
                selected.push(attr.clone());
            }
        }
    }

    selected
}

fn main() {
    let plaintext = b"Secret message!";
    let attributes = generate_attributes_grid();
    println!("📦 Dostępne atrybuty ({}):\n{:?}", attributes.len(), attributes);

    // Wygeneruj politykę: 3 atrybuty o różnych wymiarach
    let policy_attrs = choose_disjoint_attrs(&attributes, 2);
    let policy_str = policy_attrs.join(" && ");
    let policy = AccessPolicy::parse(&policy_str).unwrap();
    println!("\n🔐 Polityka dostępu: {}", policy_str);

    // Inicjalizacja Covercrypt
    let cc = Covercrypt::default();
    let (mut msk, mut mpk) = cc_keygen(&cc, false).unwrap();
    msk.access_structure = AccessStructure::new();
    add_attributes_to_structure(&mut msk.access_structure, EncryptionHint::Classic, &attributes);
    mpk = cc.update_msk(&mut msk).unwrap();
    println!("🔑 Wygenerowano klucze:\n  MPK: {:?}\n  MSK: {:?}", mpk, msk);
    // Klucz użytkownika zgodny z polityką
    

    // Przygotowanie przypadków testowych
    let mut rng = thread_rng();
    let policy_dims: HashSet<_> = policy_attrs.iter().map(|a| a.split("::").next().unwrap()).collect();

    let remaining_attrs: Vec<_> = attributes
        .iter()
        .filter(|a| !policy_attrs.contains(a))
        .cloned()
        .collect();

    let extra_attr = remaining_attrs
        .iter()
        .filter(|a| {
            let dim = a.split("::").next().unwrap();
            !policy_dims.contains(dim)
        })
        .choose(&mut rng)
        .unwrap()
        .to_string();

    let disjoint_nonmatching = choose_disjoint_attrs(&remaining_attrs, 3);

    let cases = vec![
        /*("❌ Case A: 1 pasujące atrybuty", policy_attrs[..1].to_vec()),*/
        //("✅ Case B: dokładnie 2 pasujące", policy_attrs.clone()),
        (
            "✅ Case C: 2 pasujące + 1 dodatkowy (rozłączny wymiar)",
            {
                let mut attrs = policy_attrs.clone();
                attrs.push(extra_attr);
                attrs
            },
        ),/*
        ("❌ Case D: 3 niepasujące atrybuty", disjoint_nonmatching),
    */];

    for (label, attr_set) in cases {
        let u_policy = AccessPolicy::parse(&attr_set.join(" && ")).unwrap();
        let usk = cc.generate_user_secret_key(&mut msk, &u_policy).unwrap();
        println!("\n🔍 {}", label);
        println!("   🔸 Atrybuty: {:?}", attr_set);

        let enc_policy_str = &policy_str;

        let enc_policy = AccessPolicy::parse(&enc_policy_str).unwrap();

        let ciphertext = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
            &cc, &mpk, &enc_policy, plaintext,
        )
        .expect("Encryption failed");
        println!("   🔸 Szyfrogram: {:?}", &ciphertext);
        let result = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(&cc, &usk, &ciphertext);
        println!("   🔸 USK: {:?}", &usk.length());
        println!("   🔸 USK: {:?}", &usk);
        match result {
            Ok(Some(decrypted)) => {
                println!("   ✅ Odszyfrowano: {}", String::from_utf8_lossy(&decrypted));
            }
            _ => {
                println!("   ❌ Nie udało się odszyfrować.");
            }
        }
    }
}
