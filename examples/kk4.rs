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

    // 🔹 Polityka zawiera atrybut z pustą nazwą: "REG::"
    let wildcard_attr = "REG:: "; // wildcard dla REG
    let policy_attrs = choose_disjoint_attrs(&attributes, 1); // np. "TYP::LOW"
    let full_policy_str = format!("{} && {}", wildcard_attr, policy_attrs[0]);

    let policy = AccessPolicy::parse(&full_policy_str).unwrap();
    println!("\n🔐 Polityka dostępu: {}", full_policy_str);

    // 🔐 Inicjalizacja Covercrypt
    let cc = Covercrypt::default();
    let (mut msk, mut mpk) = cc_keygen(&cc, false).unwrap();
    msk.access_structure = AccessStructure::new();
    add_attributes_to_structure(&mut msk.access_structure, EncryptionHint::Classic, &attributes);
    mpk = cc.update_msk(&mut msk).unwrap();

    // 🧪 Przypadek testowy: wybierz atrybut z REG::TOP i TYP::LOW — zgodne z polityką
    let test_attr_set = vec![
        "REG::TOP".to_string(), // pasuje do "REG::"
        policy_attrs[0].clone(), // pasuje wprost
    ];

    // 🔐 Twórz politykę użytkownika zgodną z atrybutami
    let user_policy_str = test_attr_set.join(" && ");
    let user_policy = AccessPolicy::parse(&user_policy_str).unwrap();
    let usk = cc.generate_user_secret_key(&mut msk, &user_policy).unwrap();
    println!("🔐 Klucze użytkownika: {:?}", usk);
    // 🔐 Szyfrowanie
    let ciphertext = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
        &cc,
        &mpk,
        &policy,
        plaintext,
    ).expect("Encryption failed");

    println!("\n🔒 Szyfrowanie zakończone");
    println!("🔐 Użytkownik: {:?}", test_attr_set);

    // 🔓 Próba odszyfrowania
    let result = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(&cc, &usk, &ciphertext);
    match result {
        Ok(Some(decrypted)) => {
            println!("✅ Odszyfrowano poprawnie: {}", String::from_utf8_lossy(&decrypted));
        }
        _ => {
            println!("❌ Nie udało się odszyfrować.");
        }
    }
}
