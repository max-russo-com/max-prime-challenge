#[cfg(test)]
use dashu_int::ops::BitTest;
use dashu_int::UBig;
use rand::Rng;
#[cfg(test)]
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const LOCAL_DISCOVERIES_PATH: &str = "discoveries/local_discoveries.json";
const APP_STATE_DIR: &str = "app_state";
const CURRENT_RUN_STATE_PATH: &str = "app_state/current_run.json";
const OFFICIAL_CLIENT_CONFIG_PATH: &str = "app_state/official_client_config.json";
const OFFICIAL_API_BASE: &str = "https://www.max-russo.com/max/prime";

#[derive(Serialize, Deserialize, Clone)]
struct AdvancedFilterConfig {
    enabled: bool,
    modulus_m: String,
    remainder_r: String,
    original_moduli: Vec<String>,
    original_remainders: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AdvancedExperimentConfig {
    experiment_id: String,
    n0: String,
    step: String,
    iterations: usize,
    test_n: bool,
    test_d: bool,
    filter: AdvancedFilterConfig,
}

#[derive(Serialize, Deserialize, Clone)]
struct AdvancedRunResult {
    experiment_id: String,
    mode: String,
    iterations_done: usize,
    test_n: bool,
    test_d: bool,
    filter_enabled: bool,
    expected_n_primes: f64,
    observed_n_primes: usize,
    n_enrichment: f64,
    expected_d_primes: f64,
    observed_d_primes: usize,
    d_enrichment: f64,
    hits: Vec<LocalDiscovery>,
    saved_at_unix: u64,
    note: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct LocalDiscovery {
    mode: String,
    candidate_type: String,
    #[serde(default)]
    i: usize,
    n: String,
    candidate: String,
    digits: usize,
    sha256: String,
    found_at_unix: u64,
    note: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CurrentRunState {
    status: String,
    mode: String,
    experiment_id: String,
    candidate_type: String,
    iterations_total: usize,
    iterations_done: usize,
    n_digits: usize,
    hits_found: usize,
    hits_exported: usize,
    best_digits: usize,
    best_sha256: String,
    test_n: bool,
    test_d: bool,
    filter_enabled: bool,
    filter: Option<AdvancedFilterConfig>,
    expected_n_primes: f64,
    observed_n_primes: usize,
    n_enrichment: f64,
    expected_d_primes: f64,
    observed_d_primes: usize,
    d_enrichment: f64,
    hits: Vec<LocalDiscovery>,
    engine: String,
    started_at_unix: u64,
    updated_at_unix: u64,
    completed_at_unix: u64,
    message: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct OfficialClientConfig {
    mode: String,
    official_api_base: String,
    client_device_id: String,
    participant_id: String,
    participant_token: String,
    participant_token_status: String,
    token_id: String,
    max_id: String,
    max_id_hash: String,
    public_nickname: String,
    public_display_name: String,
    max_login_status: String,
    registration_id: String,
    registration_status: String,
    login_session_id: String,
    login_session_status: String,
    login_started_at_unix: u64,
    login_expires_at_unix: u64,
    qr_text: String,
    deeplink: String,
    callback_url: String,
    created_at_unix: u64,
    updated_at_unix: u64,
    note: String,
}

fn write_text_atomic(path: &str, text: &str) -> Result<(), String> {
    let tmp_path = format!("{}.tmp-{}-{}", path, std::process::id(), now_unix());

    write_sensitive_text(&tmp_path, text)?;

    fs::rename(&tmp_path, path).map_err(|e| {
        format!(
            "Cannot replace {} atomically from {}: {}",
            path, tmp_path, e
        )
    })?;

    Ok(())
}

fn create_private_dir(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("Cannot create private directory {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot secure directory {path}: {e}"))?;
    }
    Ok(())
}

fn write_sensitive_text(path: &str, text: impl AsRef<[u8]>) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Cannot write sensitive file {path}: {e}"))?;
        file.write_all(text.as_ref())
            .map_err(|e| format!("Cannot write sensitive file {path}: {e}"))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot secure sensitive file {path}: {e}"))?;
        return Ok(());
    }
    #[cfg(not(unix))]
    fs::write(path, text).map_err(|e| format!("Cannot write sensitive file {path}: {e}"))
}

fn parallel_safe_suffix() -> String {
    format!("{}-pid{}", now_unix(), std::process::id())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_decimal(value: &UBig) -> String {
    let s = value.to_string();
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let bytes = hasher.finalize();

    let mut out = String::new();
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn decimal_digits(value: &UBig) -> usize {
    value.to_string().len()
}

fn modpow_dashu(base: &UBig, exp: &UBig, modulus: &UBig) -> UBig {
    let zero = UBig::from(0u32);
    let one = UBig::from(1u32);
    let two = UBig::from(2u32);

    if modulus == &one {
        return zero;
    }

    let mut result = one.clone();
    let mut b = base % modulus;
    let mut e = exp.clone();

    while e > zero {
        if &e % &two == one {
            result = (&result * &b) % modulus;
        }
        e /= &two;
        b = (&b * &b) % modulus;
    }

    result
}

fn random_decimal_string(digits: usize) -> String {
    let digits = digits.max(2);
    let mut rng = rand::thread_rng();
    let mut s = String::new();

    let first: u8 = rng.gen_range(1..10);
    s.push_str(&first.to_string());

    for _ in 1..digits {
        let d: u8 = rng.gen_range(0..10);
        s.push_str(&d.to_string());
    }

    s
}

fn n_candidate_from_n(n: &UBig) -> UBig {
    let six = UBig::from(6u32);
    let thirty_one = UBig::from(31u32);
    &thirty_one + &six * n * (n + UBig::from(1u32))
}

fn is_probable_prime(n: &UBig) -> bool {
    let zero = UBig::from(0u32);
    let one = UBig::from(1u32);
    let two = UBig::from(2u32);

    if n < &two {
        return false;
    }

    let small_primes: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for p in small_primes.iter() {
        let bp = UBig::from(*p);
        if n == &bp {
            return true;
        }
        if n % &bp == zero {
            return false;
        }
    }

    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s: u32 = 0;

    while &d % &two == zero {
        d /= &two;
        s += 1;
    }

    let bases: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for a in bases.iter() {
        let base = UBig::from(*a);

        if base >= n_minus_one {
            continue;
        }

        let mut x = modpow_dashu(&base, &d, n);

        if x == one || x == n_minus_one {
            continue;
        }

        let mut passed = false;

        for _ in 1..s {
            x = modpow_dashu(&x, &two, n);
            if x == n_minus_one {
                passed = true;
                break;
            }
        }

        if !passed {
            return false;
        }
    }

    true
}

fn load_local_discoveries() -> Vec<LocalDiscovery> {
    if !Path::new(LOCAL_DISCOVERIES_PATH).exists() {
        return Vec::new();
    }

    let txt = match fs::read_to_string(LOCAL_DISCOVERIES_PATH) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    serde_json::from_str(&txt).unwrap_or_else(|_| Vec::new())
}

fn save_local_discoveries(items: &[LocalDiscovery]) -> Result<(), String> {
    fs::create_dir_all("discoveries")
        .map_err(|e| format!("Cannot create discoveries folder: {}", e))?;
    let txt = serde_json::to_string_pretty(items)
        .map_err(|e| format!("Cannot serialize discoveries: {}", e))?;
    fs::write(LOCAL_DISCOVERIES_PATH, txt)
        .map_err(|e| format!("Cannot write discoveries: {}", e))?;
    Ok(())
}

fn append_local_discoveries(new_items: Vec<LocalDiscovery>) -> Result<(), String> {
    let mut all = load_local_discoveries();
    all.extend(new_items);
    save_local_discoveries(&all)
}

fn save_current_run_state(state: &CurrentRunState) -> Result<(), String> {
    create_private_dir(APP_STATE_DIR)?;

    let txt = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Cannot serialize current run state: {}", e))?;

    write_sensitive_text(CURRENT_RUN_STATE_PATH, &txt)?;

    Ok(())
}

fn load_current_run_state() -> Option<CurrentRunState> {
    if !Path::new(CURRENT_RUN_STATE_PATH).exists() {
        return None;
    }

    let txt = fs::read_to_string(CURRENT_RUN_STATE_PATH).ok()?;
    serde_json::from_str(&txt).ok()
}

fn print_status() {
    println!();
    println!("Current Run Status");
    println!("==================");
    println!();

    match load_current_run_state() {
        Some(s) => {
            println!("Status: {}", s.status);
            println!("Mode: {}", s.mode);
            println!("Candidate type: {}", s.candidate_type);
            println!("Progress: {}/{}", s.iterations_done, s.iterations_total);
            println!("n digits: {}", s.n_digits);
            println!("Hits found: {}", s.hits_found);
            println!("Best size: {} digits", s.best_digits);
            println!("Expected random N primes: {:.6}", s.expected_n_primes);
            println!("Observed N primes: {}", s.observed_n_primes);
            println!("N enrichment: {:.3}×", s.n_enrichment);

            if !s.best_sha256.is_empty() {
                println!("Best SHA-256: {}", s.best_sha256);
            }

            println!("Message: {}", s.message);
            println!();
            println!("State file:");
            println!("   {}", CURRENT_RUN_STATE_PATH);
        }
        None => {
            println!("No run state found yet.");
            println!();
            println!("Run:");
            println!("   max_prime_public_client local-demo");
            println!("   max_prime_public_client official-explain");
        }
    }

    println!();
}

fn print_welcome() {
    println!();
    println!("MAX Prime Challenge");
    println!("===================");
    println!();
    println!("Help discover huge prime numbers.");
    println!();
    println!("MAX Prime Challenge lets your computer test small pieces of a larger");
    println!("mathematical search. Each participant receives a small work unit,");
    println!("computes it locally, and submits the result securely.");
    println!();
    println!("You can use this client in two ways:");
    println!();
    println!("1) Local Mode");
    println!("   Try MAX Prime freely on your own computer.");
    println!("   No login is required. Nothing is submitted officially.");
    println!();
    println!("2) Official Challenge Mode");
    println!("   Join a public distributed challenge.");
    println!("   Login with MAX, receive official work units, and contribute");
    println!("   computing power together with other participants.");
    println!();
    println!("Why this is different:");
    println!("   MAX Prime Challenge explores a structured family of candidates");
    println!("   generated by MAX Prime Theory.");
    println!();
    println!("   The goal is not only to find primes, but also to measure whether");
    println!("   this structure produces more probable primes than a random search");
    println!("   would suggest. This effect is called enrichment.");
    println!();
    println!("This first public client focuses on N candidates.");
    println!("N candidates showed the strongest enrichment signal in our tests and");
    println!("are more efficient to search at large digit sizes.");
    println!();
    println!("Try now:");
    println!("   max_prime_public_client local-demo");
    println!("   max_prime_public_client official-explain");
    println!();
    println!("Useful commands:");
    println!("   max_prime_public_client welcome");
    println!("   max_prime_public_client modes");
    println!("   max_prime_public_client privacy");
    println!("   max_prime_public_client explain-n");
    println!("   max_prime_public_client status");
    println!("   max_prime_public_client discoveries");
    println!("   max_prime_public_client discoveries-all");
    println!("   max_prime_public_client local-demo");
    println!("   max_prime_public_client official-explain");
    println!("   max_prime_public_client copy-local-prime 1");
    println!("   max_prime_public_client copy-local-sha 1");
    println!();
}

fn print_modes() {
    println!();
    println!("MAX Prime Client Modes");
    println!("======================");
    println!();
    println!("Local Mode");
    println!("----------");
    println!("Use your computer to run a private prime search.");
    println!();
    println!("- No MAX Login required.");
    println!("- No official server submission.");
    println!("- You can view, copy, and export primes found locally.");
    println!("- Good for testing, learning, and private experiments.");
    println!();
    println!("Official Challenge Mode");
    println!("-----------------------");
    println!("Join an official MAX Prime Challenge.");
    println!();
    println!("- Login with MAX.");
    println!("- Receive official work units from the server.");
    println!("- Compute locally on your computer.");
    println!("- Submit assigned results only.");
    println!("- If a possible prime is found, it is automatically verified.");
    println!("- Verified hits may appear in the public challenge ranking.");
    println!();
}

fn print_privacy() {
    println!();
    println!("Privacy");
    println!("=======");
    println!();
    println!("Login with MAX does not send your name, email, phone number,");
    println!("or personal profile.");
    println!();
    println!("The server receives only the technical proof needed to recognize");
    println!("your MAX ID and assign official work units.");
    println!();
    println!("Your public name or nickname is optional.");
    println!("It is used only if you choose to appear in the public ranking after");
    println!("finding a major prime.");
    println!();
}

fn print_explain_n() {
    println!();
    println!("Why this client focuses on N");
    println!("============================");
    println!();
    println!("MAX Prime Theory can generate related candidate values, including");
    println!("N and d.");
    println!();
    println!("This first public client focuses on N candidates because N showed");
    println!("the strongest enrichment signal in our tests.");
    println!();
    println!("For small numbers, testing more candidate types is easy.");
    println!("For numbers with thousands of digits, every extra test costs real");
    println!("computing time.");
    println!();
    println!("That is why the public challenge focuses on N first:");
    println!();
    println!("- better observed enrichment;");
    println!("- better chance per unit of computation;");
    println!("- simpler public explanation;");
    println!("- cleaner first distributed challenge.");
    println!();
    println!("The related d values may become a future experimental track.");
    println!();
}

fn print_discoveries() {
    print_discoveries_limited(10);
}

fn print_discoveries_all() {
    print_discoveries_limited(usize::MAX);
}

fn print_discoveries_limited(limit: usize) {
    println!();
    println!("Discoveries");
    println!("===========");
    println!();

    let items = load_local_discoveries();

    if items.is_empty() {
        println!("No local discoveries yet.");
        println!();
        println!("Run:");
        println!("   max_prime_public_client local-demo");
        println!("   max_prime_public_client official-explain");
        println!();
    } else {
        let best_digits = items.iter().map(|d| d.digits).max().unwrap_or(0);

        println!("My local discoveries");
        println!("--------------------");
        println!();
        println!("Total local discoveries: {}", items.len());
        println!("Best size: {} digits", best_digits);
        println!("Storage: {}", LOCAL_DISCOVERIES_PATH);
        println!();

        let shown = items.len().min(limit);

        for (idx, d) in items.iter().take(shown).enumerate() {
            println!("#{} | {} | {} digits", idx + 1, d.candidate_type, d.digits);
            println!("  SHA-256: {}", d.sha256);
            println!("  Copy full prime:");
            println!("     max_prime_public_client copy-local-prime {}", idx + 1);
            println!("  Copy SHA-256:");
            println!("     max_prime_public_client copy-local-sha {}", idx + 1);
            println!();
        }

        if shown < items.len() {
            println!("Showing first {} of {} discoveries.", shown, items.len());
            println!("To show everything:");
            println!("   max_prime_public_client discoveries-all");
            println!();
        }
    }

    println!("Future GUI sections:");
    println!("- My local discoveries");
    println!("- My official submissions");
    println!("- Public challenge discoveries");
    println!();
    println!("A huge prime can have thousands of digits.");
    println!("The SHA-256 fingerprint is a compact way to identify the exact same");
    println!("number without copying the full number every time.");
    println!();
}

fn d_candidate_from_n(n: &UBig) -> UBig {
    UBig::from(5u32) + n * (n + UBig::from(1u32))
}

fn expected_prime_probability_from_digits(digits: usize) -> f64 {
    1.0 / ((digits as f64) * std::f64::consts::LN_10)
}

fn parse_ubig_decimal(label: &str, value: &str) -> Result<UBig, String> {
    UBig::from_str(value).map_err(|e| format!("Cannot parse {} as decimal integer: {}", label, e))
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn egcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x1, y1) = egcd_i128(b, a % b);
        (g, y1, x1 - (a / b) * y1)
    }
}

fn mod_inverse_u128(a: u128, m: u128) -> Result<u128, String> {
    if m <= 1 {
        return Err("CRT modulus must be greater than 1.".to_string());
    }

    if a > i128::MAX as u128 || m > i128::MAX as u128 {
        return Err(
            "CRT modular inverse currently supports original moduli within i128 range.".to_string(),
        );
    }

    let (g, x, _) = egcd_i128(a as i128, m as i128);
    if g != 1 {
        return Err(format!(
            "CRT inverse does not exist: {} and {} are not coprime.",
            a, m
        ));
    }

    Ok(x.rem_euclid(m as i128) as u128)
}

fn mul_mod_u128(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut result: u128 = 0;
    a %= m;

    while b > 0 {
        if b & 1 == 1 {
            result = (result + a) % m;
        }
        a = (a * 2) % m;
        b >>= 1;
    }

    result
}

fn parse_u128_decimal(label: &str, value: &str) -> Result<u128, String> {
    let t = value.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("{} must contain only decimal digits.", label));
    }

    t.parse::<u128>()
        .map_err(|e| format!("Cannot parse {} as u128 decimal integer: {}", label, e))
}

fn resolve_advanced_filter(filter: &AdvancedFilterConfig) -> Result<AdvancedFilterConfig, String> {
    if !filter.enabled {
        return Ok(AdvancedFilterConfig {
            enabled: false,
            modulus_m: "1".to_string(),
            remainder_r: "0".to_string(),
            original_moduli: Vec::new(),
            original_remainders: Vec::new(),
        });
    }

    let has_originals =
        !filter.original_moduli.is_empty() || !filter.original_remainders.is_empty();

    if !has_originals {
        let m = parse_ubig_decimal("filter.modulus_m", &filter.modulus_m)?;
        let _r = parse_ubig_decimal("filter.remainder_r", &filter.remainder_r)?;

        if m == UBig::from(0u32) {
            return Err("CRT filter is enabled but filter.modulus_m is zero.".to_string());
        }

        return Ok(filter.clone());
    }

    if filter.original_moduli.len() != filter.original_remainders.len() {
        return Err(format!(
            "CRT multi-filter requires same count of original_moduli and original_remainders. Got {} moduli and {} remainders.",
            filter.original_moduli.len(),
            filter.original_remainders.len()
        ));
    }

    if filter.original_moduli.is_empty() {
        return Err("CRT multi-filter is enabled but original_moduli is empty.".to_string());
    }

    let mut m_acc: u128 = 1;
    let mut r_acc: u128 = 0;

    for (idx, (m_txt, r_txt)) in filter
        .original_moduli
        .iter()
        .zip(filter.original_remainders.iter())
        .enumerate()
    {
        let m2 = parse_u128_decimal(&format!("filter.original_moduli[{}]", idx), m_txt)?;
        let r2 = parse_u128_decimal(&format!("filter.original_remainders[{}]", idx), r_txt)?;

        if m2 <= 1 {
            return Err(format!(
                "CRT modulus at index {} must be greater than 1.",
                idx
            ));
        }

        if r2 >= m2 {
            return Err(format!(
                "CRT remainder at index {} must be smaller than its modulus. Got remainder {} modulo {}.",
                idx, r2, m2
            ));
        }

        let g = gcd_u128(m_acc, m2);
        if g != 1 {
            return Err(format!(
                "CRT moduli must be pairwise coprime. Current cumulative M {} and modulus {} have gcd {}.",
                m_acc, m2, g
            ));
        }

        let r1_mod_m2 = r_acc % m2;
        let diff = if r2 >= r1_mod_m2 {
            r2 - r1_mod_m2
        } else {
            m2 - (r1_mod_m2 - r2)
        };

        let inv = mod_inverse_u128(m_acc % m2, m2)?;
        let k = mul_mod_u128(diff, inv, m2);

        let add = m_acc
            .checked_mul(k)
            .ok_or_else(|| "CRT cumulative remainder overflowed u128. Use cumulative M/R for very large CRT products.".to_string())?;

        let new_m = m_acc
            .checked_mul(m2)
            .ok_or_else(|| "CRT cumulative modulus overflowed u128. Use cumulative M/R for very large CRT products.".to_string())?;

        r_acc = (r_acc + add) % new_m;
        m_acc = new_m;
    }

    Ok(AdvancedFilterConfig {
        enabled: true,
        modulus_m: m_acc.to_string(),
        remainder_r: r_acc.to_string(),
        original_moduli: filter.original_moduli.clone(),
        original_remainders: filter.original_remainders.clone(),
    })
}

fn candidate_type_label(test_n: bool, test_d: bool) -> String {
    match (test_n, test_d) {
        (true, true) => "N,d".to_string(),
        (true, false) => "N".to_string(),
        (false, true) => "d".to_string(),
        (false, false) => "none".to_string(),
    }
}

fn run_advanced_local(config_path: &str) -> Result<(), String> {
    println!();
    println!("Advanced Local Experiment");
    println!("=========================");
    println!();
    println!("Config:");
    println!("   {}", config_path);
    println!();

    let txt =
        fs::read_to_string(config_path).map_err(|e| format!("Cannot read config file: {}", e))?;

    let cfg: AdvancedExperimentConfig = serde_json::from_str(&txt)
        .map_err(|e| format!("Cannot parse advanced experiment JSON: {}", e))?;

    if !cfg.test_n && !cfg.test_d {
        return Err(
            "Config must enable at least one candidate type: test_n or test_d.".to_string(),
        );
    }

    let n0 = parse_ubig_decimal("n0", &cfg.n0)?;
    let step = parse_ubig_decimal("step", &cfg.step)?;
    let resolved_filter = resolve_advanced_filter(&cfg.filter)?;
    let modulus_m = parse_ubig_decimal("filter.modulus_m", &resolved_filter.modulus_m)?;
    let remainder_r = parse_ubig_decimal("filter.remainder_r", &resolved_filter.remainder_r)?;

    let started_at = now_unix();

    let mut state = CurrentRunState {
        status: "running".to_string(),
        mode: "advanced-local".to_string(),
        experiment_id: cfg.experiment_id.clone(),
        candidate_type: candidate_type_label(cfg.test_n, cfg.test_d),
        iterations_total: cfg.iterations,
        iterations_done: 0,
        n_digits: cfg.n0.len(),
        hits_found: 0,
        hits_exported: 0,
        best_digits: 0,
        best_sha256: String::new(),
        test_n: cfg.test_n,
        test_d: cfg.test_d,
        filter_enabled: resolved_filter.enabled,
        filter: Some(resolved_filter.clone()),
        expected_n_primes: 0.0,
        observed_n_primes: 0,
        n_enrichment: 0.0,
        expected_d_primes: 0.0,
        observed_d_primes: 0,
        d_enrichment: 0.0,
        hits: Vec::new(),
        engine: "dashu-int".to_string(),
        started_at_unix: started_at,
        updated_at_unix: started_at,
        completed_at_unix: 0,
        message: "Advanced local experiment running. No official server submission.".to_string(),
    };

    save_current_run_state(&state)?;

    println!("Experiment ID: {}", cfg.experiment_id);
    println!("Iterations: {}", cfg.iterations);
    println!("Test N: {}", cfg.test_n);
    println!("Test d: {}", cfg.test_d);
    println!("CRT filter enabled: {}", resolved_filter.enabled);
    println!("Engine: dashu-int");
    println!();

    let mut hits: Vec<LocalDiscovery> = Vec::new();

    let mut expected_n_primes: f64 = 0.0;
    let mut observed_n_primes: usize = 0;

    let mut expected_d_primes: f64 = 0.0;
    let mut observed_d_primes: usize = 0;

    // Motore privato opzionale.
    // Mantiene intatti stato, progressi ed esportazioni.
    let private_advanced_optimized = true;

    let first_effective = if resolved_filter.enabled {
        &remainder_r + &modulus_m * &n0
    } else {
        n0.clone()
    };

    let effective_step = if resolved_filter.enabled {
        &modulus_m * &step
    } else {
        step.clone()
    };

    // Il crivello conviene soprattutto sui pacchetti grandi.
    // Con filtri arbitrari non saltiamo alcun modulo.
    let use_private_sieve = private_advanced_optimized
        && cfg.test_n
        && cfg.iterations >= 25
        && cfg.iterations <= 200_000
        && decimal_digits(&n_candidate_from_n(&first_effective)) >= 100;

    let (private_n_mask, mut private_n_cursor) = if use_private_sieve {
        let primes = crtcomp_primes_up_to(if cfg.iterations < 500 {
            500_000
        } else {
            5_000_000
        });

        let schedule = crtcomp_compile_schedule(&primes, &effective_step, false);

        let mut persistent = crtcomp_initialize_persistent_state(&first_effective, &schedule);

        let mask = crtcomp_mark_persistent(cfg.iterations, &schedule, &mut persistent);

        (
            Some(mask),
            Some(CrtCompCandidateCursor::new(
                &first_effective,
                &effective_step,
            )),
        )
    } else {
        (None, None)
    };

    println!(
        "MAX optimized engine: {}",
        if private_advanced_optimized {
            "OPTIMIZED"
        } else {
            "LEGACY"
        }
    );

    println!("MAX structural sieve: {}", use_private_sieve);

    for i in 0..cfg.iterations {
        let n_raw = &n0 + (&step * UBig::from(i as u64));

        let n_effective = if resolved_filter.enabled {
            &remainder_r + (&modulus_m * &n_raw)
        } else {
            n_raw.clone()
        };

        if cfg.test_n {
            let private_rejected = private_n_mask.as_ref().map(|mask| mask[i]).unwrap_or(false);

            // Conserviamo il conteggio originale delle cifre.
            // Evitiamo MR sui candidati scartati dal crivello.
            let candidate = if private_rejected {
                n_candidate_from_n(&n_effective)
            } else if let Some(cursor) = private_n_cursor.as_mut() {
                cursor.at(i).clone()
            } else {
                n_candidate_from_n(&n_effective)
            };
            let digits = decimal_digits(&candidate);
            expected_n_primes += expected_prime_probability_from_digits(digits);

            if !private_rejected
                && if private_advanced_optimized {
                    is_probable_prime_ring_max(&candidate)
                } else {
                    is_probable_prime(&candidate)
                }
            {
                observed_n_primes += 1;
                let sha = sha256_decimal(&candidate);

                if digits > state.best_digits {
                    state.best_digits = digits;
                    state.best_sha256 = sha.clone();
                }

                println!(
                    "Hit found: N | i {} | {} digits | sha256 {}",
                    i, digits, sha
                );

                hits.push(LocalDiscovery {
                    mode: "advanced-local".to_string(),
                    candidate_type: "N".to_string(),
                    i,
                    n: n_effective.to_string(),
                    candidate: candidate.to_string(),
                    digits,
                    sha256: sha,
                    found_at_unix: now_unix(),
                    note: format!(
                        "Advanced local experiment {}. Not an official challenge submission.",
                        cfg.experiment_id
                    ),
                });
            }
        }

        if cfg.test_d {
            let candidate = d_candidate_from_n(&n_effective);
            let digits = decimal_digits(&candidate);
            expected_d_primes += expected_prime_probability_from_digits(digits);

            if if private_advanced_optimized {
                is_probable_prime_ring_general(&candidate)
            } else {
                is_probable_prime(&candidate)
            } {
                observed_d_primes += 1;
                let sha = sha256_decimal(&candidate);

                if digits > state.best_digits {
                    state.best_digits = digits;
                    state.best_sha256 = sha.clone();
                }

                println!(
                    "Hit found: d | i {} | {} digits | sha256 {}",
                    i, digits, sha
                );

                hits.push(LocalDiscovery {
                    mode: "advanced-local".to_string(),
                    candidate_type: "d".to_string(),
                    i,
                    n: n_effective.to_string(),
                    candidate: candidate.to_string(),
                    digits,
                    sha256: sha,
                    found_at_unix: now_unix(),
                    note: format!(
                        "Advanced local experiment {}. Not an official challenge submission.",
                        cfg.experiment_id
                    ),
                });
            }
        }

        state.iterations_done = i + 1;
        state.hits_found = hits.len();
        state.hits_exported = hits.len();
        state.expected_n_primes = expected_n_primes;
        state.observed_n_primes = observed_n_primes;
        state.n_enrichment = if expected_n_primes > 0.0 {
            observed_n_primes as f64 / expected_n_primes
        } else {
            0.0
        };
        state.expected_d_primes = expected_d_primes;
        state.observed_d_primes = observed_d_primes;
        state.d_enrichment = if expected_d_primes > 0.0 {
            observed_d_primes as f64 / expected_d_primes
        } else {
            0.0
        };
        state.hits = hits.clone();
        state.updated_at_unix = now_unix();

        if i == 0 || (i + 1) % 100 == 0 || i + 1 == cfg.iterations {
            save_current_run_state(&state)?;
            println!(
                "Progress: {}/{} | hits: {} | N enrichment: {:.3}×",
                i + 1,
                cfg.iterations,
                hits.len(),
                state.n_enrichment
            );
        }
    }

    let n_enrichment = if expected_n_primes > 0.0 {
        observed_n_primes as f64 / expected_n_primes
    } else {
        0.0
    };

    let d_enrichment = if expected_d_primes > 0.0 {
        observed_d_primes as f64 / expected_d_primes
    } else {
        0.0
    };

    if !hits.is_empty() {
        append_local_discoveries(hits.clone())?;
    }

    state.status = "completed".to_string();
    state.iterations_done = cfg.iterations;
    state.hits_found = hits.len();
    state.hits_exported = hits.len();
    state.expected_n_primes = expected_n_primes;
    state.observed_n_primes = observed_n_primes;
    state.n_enrichment = n_enrichment;
    state.expected_d_primes = expected_d_primes;
    state.observed_d_primes = observed_d_primes;
    state.d_enrichment = d_enrichment;
    state.hits = hits.clone();
    state.updated_at_unix = now_unix();
    state.completed_at_unix = state.updated_at_unix;
    state.message = format!(
        "Advanced local experiment completed. Hits: {}. N enrichment: {:.3}×. d enrichment: {:.3}×. Engine: dashu-int.",
        hits.len(),
        n_enrichment,
        d_enrichment
    );
    save_current_run_state(&state)?;

    let result = AdvancedRunResult {
        experiment_id: cfg.experiment_id.clone(),
        mode: "advanced-local".to_string(),
        iterations_done: cfg.iterations,
        test_n: cfg.test_n,
        test_d: cfg.test_d,
        filter_enabled: resolved_filter.enabled,
        expected_n_primes,
        observed_n_primes,
        n_enrichment,
        expected_d_primes,
        observed_d_primes,
        d_enrichment,
        hits: hits.clone(),
        saved_at_unix: now_unix(),
        note: "Advanced local experiment result. Not an official challenge submission. Engine: dashu-int.".to_string(),
    };

    fs::create_dir_all("exports").map_err(|e| format!("Cannot create exports folder: {}", e))?;

    let export_path = format!(
        "exports/advanced_local_{}_{}.json",
        cfg.experiment_id,
        now_unix()
    );
    let result_json = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Cannot serialize advanced result: {}", e))?;

    fs::write(&export_path, result_json)
        .map_err(|e| format!("Cannot write advanced result export: {}", e))?;

    println!();
    println!("Advanced Local Experiment completed.");
    println!("------------------------------------");
    println!("Experiment ID: {}", cfg.experiment_id);
    println!("Iterations tested: {}", cfg.iterations);
    println!("Test N: {}", cfg.test_n);
    println!("Test d: {}", cfg.test_d);
    println!("CRT filter enabled: {}", resolved_filter.enabled);
    println!("Engine: dashu-int");
    println!();
    println!("Observed N primes: {}", observed_n_primes);
    println!("Expected random N primes: {:.6}", expected_n_primes);
    println!("N enrichment: {:.3}×", n_enrichment);
    println!();
    println!("Observed d primes: {}", observed_d_primes);
    println!("Expected random d primes: {:.6}", expected_d_primes);
    println!("d enrichment: {:.3}×", d_enrichment);
    println!();
    println!("Total hits saved: {}", hits.len());
    println!("Result export:");
    println!("   {}", export_path);
    println!();
    println!("State file:");
    println!("   {}", CURRENT_RUN_STATE_PATH);
    println!();

    Ok(())
}

fn preview_advanced_local(config_path: &str) -> Result<(), String> {
    println!();
    println!("Advanced Local Preview");
    println!("======================");
    println!();
    println!("Config:");
    println!("   {}", config_path);
    println!();

    let txt =
        fs::read_to_string(config_path).map_err(|e| format!("Cannot read config file: {}", e))?;

    let cfg: AdvancedExperimentConfig = serde_json::from_str(&txt)
        .map_err(|e| format!("Cannot parse advanced experiment JSON: {}", e))?;

    if !cfg.test_n && !cfg.test_d {
        return Err(
            "Config must enable at least one candidate type: test_n or test_d.".to_string(),
        );
    }

    if cfg.iterations == 0 {
        return Err("Config iterations must be greater than zero.".to_string());
    }

    let n0 = parse_ubig_decimal("n0", &cfg.n0)?;
    let step = parse_ubig_decimal("step", &cfg.step)?;
    let resolved_filter = resolve_advanced_filter(&cfg.filter)?;
    let modulus_m = parse_ubig_decimal("filter.modulus_m", &resolved_filter.modulus_m)?;
    let remainder_r = parse_ubig_decimal("filter.remainder_r", &resolved_filter.remainder_r)?;

    let first_i: usize = 0;
    let last_i: usize = cfg.iterations - 1;

    let first_n_raw = n0.clone();
    let last_n_raw = &n0 + (&step * UBig::from(last_i as u64));

    let first_n_effective = if resolved_filter.enabled {
        &remainder_r + (&modulus_m * &first_n_raw)
    } else {
        first_n_raw.clone()
    };

    let last_n_effective = if resolved_filter.enabled {
        &remainder_r + (&modulus_m * &last_n_raw)
    } else {
        last_n_raw.clone()
    };

    println!("Experiment ID: {}", cfg.experiment_id);
    println!("Iterations: {}", cfg.iterations);
    println!(
        "Candidate types: {}",
        candidate_type_label(cfg.test_n, cfg.test_d)
    );
    println!("Test N: {}", cfg.test_n);
    println!("Test d: {}", cfg.test_d);
    println!();

    println!("Input size:");
    println!("   n0 digits: {}", cfg.n0.len());
    println!("   step digits: {}", cfg.step.len());
    println!();

    println!("CRT filter:");
    println!("   enabled: {}", resolved_filter.enabled);
    println!("   M: {}", resolved_filter.modulus_m);
    println!("   R: {}", resolved_filter.remainder_r);
    println!(
        "   original moduli count: {}",
        resolved_filter.original_moduli.len()
    );
    println!(
        "   original remainders count: {}",
        resolved_filter.original_remainders.len()
    );

    if resolved_filter.enabled {
        println!("   CRT formula: n_effective = R + M * n_raw");
    } else {
        println!("   CRT formula: OFF, so n_effective = n_raw");
    }
    println!();

    println!("Iteration range preview:");
    println!("   first i: {}", first_i);
    println!("   last i: {}", last_i);
    println!("   first n_raw digits: {}", decimal_digits(&first_n_raw));
    println!("   last n_raw digits: {}", decimal_digits(&last_n_raw));
    println!(
        "   first n_effective digits: {}",
        decimal_digits(&first_n_effective)
    );
    println!(
        "   last n_effective digits: {}",
        decimal_digits(&last_n_effective)
    );
    println!();

    if cfg.test_n {
        let first_n_candidate = n_candidate_from_n(&first_n_effective);
        let last_n_candidate = n_candidate_from_n(&last_n_effective);
        println!("N candidate preview:");
        println!("   formula: N = 31 + 6*n_effective*(n_effective+1)");
        println!("   first N digits: {}", decimal_digits(&first_n_candidate));
        println!("   last N digits: {}", decimal_digits(&last_n_candidate));
        println!(
            "   first N expected prime probability approx: {:.9}",
            expected_prime_probability_from_digits(decimal_digits(&first_n_candidate))
        );
        println!();
    }

    if cfg.test_d {
        let first_d_candidate = d_candidate_from_n(&first_n_effective);
        let last_d_candidate = d_candidate_from_n(&last_n_effective);
        println!("d candidate preview:");
        println!("   formula: d = 5 + n_effective*(n_effective+1)");
        println!("   first d digits: {}", decimal_digits(&first_d_candidate));
        println!("   last d digits: {}", decimal_digits(&last_d_candidate));
        println!(
            "   first d expected prime probability approx: {:.9}",
            expected_prime_probability_from_digits(decimal_digits(&first_d_candidate))
        );
        println!();
    }

    println!("Safety note:");
    println!("   This command does not run the experiment.");
    println!("   It does not save discoveries.");
    println!("   It does not export a result JSON.");
    println!("   It only previews the config before advanced-local execution.");
    println!();

    println!("To run this experiment:");
    println!("   max_prime_public_client advanced-local {}", config_path);
    println!();

    Ok(())
}

fn generate_client_device_id() -> String {
    let seed = format!(
        "max-prime-public-client:{}:{}:{:?}",
        now_unix(),
        std::process::id(),
        std::time::SystemTime::now()
    );
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("mpc-device-{}", &hex[..24])
}

fn default_official_client_config() -> OfficialClientConfig {
    let now = now_unix();
    OfficialClientConfig {
        mode: "official-participant-v1".to_string(),
        official_api_base: OFFICIAL_API_BASE.to_string(),
        client_device_id: generate_client_device_id(),
        participant_id: "".to_string(),
        participant_token: "".to_string(),
        participant_token_status: "not_registered".to_string(),
        token_id: "".to_string(),
        max_id: "".to_string(),
        max_id_hash: "".to_string(),
        public_nickname: "".to_string(),
        public_display_name: "".to_string(),
        max_login_status: "not_connected".to_string(),
        registration_id: "".to_string(),
        registration_status: "not_started".to_string(),
        login_session_id: "".to_string(),
        login_session_status: "not_started".to_string(),
        login_started_at_unix: 0,
        login_expires_at_unix: 0,
        qr_text: "".to_string(),
        deeplink: "".to_string(),
        callback_url: "".to_string(),
        created_at_unix: now,
        updated_at_unix: now,
        note: "Official participant config. The participant token is stored locally on this computer and must not be shared.".to_string(),
    }
}

fn validate_official_api_base(official_api_base: &str) -> Result<(), String> {
    if official_api_base == OFFICIAL_API_BASE {
        Ok(())
    } else {
        Err(format!(
            "Invalid official_api_base in official client config: expected exactly {}. Refusing to contact a non-official endpoint.",
            OFFICIAL_API_BASE
        ))
    }
}

fn save_official_client_config(cfg: &OfficialClientConfig) -> Result<(), String> {
    create_private_dir(APP_STATE_DIR)?;
    let txt = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("Cannot serialize official client config: {}", e))?;
    write_text_atomic(OFFICIAL_CLIENT_CONFIG_PATH, &txt)
        .map_err(|e| format!("Cannot write official client config: {}", e))?;
    Ok(())
}

fn load_or_create_official_client_config() -> Result<OfficialClientConfig, String> {
    if Path::new(OFFICIAL_CLIENT_CONFIG_PATH).exists() {
        let txt = fs::read_to_string(OFFICIAL_CLIENT_CONFIG_PATH)
            .map_err(|e| format!("Cannot read official client config: {}", e))?;

        let value: serde_json::Value = serde_json::from_str(&txt)
            .map_err(|e| format!("Cannot parse official client config JSON: {}", e))?;

        let now = now_unix();
        let cfg = OfficialClientConfig {
            mode: {
                let m = value.get("mode").and_then(|v| v.as_str()).unwrap_or("official-participant-v1");
                if m == "official-skeleton" { "official-participant-v1".to_string() } else { m.to_string() }
            },
            official_api_base: value.get("official_api_base").and_then(|v| v.as_str()).unwrap_or(OFFICIAL_API_BASE).to_string(),
            client_device_id: value.get("client_device_id").and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(|v| v.to_string()).unwrap_or_else(generate_client_device_id),
            participant_id: value.get("participant_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            participant_token: value.get("participant_token").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            participant_token_status: value.get("participant_token_status").and_then(|v| v.as_str()).unwrap_or("not_registered").to_string(),
            token_id: value.get("token_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            max_id: value.get("max_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            max_id_hash: value.get("max_id_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            public_nickname: value.get("public_nickname").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            public_display_name: value.get("public_display_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            max_login_status: value.get("max_login_status").and_then(|v| v.as_str()).unwrap_or("not_connected").to_string(),
            registration_id: value.get("registration_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            registration_status: value.get("registration_status").and_then(|v| v.as_str()).unwrap_or_else(|| value.get("login_session_status").and_then(|v| v.as_str()).unwrap_or("not_started")).to_string(),
            login_session_id: value.get("login_session_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            login_session_status: value.get("login_session_status").and_then(|v| v.as_str()).unwrap_or("not_started").to_string(),
            login_started_at_unix: value.get("login_started_at_unix").and_then(|v| v.as_u64()).unwrap_or(0),
            login_expires_at_unix: value.get("login_expires_at_unix").and_then(|v| v.as_u64()).unwrap_or(0),
            qr_text: value.get("qr_text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            deeplink: value.get("deeplink").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            callback_url: value.get("callback_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            created_at_unix: value.get("created_at_unix").and_then(|v| v.as_u64()).unwrap_or(now),
            updated_at_unix: value.get("updated_at_unix").and_then(|v| v.as_u64()).unwrap_or(now),
            note: value.get("note").and_then(|v| v.as_str()).unwrap_or("Official participant config. The participant token is stored locally on this computer and must not be shared.").to_string(),
        };

        validate_official_api_base(&cfg.official_api_base)?;
        save_official_client_config(&cfg)?;
        Ok(cfg)
    } else {
        let cfg = default_official_client_config();
        save_official_client_config(&cfg)?;
        Ok(cfg)
    }
}

fn print_official_config(cfg: &OfficialClientConfig) {
    println!();
    println!("Official Client Config");
    println!("======================");
    println!();
    println!("Config file:");
    println!("   {}", OFFICIAL_CLIENT_CONFIG_PATH);
    println!();
    println!("Mode: {}", cfg.mode);
    println!("Official API base: {}", cfg.official_api_base);
    println!("Client device ID: {}", cfg.client_device_id);
    println!("MAX Login status: {}", cfg.max_login_status);
    println!(
        "Registration ID: {}",
        if cfg.registration_id.is_empty() {
            "(none)"
        } else {
            &cfg.registration_id
        }
    );
    println!("Registration status: {}", cfg.registration_status);
    println!(
        "Login session ID: {}",
        if cfg.login_session_id.is_empty() {
            "(none)"
        } else {
            &cfg.login_session_id
        }
    );
    println!("Login session status: {}", cfg.login_session_status);
    println!("Login started at unix: {}", cfg.login_started_at_unix);
    println!("Login expires at unix: {}", cfg.login_expires_at_unix);
    println!(
        "Participant ID: {}",
        if cfg.participant_id.is_empty() {
            "(not registered yet)"
        } else {
            &cfg.participant_id
        }
    );
    println!("Participant token status: {}", cfg.participant_token_status);
    println!(
        "Token ID: {}",
        if cfg.token_id.is_empty() {
            "(none)"
        } else {
            &cfg.token_id
        }
    );
    println!(
        "MAX ID: {}",
        if cfg.max_id.is_empty() {
            "(not loaded yet)"
        } else {
            &cfg.max_id
        }
    );
    println!(
        "Public nickname: {}",
        if cfg.public_nickname.is_empty() {
            "(none)"
        } else {
            &cfg.public_nickname
        }
    );
    println!(
        "Public display name: {}",
        if cfg.public_display_name.is_empty() {
            "(MAX ID or not loaded yet)"
        } else {
            &cfg.public_display_name
        }
    );
    println!(
        "Participant token stored locally: {}",
        if cfg.participant_token.is_empty() {
            "false"
        } else {
            "true"
        }
    );
    println!("Created at unix: {}", cfg.created_at_unix);
    println!("Updated at unix: {}", cfg.updated_at_unix);
    println!();
    println!("Security:");
    println!("   No Hugging Face token is stored here.");
    println!("   No database credentials are stored here.");
    println!("   No private MAX Login code is stored here.");
    println!("   The participant token is a local secret. Do not publish app_state/official_client_config.json.");
    println!();
    println!("Note:");
    println!("   {}", cfg.note);
    println!();
}

fn official_cli_banner(title: &str) {
    let line = "=".repeat(72);
    println!();
    println!("{}", line);
    println!("{}", title.to_uppercase());
    println!("{}", line);
    println!();
}

fn official_update_identity_from_response(
    cfg: &mut OfficialClientConfig,
    response: &serde_json::Value,
) {
    if let Some(max_id) = official_find_string_deep(response, "max_id") {
        if !max_id.trim().is_empty() {
            cfg.max_id = max_id.trim().to_string();
        }
    }

    if let Some(max_id_hash) = official_find_string_deep(response, "max_id_hash") {
        if !max_id_hash.trim().is_empty() {
            cfg.max_id_hash = max_id_hash.trim().to_string();
        }
    }

    if cfg.max_id.is_empty() && !cfg.max_id_hash.is_empty() {
        cfg.max_id = cfg.max_id_hash.clone();
    }

    if cfg.max_id_hash.is_empty() && !cfg.max_id.is_empty() {
        cfg.max_id_hash = cfg.max_id.clone();
    }

    if let Some(public_nickname) = official_find_string_deep(response, "public_nickname") {
        cfg.public_nickname = public_nickname.trim().to_string();
    }

    if let Some(public_display_name) = official_find_string_deep(response, "public_display_name") {
        cfg.public_display_name = public_display_name.trim().to_string();
    }

    if cfg.public_display_name.is_empty() {
        if !cfg.public_nickname.is_empty() {
            cfg.public_display_name = cfg.public_nickname.clone();
        } else if !cfg.max_id.is_empty() {
            cfg.public_display_name = cfg.max_id.clone();
        }
    }

    cfg.updated_at_unix = now_unix();
}

fn official_print_identity_from_config(cfg: &OfficialClientConfig) {
    println!("MAX ID:");
    println!(
        "   {}",
        if cfg.max_id.is_empty() {
            "(not loaded yet)"
        } else {
            &cfg.max_id
        }
    );
    println!("Public nickname:");
    println!(
        "   {}",
        if cfg.public_nickname.is_empty() {
            "(none)"
        } else {
            &cfg.public_nickname
        }
    );
    println!("Public display name:");
    println!(
        "   {}",
        if cfg.public_display_name.is_empty() {
            "(MAX ID or not loaded yet)"
        } else {
            &cfg.public_display_name
        }
    );
}

fn official_config_mode() -> Result<(), String> {
    let cfg = load_or_create_official_client_config()?;
    print_official_config(&cfg);
    Ok(())
}

fn official_device_mode() -> Result<(), String> {
    let cfg = load_or_create_official_client_config()?;
    println!();
    println!("Official Client Device");
    println!("======================");
    println!();
    println!("Client device ID:");
    println!("   {}", cfg.client_device_id);
    println!();
    println!("Config file:");
    println!("   {}", OFFICIAL_CLIENT_CONFIG_PATH);
    println!();
    println!("Status: local device identity only. Not registered with MAX Login yet.");
    println!();
    Ok(())
}

#[allow(dead_code)]
fn generate_login_session_id(client_device_id: &str) -> String {
    let seed = format!(
        "max-prime-login-placeholder:{}:{}:{}",
        client_device_id,
        now_unix(),
        std::process::id()
    );
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("mpc-login-{}", &hex[..24])
}

fn official_login_start_mode() -> Result<(), String> {
    let mut cfg = load_or_create_official_client_config()?;
    let now = now_unix();

    println!();
    println!("Official MAX Login Registration Start");
    println!("=====================================");
    println!();

    if !cfg.participant_token.trim().is_empty() && cfg.participant_token_status == "registered" {
        println!("This client is already registered.");
        println!("Participant ID:");
        println!("   {}", cfg.participant_id);
        println!("Participant token stored locally:");
        println!("   true");
        println!();
        println!("You can now run official assigned work.");
        println!();
        return Ok(());
    }

    if !cfg.registration_id.trim().is_empty()
        && cfg.registration_status == "pending"
        && cfg.login_expires_at_unix > now
    {
        println!("A MAX Login registration is already pending.");
        println!("Do not click Register again unless this request expires.");
        println!();
        println!("Registration ID:");
        println!("   {}", cfg.registration_id);
        println!("Expires at unix:");
        println!("   {}", cfg.login_expires_at_unix);
        println!();
        println!("MAX Login QR text:");
        if cfg.qr_text.trim().is_empty() {
            println!("   (QR text not stored locally)");
        } else {
            println!("{}", cfg.qr_text);
        }
        println!();
        if !cfg.deeplink.trim().is_empty() {
            println!("MAX App deeplink / fallback:");
            println!("   {}", cfg.deeplink);
            println!();
        }
        println!("After approving with MAX App, run:");
        println!("   max_prime_public_client official-login-status");
        println!();
        return Ok(());
    }

    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let url = format!("{}/api-prime-participant-register-start.php", base);

    let payload = serde_json::json!({
        "client_device_id": cfg.client_device_id,
        "device_label": "MAX Prime Public Client"
    });

    println!("Contacting MAX Prime server...");
    println!("Endpoint:");
    println!("   {}", url);
    println!("Client device ID:");
    println!("   {}", cfg.client_device_id);
    println!();

    let response = official_http_post_json(&url, &payload)?;

    create_private_dir(APP_STATE_DIR)?;
    write_sensitive_text(
        "app_state/last_registration_start_response.json",
        serde_json::to_string_pretty(&official_redact_secrets(&response))
            .map_err(|e| format!("Cannot serialize registration start response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write registration start response: {}", e))?;

    if !official_bool_ok(&response) {
        println!("Registration start failed.");
        if let Some(error_code) = response.get("error_code").and_then(|v| v.as_str()) {
            println!("Error code: {}", error_code);
        }
        if let Some(message) = response.get("message").and_then(|v| v.as_str()) {
            println!("Message: {}", message);
        }
        println!("Response saved:");
        println!("   app_state/last_registration_start_response.json");
        return Ok(());
    }

    let registration_id =
        official_find_string_deep(&response, "registration_id").ok_or_else(|| {
            "Registration start response did not include registration_id.".to_string()
        })?;

    let raw_qr_text = official_find_string_deep(&response, "qr_text")
        .or_else(|| official_find_string_deep(&response, "payload_b64"))
        .unwrap_or_default();

    let deeplink = official_find_string_deep(&response, "deeplink").unwrap_or_default();
    let fallback = official_find_string_deep(&response, "fallback").unwrap_or_default();

    // IMPORTANT:
    // Internal MAX App scanner expects raw JSON payload in the QR,
    // exactly like protected publish approval.
    // The server field qr_text is the source of truth.
    let qr_text = raw_qr_text.clone();

    let callback_url = official_find_string_deep(&response, "callback").unwrap_or_default();
    let expires_at = official_find_u64_deep(&response, "expires_at_unix")
        .or_else(|| official_find_u64_deep(&response, "expires_at"))
        .unwrap_or(now + 300);

    cfg.registration_id = registration_id.clone();
    cfg.registration_status = "pending".to_string();
    cfg.login_session_id = registration_id.clone();
    cfg.login_session_status = "pending".to_string();
    cfg.max_login_status = "pending_user_approval".to_string();
    cfg.login_started_at_unix = now;
    cfg.login_expires_at_unix = expires_at;
    cfg.qr_text = qr_text.clone();
    cfg.deeplink = deeplink.clone();
    cfg.callback_url = callback_url;
    cfg.updated_at_unix = now;
    cfg.note = "MAX Login participant registration started. Approve it with MAX App, then run official-login-status.".to_string();

    save_official_client_config(&cfg)?;

    println!("Registration started.");
    println!();
    println!("Registration ID:");
    println!("   {}", registration_id);
    println!("Expires at unix:");
    println!("   {}", expires_at);
    println!();
    println!("MAX Login QR text:");
    if qr_text.trim().is_empty() {
        println!("   (QR text not returned by server)");
    } else {
        println!("{}", qr_text);
    }
    println!();

    println!("QR selection rule:");
    println!("   qr_text raw JSON payload for internal MAX App scanner");
    println!();

    if !fallback.trim().is_empty() {
        println!("MAX App fallback:");
        println!("   {}", fallback);
        println!();
    }

    if !deeplink.trim().is_empty() {
        println!("MAX App deeplink:");
        println!("   {}", deeplink);
        println!();
    }

    if !raw_qr_text.trim().is_empty() && raw_qr_text != qr_text {
        println!("Raw server qr_text:");
        println!("   {}", raw_qr_text);
        println!();
    }

    println!("Next step:");
    println!("   1. Scan/approve this MAX Login request with MAX App.");
    println!("   2. Then run:");
    println!("      max_prime_public_client official-login-status");
    println!();
    println!("Server response saved:");
    println!("   app_state/last_registration_start_response.json");
    println!();

    Ok(())
}

fn official_login_status_mode() -> Result<(), String> {
    let mut cfg = load_or_create_official_client_config()?;
    let now = now_unix();

    official_cli_banner("Official MAX Login Registration Status");
    println!("Official MAX Login Registration Status");
    println!("======================================");
    println!();

    if cfg.registration_id.trim().is_empty() {
        println!("No registration is in progress.");
        println!();
        println!("Start registration first:");
        println!("   max_prime_public_client official-login-start");
        println!();
        return Ok(());
    }

    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let url = format!("{}/api-prime-participant-register-poll.php", base);

    let payload = serde_json::json!({
        "registration_id": cfg.registration_id,
        "client_device_id": cfg.client_device_id
    });

    println!("Polling MAX Prime server...");
    println!("Registration ID:");
    println!("   {}", cfg.registration_id);
    println!("Client device ID:");
    println!("   {}", cfg.client_device_id);
    println!();

    let response = official_http_post_json(&url, &payload)?;

    create_private_dir(APP_STATE_DIR)?;
    write_sensitive_text(
        "app_state/last_registration_poll_response.json",
        serde_json::to_string_pretty(&official_redact_secrets(&response))
            .map_err(|e| format!("Cannot serialize registration poll response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write registration poll response: {}", e))?;

    let status = official_find_string_deep(&response, "registration_status")
        .or_else(|| official_find_string_deep(&response, "qr_status"))
        .or_else(|| official_find_string_deep(&response, "status"))
        .unwrap_or_else(|| "unknown".to_string());

    cfg.registration_status = status.clone();
    cfg.login_session_status = status.clone();
    cfg.updated_at_unix = now;

    if now > cfg.login_expires_at_unix
        && cfg.login_expires_at_unix > 0
        && cfg.participant_token.is_empty()
    {
        cfg.max_login_status = "expired_or_not_connected".to_string();
    }

    if let Some(participant_id) = official_find_string_deep(&response, "participant_id") {
        if !participant_id.trim().is_empty() {
            cfg.participant_id = participant_id;
        }
    }

    if let Some(token_id) = official_find_string_deep(&response, "token_id") {
        if !token_id.trim().is_empty() {
            cfg.token_id = token_id;
        }
    }

    if let Some(participant_token) = official_find_string_deep(&response, "participant_token") {
        if !participant_token.trim().is_empty() {
            cfg.participant_token = participant_token;
            cfg.participant_token_status = "registered".to_string();
            cfg.max_login_status = "connected".to_string();
            cfg.registration_status = "approved".to_string();
            cfg.login_session_status = "approved".to_string();
            cfg.note = "MAX Login approved. Participant token stored locally. This file is now sensitive and must not be published.".to_string();
        }
    }

    official_update_identity_from_response(&mut cfg, &response);
    save_official_client_config(&cfg)?;

    println!("Registration status:");
    println!("   {}", cfg.registration_status);
    println!("MAX Login status:");
    println!("   {}", cfg.max_login_status);
    println!("Participant ID:");
    println!(
        "   {}",
        if cfg.participant_id.is_empty() {
            "(not registered yet)"
        } else {
            &cfg.participant_id
        }
    );
    println!("Participant token status:");
    println!("   {}", cfg.participant_token_status);
    official_print_identity_from_config(&cfg);
    println!("Participant token stored locally:");
    println!(
        "   {}",
        if cfg.participant_token.is_empty() {
            "false"
        } else {
            "true"
        }
    );
    println!();

    if cfg.participant_token_status == "registered" && !cfg.participant_token.is_empty() {
        println!("Registration completed.");
        println!("You can now run official assigned work:");
        println!("   max_prime_public_client official-run-once <challenge_id>");
    } else {
        println!("Registration is not completed yet.");
        println!("Approve the QR request with MAX App, then run this command again.");
        if !cfg.qr_text.trim().is_empty() {
            println!();
            println!("Stored QR text:");
            println!("{}", cfg.qr_text);
        }
    }

    println!();
    println!("Poll response saved with secrets redacted:");
    println!("   app_state/last_registration_poll_response.json");
    println!();

    Ok(())
}

fn official_get_work_mode() -> Result<(), String> {
    let mut cfg = load_or_create_official_client_config()?;

    official_cli_banner("Official Participant Status");
    println!("Client device ID:");
    println!("   {}", cfg.client_device_id);
    println!("Participant ID:");
    println!(
        "   {}",
        if cfg.participant_id.is_empty() {
            "(not registered yet)"
        } else {
            &cfg.participant_id
        }
    );
    println!("Participant token status:");
    println!("   {}", cfg.participant_token_status);
    official_print_identity_from_config(&cfg);
    println!();

    if cfg.participant_token.trim().is_empty() {
        println!("Blocked locally: participant token is missing.");
        println!();
        println!("Run:");
        println!("   max_prime_public_client official-login-start");
        println!("   max_prime_public_client official-login-status");
        println!();
        return Ok(());
    }

    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let url = format!("{}/api-prime-participant-status.php", base);

    let payload = serde_json::json!({
        "participant_token": cfg.participant_token,
        "client_device_id": cfg.client_device_id
    });

    let response = official_http_post_json(&url, &payload)?;

    create_private_dir(APP_STATE_DIR)?;
    write_sensitive_text(
        "app_state/last_participant_status_response.json",
        serde_json::to_string_pretty(&official_redact_secrets(&response))
            .map_err(|e| format!("Cannot serialize participant status response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write participant status response: {}", e))?;

    println!("Server status response:");
    println!("   ok: {}", official_bool_ok(&response));

    if official_bool_ok(&response) {
        official_update_identity_from_response(&mut cfg, &response);

        if let Some(pid) = response.get("participant_id").and_then(|v| v.as_str()) {
            if !pid.trim().is_empty() {
                cfg.participant_id = pid.trim().to_string();
            }
        }

        if let Some(token_id) = response.get("token_id").and_then(|v| v.as_str()) {
            if !token_id.trim().is_empty() {
                cfg.token_id = token_id.trim().to_string();
            }
        }

        if let Some(token_status) = response.get("token_status").and_then(|v| v.as_str()) {
            if token_status.eq_ignore_ascii_case("ACTIVE") {
                cfg.participant_token_status = "registered".to_string();
                cfg.max_login_status = "connected".to_string();
            }
        }

        cfg.note = "Official participant status refreshed from server. MAX ID is the official public identity.".to_string();
        save_official_client_config(&cfg)?;

        println!("   participant_id: {}", cfg.participant_id);
        println!(
            "   token_status: {}",
            response
                .get("token_status")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
        );
        println!(
            "   device_status: {}",
            response
                .get("device_status")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
        );
        official_print_identity_from_config(&cfg);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&official_redact_secrets(&response))
                .unwrap_or_else(|_| "{}".to_string())
        );
        return Err("Participant status check failed.".to_string());
    }

    println!();
    println!("Response saved with secrets redacted:");
    println!("   app_state/last_participant_status_response.json");
    println!();

    Ok(())
}

fn official_participant_status_mode() -> Result<(), String> {
    official_get_work_mode()
}

fn official_set_nickname_mode(nickname: &str) -> Result<(), String> {
    let mut cfg = load_or_create_official_client_config()?;

    if cfg.participant_token.trim().is_empty() {
        return Err("Cannot set nickname: participant token is missing. Run official-login-start and official-login-status first.".to_string());
    }

    let nickname = nickname.trim();
    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let url = format!("{}/api-prime-participant-nickname.php", base);

    let payload = serde_json::json!({
        "participant_token": cfg.participant_token,
        "client_device_id": cfg.client_device_id,
        "public_nickname": nickname
    });

    let response = official_http_post_json(&url, &payload)?;

    create_private_dir(APP_STATE_DIR)?;
    write_sensitive_text(
        "app_state/last_participant_nickname_response.json",
        serde_json::to_string_pretty(&official_redact_secrets(&response))
            .map_err(|e| format!("Cannot serialize nickname response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write nickname response: {}", e))?;

    official_cli_banner("Official Public Nickname");

    if !official_bool_ok(&response) {
        println!("Server rejected nickname update.");
        println!(
            "{}",
            serde_json::to_string_pretty(&official_redact_secrets(&response))
                .unwrap_or_else(|_| "{}".to_string())
        );
        return Err("Nickname update failed.".to_string());
    }

    official_update_identity_from_response(&mut cfg, &response);
    cfg.note = "Official participant public nickname updated locally from server response. MAX ID remains the official identity.".to_string();
    save_official_client_config(&cfg)?;

    println!("Nickname update accepted.");
    official_print_identity_from_config(&cfg);
    println!();
    println!("Response saved:");
    println!("   app_state/last_participant_nickname_response.json");
    println!();

    Ok(())
}

fn official_logout_mode() -> Result<(), String> {
    let mut cfg = load_or_create_official_client_config()?;

    if cfg.participant_token.trim().is_empty() {
        println!();
        println!("Official Logout");
        println!("===============");
        println!();
        println!("This client is already logged out locally.");
        println!();
        return Ok(());
    }

    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let url = format!("{}/api-prime-participant-logout.php", base);

    let payload = serde_json::json!({
        "participant_token": cfg.participant_token,
        "client_device_id": cfg.client_device_id
    });

    let response = official_http_post_json(&url, &payload)?;

    create_private_dir(APP_STATE_DIR)?;
    write_sensitive_text(
        "app_state/last_participant_logout_response.json",
        serde_json::to_string_pretty(&official_redact_secrets(&response))
            .map_err(|e| format!("Cannot serialize logout response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write logout response: {}", e))?;

    official_cli_banner("Official Logout");

    if !official_bool_ok(&response) {
        println!("Server did not confirm logout. Local token was kept for debugging.");
        println!(
            "{}",
            serde_json::to_string_pretty(&official_redact_secrets(&response))
                .unwrap_or_else(|_| "{}".to_string())
        );
        return Err("Logout failed: server did not confirm token revocation.".to_string());
    }

    let old_device_id = cfg.client_device_id.clone();
    let old_api_base = cfg.official_api_base.clone();
    let created_at = cfg.created_at_unix;

    cfg = OfficialClientConfig {
        mode: "official-participant-v1".to_string(),
        official_api_base: old_api_base,
        client_device_id: old_device_id,
        participant_id: "".to_string(),
        participant_token: "".to_string(),
        participant_token_status: "logged_out".to_string(),
        token_id: "".to_string(),
        max_id: "".to_string(),
        max_id_hash: "".to_string(),
        public_nickname: "".to_string(),
        public_display_name: "".to_string(),
        max_login_status: "not_connected".to_string(),
        registration_id: "".to_string(),
        registration_status: "not_started".to_string(),
        login_session_id: "".to_string(),
        login_session_status: "not_started".to_string(),
        login_started_at_unix: 0,
        login_expires_at_unix: 0,
        qr_text: "".to_string(),
        deeplink: "".to_string(),
        callback_url: "".to_string(),
        created_at_unix: created_at,
        updated_at_unix: now_unix(),
        note: "Logged out from MAX Prime Challenge. This computer can register again with the same MAX ID or another MAX ID.".to_string(),
    };

    save_official_client_config(&cfg)?;

    println!("Server confirmed logout.");
    println!("Local participant token removed.");
    println!("Client device ID preserved:");
    println!("   {}", cfg.client_device_id);
    println!();
    println!("Response saved:");
    println!("   app_state/last_participant_logout_response.json");
    println!();

    Ok(())
}

fn official_submit_result_mode() -> Result<(), String> {
    println!();
    println!("Official Submit Result");
    println!("======================");
    println!();
    println!("This public client submits results through:");
    println!("   max_prime_public_client official-run-once <challenge_id>");
    println!();
    println!("That command performs the safe sequence:");
    println!("   get-work -> compute assigned work -> submit result");
    println!();
    println!("Manual submit is intentionally not exposed as a separate public command yet.");
    println!("This avoids submitting stale or edited payloads by mistake.");
    println!();

    Ok(())
}

fn official_url_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn official_json_get_string(value: &serde_json::Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .ok_or_else(|| format!("Missing or invalid string field: {}", key))
}

fn official_json_get_bool(value: &serde_json::Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("Missing or invalid bool field: {}", key))
}

fn official_json_get_usize(value: &serde_json::Value, key: &str) -> Result<usize, String> {
    value
        .get(key)
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .ok_or_else(|| format!("Missing or invalid integer field: {}", key))
}

fn official_find_string_deep(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(key).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            for v in map.values() {
                if let Some(found) = official_find_string_deep(v, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for v in items {
                if let Some(found) = official_find_string_deep(v, key) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn official_find_u64_deep(value: &serde_json::Value, key: &str) -> Option<u64> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(key).and_then(|v| v.as_u64()) {
                return Some(v);
            }
            for v in map.values() {
                if let Some(found) = official_find_u64_deep(v, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for v in items {
                if let Some(found) = official_find_u64_deep(v, key) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn official_bool_ok(value: &serde_json::Value) -> bool {
    value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
}

fn official_redact_secrets(value: &serde_json::Value) -> serde_json::Value {
    let mut v = value.clone();

    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let lk = k.to_lowercase();
                    if lk == "token"
                        || lk.contains("token")
                        || lk.contains("secret")
                        || lk.contains("password")
                        || lk.contains("authorization")
                        || lk.contains("cookie")
                    {
                        *val = serde_json::Value::String("REDACTED_LOCAL_SECRET".to_string());
                    } else {
                        walk(val);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item);
                }
            }
            _ => {}
        }
    }

    walk(&mut v);
    v
}

fn official_parse_ubig(label: &str, value: &str) -> Result<UBig, String> {
    UBig::from_str(value).map_err(|e| format!("Cannot parse {} as integer: {}", label, e))
}

fn participant_authorization(participant_token: &str) -> String {
    format!("Bearer {participant_token}")
}

fn official_http_get_json(url: &str, participant_token: &str) -> Result<serde_json::Value, String> {
    match ureq::get(url)
        .set(
            "Authorization",
            &participant_authorization(participant_token),
        )
        .call()
    {
        Ok(response) => response
            .into_json::<serde_json::Value>()
            .map_err(|e| format!("Cannot parse GET JSON response: {}", e)),
        Err(ureq::Error::Status(code, response)) => {
            let parsed = response.into_json::<serde_json::Value>().ok();
            if let Some(v) = parsed {
                Ok(v)
            } else {
                Err(format!("GET HTTP error {}", code))
            }
        }
        Err(e) => Err(format!("GET request failed: {}", e)),
    }
}

fn official_http_post_json(
    url: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    match ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(payload.clone())
    {
        Ok(response) => response
            .into_json::<serde_json::Value>()
            .map_err(|e| format!("Cannot parse POST JSON response: {}", e)),
        Err(ureq::Error::Status(code, response)) => {
            let parsed = response.into_json::<serde_json::Value>().ok();
            if let Some(v) = parsed {
                Ok(v)
            } else {
                Err(format!("POST HTTP error {}", code))
            }
        }
        Err(e) => Err(format!("POST request failed: {}", e)),
    }
}

struct OfficialAssignmentHeartbeat {
    stop_requested: Arc<AtomicBool>,
    fatal_lease_error: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl OfficialAssignmentHeartbeat {
    fn fatal_lease_error(&self) -> bool {
        self.fatal_lease_error.load(Ordering::SeqCst)
    }

    fn stop(mut self) -> bool {
        self.stop_requested.store(true, Ordering::SeqCst);

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }

        self.fatal_lease_error.load(Ordering::SeqCst)
    }
}

impl Drop for OfficialAssignmentHeartbeat {
    fn drop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn official_heartbeat_url(heartbeat_endpoint: &str, api_base: &str) -> Result<String, String> {
    let heartbeat_endpoint = heartbeat_endpoint.trim();

    match Url::parse(heartbeat_endpoint) {
        Ok(heartbeat_url) => {
            if heartbeat_url.scheme() != "https" {
                return Err(
                    "Cannot start heartbeat: heartbeat endpoint must use HTTPS.".to_string()
                );
            }

            let api_base_url = Url::parse(api_base).map_err(|_| {
                "Cannot start heartbeat: invalid API base for absolute heartbeat endpoint."
                    .to_string()
            })?;

            if heartbeat_url.origin() != api_base_url.origin() {
                return Err(
                    "Cannot start heartbeat: heartbeat endpoint must use the API origin."
                        .to_string(),
                );
            }

            Ok(heartbeat_endpoint.to_string())
        }
        Err(_) => {
            let has_scheme = heartbeat_endpoint
                .split_once(':')
                .map(|(scheme, _)| {
                    !scheme.is_empty()
                        && scheme.chars().enumerate().all(|(index, c)| {
                            c.is_ascii_alphabetic()
                                || (index > 0 && matches!(c, '+' | '-' | '.' | '0'..='9'))
                        })
                })
                .unwrap_or(false);

            if heartbeat_endpoint.starts_with("//") || has_scheme {
                return Err("Cannot start heartbeat: invalid heartbeat endpoint.".to_string());
            }

            Ok(format!(
                "{}/{}",
                api_base.trim_end_matches('/'),
                heartbeat_endpoint.trim_start_matches('/')
            ))
        }
    }
}

fn official_start_assignment_heartbeat(
    get_response: &serde_json::Value,
    cfg: &OfficialClientConfig,
    api_base: &str,
) -> Result<OfficialAssignmentHeartbeat, String> {
    let assignment = get_response
        .get("assignment")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Cannot start heartbeat: missing assignment object.".to_string())?;

    let heartbeat_endpoint = assignment
        .get("heartbeat_endpoint")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("api-prime-assignment-heartbeat.php");

    // Validate the server-provided destination before reading or cloning either token.
    let heartbeat_url = official_heartbeat_url(heartbeat_endpoint, api_base)?;

    let assignment_id = assignment
        .get("assignment_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Cannot start heartbeat: missing assignment_id.".to_string())?
        .to_string();

    let assignment_token = assignment
        .get("assignment_token")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Cannot start heartbeat: missing assignment_token.".to_string())?
        .to_string();

    let heartbeat_interval_seconds = assignment
        .get("heartbeat_interval_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(900)
        .max(60);

    let heartbeat_jitter_seconds = assignment
        .get("heartbeat_jitter_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(120)
        .min(heartbeat_interval_seconds.saturating_sub(30));

    let challenge_id = get_response
        .get("challenge_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "Cannot start heartbeat: missing challenge_id.".to_string())?
        .to_string();

    let participant_token = cfg.participant_token.clone();
    let client_device_id = cfg.client_device_id.clone();

    let stop_requested = Arc::new(AtomicBool::new(false));
    let fatal_lease_error = Arc::new(AtomicBool::new(false));

    let thread_stop_requested = Arc::clone(&stop_requested);
    let thread_fatal_lease_error = Arc::clone(&fatal_lease_error);

    let handle = thread::spawn(move || {
        let mut rng = rand::thread_rng();

        loop {
            let jitter: i64 = if heartbeat_jitter_seconds > 0 {
                rng.gen_range(
                    -(heartbeat_jitter_seconds as i64)..=(heartbeat_jitter_seconds as i64),
                )
            } else {
                0
            };

            let wait_seconds = (heartbeat_interval_seconds as i64 + jitter).max(30) as u64;

            for _ in 0..wait_seconds {
                if thread_stop_requested.load(Ordering::SeqCst) {
                    return;
                }

                thread::sleep(Duration::from_secs(1));
            }

            if thread_stop_requested.load(Ordering::SeqCst) {
                return;
            }

            let payload = serde_json::json!({
                "challenge_id": challenge_id,
                "assignment_id": assignment_id,
                "assignment_token": assignment_token,
                "participant_token": participant_token,
                "client_device_id": client_device_id
            });

            let retry_delays_seconds = [0_u64, 2, 5, 15];
            let mut renewed = false;

            for (attempt_index, delay_seconds) in retry_delays_seconds.iter().enumerate() {
                if thread_stop_requested.load(Ordering::SeqCst) {
                    return;
                }

                if *delay_seconds > 0 {
                    thread::sleep(Duration::from_secs(*delay_seconds));
                }

                match official_http_post_json(&heartbeat_url, &payload) {
                    Ok(response) => {
                        if official_bool_ok(&response) {
                            renewed = true;
                            break;
                        }

                        let error_code = response
                            .get("error_code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        if matches!(
                            error_code,
                            "ASSIGNMENT_EXPIRED"
                                | "ASSIGNMENT_SUPERSEDED"
                                | "ASSIGNMENT_NOT_ACTIVE"
                                | "ASSIGNMENT_NOT_FOUND"
                                | "ASSIGNMENT_TOKEN_INVALID"
                                | "ASSIGNMENT_PARTICIPANT_MISMATCH"
                                | "ASSIGNMENT_DEVICE_MISMATCH"
                        ) {
                            eprintln!(
                                "Heartbeat stopped: server rejected the active lease ({error_code})."
                            );

                            thread_fatal_lease_error.store(true, Ordering::SeqCst);

                            return;
                        }

                        eprintln!(
                            "Heartbeat attempt {}/{} rejected temporarily: {}",
                            attempt_index + 1,
                            retry_delays_seconds.len(),
                            if error_code.is_empty() {
                                "UNKNOWN_SERVER_ERROR"
                            } else {
                                error_code
                            }
                        );
                    }

                    Err(error) => {
                        eprintln!(
                            "Heartbeat network attempt {}/{} failed: {}",
                            attempt_index + 1,
                            retry_delays_seconds.len(),
                            error
                        );
                    }
                }
            }

            if !renewed {
                eprintln!(
                    "Warning: heartbeat was not renewed after retries. The client will retry at the next interval while the lease remains valid."
                );
            }
        }
    });

    Ok(OfficialAssignmentHeartbeat {
        stop_requested,
        fatal_lease_error,
        handle: Some(handle),
    })
}

#[allow(dead_code)]
fn official_make_client_id(challenge_id: &str) -> String {
    let seed = format!(
        "max-prime-public-client:{}:{}:{}",
        challenge_id,
        now_unix(),
        std::process::id()
    );
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);
    format!("mpc-public-{}", &hex[..24])
}

#[cfg(test)]
fn official_compute_work_unit_payload_legacy(
    get_response: &serde_json::Value,
    cfg: &OfficialClientConfig,
) -> Result<serde_json::Value, String> {
    let assignment = get_response
        .get("assignment")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Missing assignment object in get-work response.".to_string())?;

    let work_unit = get_response
        .get("work_unit")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Missing work_unit object in get-work response.".to_string())?;

    let assignment_id = assignment
        .get("assignment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing assignment.assignment_id.".to_string())?
        .to_string();

    let assignment_token = assignment
        .get("assignment_token")
        .or_else(|| get_response.get("assignment_token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "Missing assignment_token in get-work response. Authenticated submit cannot continue."
                .to_string()
        })?
        .to_string();

    let client_id = cfg.client_device_id.clone();

    let challenge_id = work_unit
        .get("challenge_id")
        .or_else(|| work_unit.get("campaign_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing work_unit.challenge_id/campaign_id.".to_string())?
        .to_string();

    let campaign_id = work_unit
        .get("campaign_id")
        .or_else(|| work_unit.get("challenge_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing work_unit.campaign_id/challenge_id.".to_string())?
        .to_string();

    let work_unit_id =
        official_json_get_string(get_response.get("work_unit").unwrap(), "work_unit_id")?;
    let work_unit_index =
        official_json_get_usize(get_response.get("work_unit").unwrap(), "work_unit_index")?;
    let n0_s = official_json_get_string(get_response.get("work_unit").unwrap(), "n0")?;
    let step_s = official_json_get_string(get_response.get("work_unit").unwrap(), "step")?;
    let start_i = official_json_get_usize(get_response.get("work_unit").unwrap(), "start_i")?;
    let iterations = official_json_get_usize(get_response.get("work_unit").unwrap(), "iterations")?;
    let test_n = official_json_get_bool(get_response.get("work_unit").unwrap(), "test_n")?;
    let test_d = official_json_get_bool(get_response.get("work_unit").unwrap(), "test_d")?;

    if !test_n && !test_d {
        return Err("Official work unit has both test_n=false and test_d=false.".to_string());
    }

    let filter_value = get_response
        .get("work_unit")
        .and_then(|v| v.get("filter"))
        .ok_or_else(|| "Missing work_unit.filter.".to_string())?;

    let filter_enabled = official_json_get_bool(filter_value, "enabled")?;
    let modulus_m_s = official_json_get_string(filter_value, "modulus_m")?;
    let remainder_r_s = official_json_get_string(filter_value, "remainder_r")?;

    let n0 = official_parse_ubig("n0", &n0_s)?;
    let step = official_parse_ubig("step", &step_s)?;
    let modulus_m = official_parse_ubig("filter.modulus_m", &modulus_m_s)?;
    let remainder_r = official_parse_ubig("filter.remainder_r", &remainder_r_s)?;

    let t0 = std::time::Instant::now();

    let mut hits: Vec<serde_json::Value> = Vec::new();
    let mut n_primes_found: usize = 0;
    let mut d_primes_found: usize = 0;
    let mut n_expected_sum = 0.0_f64;
    let mut d_expected_sum = 0.0_f64;
    let mut n_digit_counts: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    let mut d_digit_counts: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();

    for offset in 0..iterations {
        let i = start_i + offset;
        let n_raw = &n0 + (&step * UBig::from(i as u64));
        let n_effective = if filter_enabled {
            &remainder_r + (&modulus_m * &n_raw)
        } else {
            n_raw.clone()
        };

        if test_n {
            let candidate = n_candidate_from_n(&n_effective);
            let digits = decimal_digits(&candidate);
            n_expected_sum += expected_prime_probability_from_digits(digits);
            *n_digit_counts.entry(digits).or_insert(0) += 1;

            if is_probable_prime(&candidate) {
                n_primes_found += 1;
                let sha = sha256_decimal(&candidate);
                hits.push(serde_json::json!({
                    "candidate_type": "N",
                    "i": i,
                    "n_raw": n_raw.to_string(),
                    "n_effective": n_effective.to_string(),
                    "candidate": candidate.to_string(),
                    "digits": digits,
                    "sha256": sha
                }));
            }
        }

        if test_d {
            let candidate = d_candidate_from_n(&n_effective);
            let digits = decimal_digits(&candidate);
            d_expected_sum += expected_prime_probability_from_digits(digits);
            *d_digit_counts.entry(digits).or_insert(0) += 1;

            if is_probable_prime(&candidate) {
                d_primes_found += 1;
                let sha = sha256_decimal(&candidate);
                hits.push(serde_json::json!({
                    "candidate_type": "d",
                    "i": i,
                    "n_raw": n_raw.to_string(),
                    "n_effective": n_effective.to_string(),
                    "candidate": candidate.to_string(),
                    "digits": digits,
                    "sha256": sha
                }));
            }
        }
    }

    let elapsed_s = t0.elapsed().as_secs_f64();
    let iterations_done = iterations;
    let total_primes = n_primes_found + d_primes_found;

    let n_expected_pct = if iterations_done > 0 {
        100.0 * n_expected_sum / iterations_done as f64
    } else {
        0.0
    };
    let d_expected_pct = if iterations_done > 0 {
        100.0 * d_expected_sum / iterations_done as f64
    } else {
        0.0
    };
    let combined_expected_sum = n_expected_sum + d_expected_sum;
    let combined_expected_pct = if iterations_done > 0 {
        100.0 * combined_expected_sum / iterations_done as f64
    } else {
        0.0
    };

    let n_observed_pct = if iterations_done > 0 {
        100.0 * n_primes_found as f64 / iterations_done as f64
    } else {
        0.0
    };
    let d_observed_pct = if iterations_done > 0 {
        100.0 * d_primes_found as f64 / iterations_done as f64
    } else {
        0.0
    };
    let combined_observed_pct = if iterations_done > 0 {
        100.0 * total_primes as f64 / iterations_done as f64
    } else {
        0.0
    };

    let n_enrichment = if n_expected_sum > 0.0 {
        n_primes_found as f64 / n_expected_sum
    } else {
        0.0
    };
    let d_enrichment = if d_expected_sum > 0.0 {
        d_primes_found as f64 / d_expected_sum
    } else {
        0.0
    };
    let combined_enrichment = if combined_expected_sum > 0.0 {
        total_primes as f64 / combined_expected_sum
    } else {
        0.0
    };

    let n_candidates_by_digits: Vec<serde_json::Value> = n_digit_counts
        .into_iter()
        .map(|(digits, count)| serde_json::json!({ "digits": digits, "count": count }))
        .collect();

    let d_candidates_by_digits: Vec<serde_json::Value> = d_digit_counts
        .into_iter()
        .map(|(digits, count)| serde_json::json!({ "digits": digits, "count": count }))
        .collect();

    let stats = serde_json::json!({
        "n_primes_found": n_primes_found,
        "d_primes_found": d_primes_found,
        "n_expected_pct": n_expected_pct,
        "d_expected_pct": d_expected_pct,
        "combined_expected_pct": combined_expected_pct,
        "n_observed_pct": n_observed_pct,
        "d_observed_pct": d_observed_pct,
        "combined_observed_pct": combined_observed_pct,
        "n_enrichment": n_enrichment,
        "d_enrichment": d_enrichment,
        "combined_enrichment": combined_enrichment,
        "n_candidates_by_digits": n_candidates_by_digits,
        "d_candidates_by_digits": d_candidates_by_digits
    });

    let result = serde_json::json!({
        "ok": true,
        "campaign_id": campaign_id,
        "work_unit_id": work_unit_id,
        "iterations_done": iterations_done,
        "elapsed_s": elapsed_s,
        "hits": hits,
        "stats": stats
    });

    let payload = serde_json::json!({
        "ok": true,
        "challenge_id": challenge_id,
        "work_unit_id": work_unit_id,
        "work_unit_index": work_unit_index.to_string(),
        "assignment_id": assignment_id,
        "assignment_token": assignment_token,
        "client_id": client_id,
        "client_device_id": cfg.client_device_id,
        "participant_id": cfg.participant_id,
        "participant_token": cfg.participant_token,
        "client_engine": {
            "name": "max_prime_public_client",
            "mode": "official-run-once",
            "math_engine": "dashu-int",
            "bigint_note": "Public client uses dashu-int for official work computation.",
            "probable_prime_note": "Miller-Rabin probable-prime test, not final public certification."
        },
        "iterations_done": iterations_done,
        "elapsed_s": elapsed_s,
        "hits": result.get("hits").cloned().unwrap_or_else(|| serde_json::json!([])),
        "stats": result.get("stats").cloned().unwrap_or_else(|| serde_json::json!({})),
        "result": result,
        "result_json": result
    });

    Ok(payload)
}

fn official_compute_work_unit_payload_optimized(
    get_response: &serde_json::Value,
    cfg: &OfficialClientConfig,
) -> Result<serde_json::Value, String> {
    let assignment = get_response
        .get("assignment")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Missing assignment object in get-work response.".to_string())?;

    let work_unit = get_response
        .get("work_unit")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Missing work_unit object in get-work response.".to_string())?;

    let assignment_id = assignment
        .get("assignment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing assignment.assignment_id.".to_string())?
        .to_string();

    let assignment_token = assignment
        .get("assignment_token")
        .or_else(|| get_response.get("assignment_token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "Missing assignment_token in get-work response. Authenticated submit cannot continue."
                .to_string()
        })?
        .to_string();

    let client_id = cfg.client_device_id.clone();

    let challenge_id = work_unit
        .get("challenge_id")
        .or_else(|| work_unit.get("campaign_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing work_unit.challenge_id/campaign_id.".to_string())?
        .to_string();

    let campaign_id = work_unit
        .get("campaign_id")
        .or_else(|| work_unit.get("challenge_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing work_unit.campaign_id/challenge_id.".to_string())?
        .to_string();

    let work_unit_id =
        official_json_get_string(get_response.get("work_unit").unwrap(), "work_unit_id")?;
    let work_unit_index =
        official_json_get_usize(get_response.get("work_unit").unwrap(), "work_unit_index")?;
    let n0_s = official_json_get_string(get_response.get("work_unit").unwrap(), "n0")?;
    let step_s = official_json_get_string(get_response.get("work_unit").unwrap(), "step")?;
    let start_i = official_json_get_usize(get_response.get("work_unit").unwrap(), "start_i")?;
    let iterations = official_json_get_usize(get_response.get("work_unit").unwrap(), "iterations")?;
    let test_n = official_json_get_bool(get_response.get("work_unit").unwrap(), "test_n")?;
    let test_d = official_json_get_bool(get_response.get("work_unit").unwrap(), "test_d")?;

    if !test_n && !test_d {
        return Err("Official work unit has both test_n=false and test_d=false.".to_string());
    }

    let filter_value = get_response
        .get("work_unit")
        .and_then(|v| v.get("filter"))
        .ok_or_else(|| "Missing work_unit.filter.".to_string())?;

    let filter_enabled = official_json_get_bool(filter_value, "enabled")?;
    let modulus_m_s = official_json_get_string(filter_value, "modulus_m")?;
    let remainder_r_s = official_json_get_string(filter_value, "remainder_r")?;

    let n0 = official_parse_ubig("n0", &n0_s)?;
    let step = official_parse_ubig("step", &step_s)?;
    let modulus_m = official_parse_ubig("filter.modulus_m", &modulus_m_s)?;
    let remainder_r = official_parse_ubig("filter.remainder_r", &remainder_r_s)?;

    let t0 = std::time::Instant::now();

    let mut hits: Vec<serde_json::Value> = Vec::new();
    let mut n_primes_found: usize = 0;
    let mut d_primes_found: usize = 0;
    let mut n_expected_sum = 0.0_f64;
    let mut d_expected_sum = 0.0_f64;
    let mut n_digit_counts: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    let mut d_digit_counts: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();

    // Motore privato sperimentale.
    // CRT arbitrario: non si presume SAFECRT50.
    // Per pacchetti piccoli evitiamo il setup del crivello.

    let first_raw = &n0 + &step * UBig::from(start_i as u64);

    let effective_start = if filter_enabled {
        &remainder_r + &modulus_m * &first_raw
    } else {
        first_raw
    };

    let effective_step = if filter_enabled {
        &modulus_m * &step
    } else {
        step.clone()
    };

    let use_sieve = test_n
        && iterations >= 25
        && iterations <= 200_000
        && decimal_digits(&n_candidate_from_n(&effective_start)) >= 100;

    let (n_mask, mut n_cursor) = if use_sieve {
        let primes = crtcomp_primes_up_to(if iterations < 500 { 500_000 } else { 5_000_000 });

        let schedule = crtcomp_compile_schedule(&primes, &effective_step, false);

        let mut state = crtcomp_initialize_persistent_state(&effective_start, &schedule);

        let mask = crtcomp_mark_persistent(iterations, &schedule, &mut state);

        (
            Some(mask),
            Some(CrtCompCandidateCursor::new(
                &effective_start,
                &effective_step,
            )),
        )
    } else {
        (None, None)
    };

    for offset in 0..iterations {
        let i = start_i + offset;
        let n_raw = &n0 + (&step * UBig::from(i as u64));
        let n_effective = if filter_enabled {
            &remainder_r + (&modulus_m * &n_raw)
        } else {
            n_raw.clone()
        };

        if test_n {
            let rejected = n_mask.as_ref().map(|mask| mask[offset]).unwrap_or(false);

            // Manteniamo le statistiche originali anche
            // quando il crivello scarta un candidato.
            let candidate = if rejected {
                n_candidate_from_n(&n_effective)
            } else if let Some(cursor) = n_cursor.as_mut() {
                cursor.at(offset).clone()
            } else {
                n_candidate_from_n(&n_effective)
            };
            let digits = decimal_digits(&candidate);
            n_expected_sum += expected_prime_probability_from_digits(digits);
            *n_digit_counts.entry(digits).or_insert(0) += 1;

            if !rejected && is_probable_prime_ring_max(&candidate) {
                n_primes_found += 1;
                let sha = sha256_decimal(&candidate);
                hits.push(serde_json::json!({
                    "candidate_type": "N",
                    "i": i,
                    "n_raw": n_raw.to_string(),
                    "n_effective": n_effective.to_string(),
                    "candidate": candidate.to_string(),
                    "digits": digits,
                    "sha256": sha
                }));
            }
        }

        if test_d {
            let candidate = d_candidate_from_n(&n_effective);
            let digits = decimal_digits(&candidate);
            d_expected_sum += expected_prime_probability_from_digits(digits);
            *d_digit_counts.entry(digits).or_insert(0) += 1;

            if is_probable_prime_ring_general(&candidate) {
                d_primes_found += 1;
                let sha = sha256_decimal(&candidate);
                hits.push(serde_json::json!({
                    "candidate_type": "d",
                    "i": i,
                    "n_raw": n_raw.to_string(),
                    "n_effective": n_effective.to_string(),
                    "candidate": candidate.to_string(),
                    "digits": digits,
                    "sha256": sha
                }));
            }
        }
    }

    let elapsed_s = t0.elapsed().as_secs_f64();
    let iterations_done = iterations;
    let total_primes = n_primes_found + d_primes_found;

    let n_expected_pct = if iterations_done > 0 {
        100.0 * n_expected_sum / iterations_done as f64
    } else {
        0.0
    };
    let d_expected_pct = if iterations_done > 0 {
        100.0 * d_expected_sum / iterations_done as f64
    } else {
        0.0
    };
    let combined_expected_sum = n_expected_sum + d_expected_sum;
    let combined_expected_pct = if iterations_done > 0 {
        100.0 * combined_expected_sum / iterations_done as f64
    } else {
        0.0
    };

    let n_observed_pct = if iterations_done > 0 {
        100.0 * n_primes_found as f64 / iterations_done as f64
    } else {
        0.0
    };
    let d_observed_pct = if iterations_done > 0 {
        100.0 * d_primes_found as f64 / iterations_done as f64
    } else {
        0.0
    };
    let combined_observed_pct = if iterations_done > 0 {
        100.0 * total_primes as f64 / iterations_done as f64
    } else {
        0.0
    };

    let n_enrichment = if n_expected_sum > 0.0 {
        n_primes_found as f64 / n_expected_sum
    } else {
        0.0
    };
    let d_enrichment = if d_expected_sum > 0.0 {
        d_primes_found as f64 / d_expected_sum
    } else {
        0.0
    };
    let combined_enrichment = if combined_expected_sum > 0.0 {
        total_primes as f64 / combined_expected_sum
    } else {
        0.0
    };

    let n_candidates_by_digits: Vec<serde_json::Value> = n_digit_counts
        .into_iter()
        .map(|(digits, count)| serde_json::json!({ "digits": digits, "count": count }))
        .collect();

    let d_candidates_by_digits: Vec<serde_json::Value> = d_digit_counts
        .into_iter()
        .map(|(digits, count)| serde_json::json!({ "digits": digits, "count": count }))
        .collect();

    let stats = serde_json::json!({
        "n_primes_found": n_primes_found,
        "d_primes_found": d_primes_found,
        "n_expected_pct": n_expected_pct,
        "d_expected_pct": d_expected_pct,
        "combined_expected_pct": combined_expected_pct,
        "n_observed_pct": n_observed_pct,
        "d_observed_pct": d_observed_pct,
        "combined_observed_pct": combined_observed_pct,
        "n_enrichment": n_enrichment,
        "d_enrichment": d_enrichment,
        "combined_enrichment": combined_enrichment,
        "n_candidates_by_digits": n_candidates_by_digits,
        "d_candidates_by_digits": d_candidates_by_digits
    });

    let result = serde_json::json!({
        "ok": true,
        "campaign_id": campaign_id,
        "work_unit_id": work_unit_id,
        "iterations_done": iterations_done,
        "elapsed_s": elapsed_s,
        "hits": hits,
        "stats": stats
    });

    let payload = serde_json::json!({
        "ok": true,
        "challenge_id": challenge_id,
        "work_unit_id": work_unit_id,
        "work_unit_index": work_unit_index.to_string(),
        "assignment_id": assignment_id,
        "assignment_token": assignment_token,
        "client_id": client_id,
        "client_device_id": cfg.client_device_id,
        "participant_id": cfg.participant_id,
        "participant_token": cfg.participant_token,
        "client_engine": {
            "name": "max_prime_public_client",
            "mode": "official-run-once",
            "math_engine": "dashu-int",
            "bigint_note": "Public client uses dashu-int for official work computation.",
            "probable_prime_note": "Miller-Rabin probable-prime test, not final public certification."
        },
        "iterations_done": iterations_done,
        "elapsed_s": elapsed_s,
        "hits": result.get("hits").cloned().unwrap_or_else(|| serde_json::json!([])),
        "stats": result.get("stats").cloned().unwrap_or_else(|| serde_json::json!({})),
        "result": result,
        "result_json": result
    });

    Ok(payload)
}

fn official_compute_work_unit_payload(
    get_response: &serde_json::Value,
    cfg: &OfficialClientConfig,
) -> Result<serde_json::Value, String> {
    official_compute_work_unit_payload_optimized(get_response, cfg)
}

fn official_hit_summary_from_payload(
    payload: &serde_json::Value,
) -> Option<(String, String, String, String)> {
    let hits = payload.get("hits")?.as_array()?;
    let hit = hits.first()?;

    let candidate_type = hit
        .get("candidate_type")
        .and_then(|v| v.as_str())
        .unwrap_or("N")
        .to_string();

    let digits = hit
        .get("digits")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    let sha256 = hit
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();

    let i_value = hit
        .get("i")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    Some((candidate_type, digits, sha256, i_value))
}

fn save_last_official_outcome(outcome: &serde_json::Value) -> Result<(), String> {
    create_private_dir(APP_STATE_DIR)?;

    write_sensitive_text(
        "app_state/last_official_outcome.json",
        serde_json::to_string_pretty(&official_redact_secrets(outcome))
            .map_err(|e| format!("Cannot serialize last official outcome: {}", e))?,
    )
    .map_err(|e| format!("Cannot write last official outcome: {}", e))
}

fn print_public_outcome_message(
    challenge_id: &str,
    work_unit_id: Option<&str>,
    payload: Option<&serde_json::Value>,
    submit_response: Option<&serde_json::Value>,
    get_response: Option<&serde_json::Value>,
) {
    let official_url = "https://www.max-russo.com";

    let accepted = submit_response
        .and_then(|v| v.get("accepted"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let has_hit = submit_response
        .and_then(|v| v.get("has_hit"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let challenge_completed = submit_response
        .and_then(|v| v.get("challenge_completed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let server_mode = submit_response
        .and_then(|v| v.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let server_message = submit_response
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            get_response
                .and_then(|v| v.get("message"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("");

    let error_code = get_response
        .and_then(|v| v.get("error_code"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let hit_summary = payload.and_then(official_hit_summary_from_payload);

    let kind = if has_hit || server_mode == "SUBMIT_HIT_RESULT" {
        "winner"
    } else if error_code == "CHALLENGE_COMPLETED" {
        "completed"
    } else if error_code == "CHALLENGE_NOT_ACTIVE" {
        "not_active"
    } else if !accepted
        && server_message
            .to_lowercase()
            .contains("paused pending verification")
    {
        "late_after_hit"
    } else if challenge_completed {
        "completed"
    } else if !accepted {
        "rejected"
    } else {
        "normal"
    };

    println!();
    println!("Official outcome");
    println!("================");

    match kind {
        "winner" => {
            println!("Congratulations — your computer found a MAX Prime hit!");
            println!();
            println!("The official server accepted and auto-verified your result.");
            println!("This result completed the current MAX Prime Challenge.");
            println!();

            println!("Challenge:");
            println!("   {}", challenge_id);

            if let Some(wu) = work_unit_id {
                println!("Winning work unit:");
                println!("   {}", wu);
            }

            if let Some((candidate_type, digits, sha256, i_value)) = hit_summary.clone() {
                println!("Candidate type:");
                println!("   {}", candidate_type);
                println!("Index i:");
                println!("   {}", i_value);
                println!("Digits:");
                println!("   {}", digits);
                println!("SHA-256:");
                println!("   {}", sha256);
            }

            println!();
            println!(
                "Thank you for your contribution. You may now join the next public Challenge."
            );
            println!("Optional future feature: submit a name or nickname for the official contributors list.");
            println!("Official results will be published on:");
            println!("   {}", official_url);
        }

        "completed" | "not_active" => {
            println!("This Challenge has been completed or is no longer active.");
            println!();
            println!("Another participant may have found a valid MAX Prime hit.");
            println!("Thank you for contributing compute power to the MAX Prime Challenge.");
            println!("Your processed packages helped advance the search.");
            println!();
            println!("Please check the official MAX Prime Challenge page for the final result:");
            println!("   {}", official_url);
            println!();
            println!("You can join the next public Challenge when available.");
        }

        "late_after_hit" => {
            println!("Your package was computed successfully, but it was not accepted.");
            println!();
            println!("This can happen in a parallel Challenge when another participant finds");
            println!("a valid hit while your computer is still finishing its current package.");
            println!("Once the server auto-verifies a hit, the Challenge is closed.");
            println!();
            println!("Thank you — your client behaved correctly.");
            println!("Please check the official MAX Prime Challenge page for the final result:");
            println!("   {}", official_url);
        }

        "rejected" => {
            println!("Your package was computed, but the official server did not accept it.");
            println!();

            if !server_message.is_empty() {
                println!("Server message:");
                println!("   {}", server_message);
                println!();
            }

            println!("This package is not counted as a completed contribution.");
            println!("The client will not report it as successfully submitted.");
        }

        _ => {
            println!("Package submitted successfully.");
            println!("No hit was found in this package.");
            println!("The client may continue with the next official package.");
            println!();
            println!("Official Challenge page:");
            println!("   {}", official_url);
        }
    }

    let outcome = serde_json::json!({
        "ok": true,
        "challenge_id": challenge_id,
        "work_unit_id": work_unit_id.unwrap_or(""),
        "outcome_kind": kind,
        "accepted": accepted,
        "has_hit": has_hit,
        "challenge_completed": challenge_completed,
        "server_mode": server_mode,
        "server_message": server_message,
        "error_code": error_code,
        "official_url": official_url,
        "hit": hit_summary.map(|(candidate_type, digits, sha256, i_value)| serde_json::json!({
            "candidate_type": candidate_type,
            "digits": digits,
            "sha256": sha256,
            "i": i_value
        })),
        "public_message": match kind {
            "winner" => "Congratulations — your computer found a MAX Prime hit. Check the official website for publication details.",
            "completed" | "not_active" => "This Challenge has been completed. Thank you for contributing. Check the official website for final results.",
            "late_after_hit" => "Your package was computed, but the Challenge was completed before it could be accepted. This is normal in parallel runs.",
            "rejected" => "The package was computed but was not accepted by the official server.",
            _ => "Package submitted successfully. No hit was found in this package."
        }
    });

    if let Err(e) = save_last_official_outcome(&outcome) {
        println!();
        println!("Warning: could not save app_state/last_official_outcome.json");
        println!("{}", e);
    } else {
        println!();
        println!("Outcome saved:");
        println!("   app_state/last_official_outcome.json");
    }

    println!();
}

fn official_run_once_mode(challenge_id: &str) -> Result<(), String> {
    if challenge_id.trim().is_empty() {
        return Err(
            "Missing challenge_id. Usage: max_prime_public_client official-run-once <challenge_id>"
                .to_string(),
        );
    }

    let cfg = load_or_create_official_client_config()?;

    if cfg.participant_token.trim().is_empty() || cfg.participant_token_status != "registered" {
        return Err(
            "Official participation requires MAX Login registration first. Run: max_prime_public_client official-login-start, approve with MAX App, then run official-login-status.".to_string()
        );
    }

    let client_id = cfg.client_device_id.clone();

    let base = cfg.official_api_base.trim_end_matches('/').to_string();
    let get_url = format!(
        "{}/api-prime-get-work.php?challenge_id={}&client_device_id={}",
        base,
        official_url_encode(challenge_id),
        official_url_encode(&cfg.client_device_id)
    );
    let submit_url = format!("{}/api-prime-submit-result.php", base);

    create_private_dir("server_client_runs")?;
    create_private_dir("server_client_runs/public")?;

    println!();
    println!("Official Run Once");
    println!("=================");
    println!();
    println!("Challenge ID: {}", challenge_id);
    println!("Client device ID: {}", client_id);
    println!("Participant auth: registered");
    println!("Engine: dashu-int");
    println!();
    println!("Step 1/4: requesting official work...");

    let mut get_response = official_http_get_json(&get_url, &cfg.participant_token)?;
    let mut get_ok = get_response
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !get_ok {
        for retry_idx in 1..=3 {
            let error_code = get_response
                .get("error_code")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if error_code != "ASSIGNMENT_CREATE_FAILED" {
                break;
            }

            let wait_ms: u64 = match retry_idx {
                1 => 250,
                2 => 500,
                _ => 1000,
            };

            println!(
                "Temporary get-work assignment error: ASSIGNMENT_CREATE_FAILED. Retry {}/3 after {} ms...",
                retry_idx,
                wait_ms
            );

            std::thread::sleep(std::time::Duration::from_millis(wait_ms));

            get_response = official_http_get_json(&get_url, &cfg.participant_token)?;
            get_ok = get_response
                .get("ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if get_ok {
                println!("Get-work retry succeeded.");
                break;
            }
        }
    }

    let safe_stamp = format!("{}-{}", challenge_id, parallel_safe_suffix());
    let get_path = format!("server_client_runs/public/{}_get_response.json", safe_stamp);
    write_sensitive_text(
        &get_path,
        serde_json::to_string_pretty(&official_redact_secrets(&get_response))
            .map_err(|e| format!("Cannot serialize get response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write get response: {}", e))?;

    if !get_ok {
        println!("Server did not assign work.");
        println!("Response saved:");
        println!("   {}", get_path);

        if let Some(error_code) = get_response.get("error_code").and_then(|v| v.as_str()) {
            println!("Error code: {}", error_code);
        }
        if let Some(message) = get_response.get("message").and_then(|v| v.as_str()) {
            println!("Message: {}", message);
        }

        print_public_outcome_message(challenge_id, None, None, None, Some(&get_response));

        println!();
        return Ok(());
    }

    let work_unit_id = get_response
        .get("work_unit")
        .and_then(|v| v.get("work_unit_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("(missing)");

    println!("Work assigned:");
    println!("   {}", work_unit_id);

    let get_auth = get_response
        .get("participant_auth")
        .and_then(|v| v.as_object());

    if let Some(auth) = get_auth {
        let auth_mode = auth.get("auth_mode").and_then(|v| v.as_str()).unwrap_or("");
        let token_status = auth
            .get("token_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let device_status = auth
            .get("device_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let participant_status = auth
            .get("participant_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        println!("Official auth:");
        println!(
            "   Auth mode: {}",
            if auth_mode.is_empty() {
                "UNKNOWN"
            } else {
                auth_mode
            }
        );
        println!(
            "   Token status: {}",
            if token_status.is_empty() {
                "UNKNOWN"
            } else {
                token_status
            }
        );
        println!(
            "   Device status: {}",
            if device_status.is_empty() {
                "UNKNOWN"
            } else {
                device_status
            }
        );
        println!(
            "   Participant status: {}",
            if participant_status.is_empty() {
                "UNKNOWN"
            } else {
                participant_status
            }
        );
    }

    let assignment_token_present = get_response
        .get("assignment")
        .and_then(|v| v.get("assignment_token"))
        .and_then(|v| v.as_str())
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    println!(
        "   Assignment token: {}",
        if assignment_token_present {
            "present"
        } else {
            "missing"
        }
    );

    let heartbeat_guard = official_start_assignment_heartbeat(&get_response, &cfg, &base)?;

    let heartbeat_interval = get_response
        .get("assignment")
        .and_then(|v| v.get("heartbeat_interval_seconds"))
        .and_then(|v| v.as_u64())
        .unwrap_or(900);

    println!("   Renewable lease: active");
    println!(
        "   Heartbeat interval: approximately {} seconds",
        heartbeat_interval
    );

    println!("Get-work response saved:");
    println!("   {}", get_path);
    println!();
    println!("Step 2/4: computing assigned work with dashu-int...");

    let payload = official_compute_work_unit_payload(&get_response, &cfg)?;
    let payload_path = format!(
        "server_client_runs/public/{}_submit_payload.json",
        payload
            .get("work_unit_id")
            .and_then(|v| v.as_str())
            .unwrap_or("official_work")
    );

    let payload_for_disk = official_redact_secrets(&payload);
    write_sensitive_text(
        &payload_path,
        serde_json::to_string_pretty(&payload_for_disk)
            .map_err(|e| format!("Cannot serialize submit payload: {}", e))?,
    )
    .map_err(|e| format!("Cannot write submit payload: {}", e))?;

    let hit_count = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);

    println!("Computation completed.");
    println!("Hits found: {}", hit_count);
    println!("Submit payload saved:");
    println!("   {}", payload_path);
    println!();

    if heartbeat_guard.fatal_lease_error() {
        let _ = heartbeat_guard.stop();

        return Err(
            "The assignment lease is no longer valid. The computed payload was saved locally but was not submitted."
                .to_string(),
        );
    }

    println!("Step 3/4: submitting result to official server...");

    let submit_response_result = official_http_post_json(&submit_url, &payload);

    let heartbeat_fatal_after_submit = heartbeat_guard.stop();

    if heartbeat_fatal_after_submit {
        return Err("The assignment lease became invalid before submission completed.".to_string());
    }

    let submit_response = submit_response_result?;
    let response_path = format!(
        "server_client_runs/public/{}_submit_response.json",
        payload
            .get("work_unit_id")
            .and_then(|v| v.as_str())
            .unwrap_or("official_work")
    );

    write_sensitive_text(
        &response_path,
        serde_json::to_string_pretty(&official_redact_secrets(&submit_response))
            .map_err(|e| format!("Cannot serialize submit response: {}", e))?,
    )
    .map_err(|e| format!("Cannot write submit response: {}", e))?;

    println!("Submit response saved:");
    println!("   {}", response_path);
    println!();
    println!("Step 4/4: server response summary");

    println!(
        "Accepted: {}",
        submit_response
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );
    println!(
        "Has hit: {}",
        submit_response
            .get("has_hit")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );
    println!(
        "Hit count: {}",
        submit_response
            .get("hit_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    );
    println!(
        "Challenge completed: {}",
        submit_response
            .get("challenge_completed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    );

    if let Some(mode) = submit_response.get("mode").and_then(|v| v.as_str()) {
        println!("Server mode: {}", mode);
    }
    if let Some(message) = submit_response.get("message").and_then(|v| v.as_str()) {
        println!("Message: {}", message);

        let submit_auth = submit_response
            .get("participant_auth")
            .and_then(|v| v.as_object());

        if let Some(auth) = submit_auth {
            let auth_mode = auth.get("auth_mode").and_then(|v| v.as_str()).unwrap_or("");
            let token_status = auth
                .get("token_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let device_status = auth
                .get("device_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let participant_status = auth
                .get("participant_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            println!("Submit auth:");
            println!(
                "   Auth mode: {}",
                if auth_mode.is_empty() {
                    "UNKNOWN"
                } else {
                    auth_mode
                }
            );
            println!(
                "   Token status: {}",
                if token_status.is_empty() {
                    "UNKNOWN"
                } else {
                    token_status
                }
            );
            println!(
                "   Device status: {}",
                if device_status.is_empty() {
                    "UNKNOWN"
                } else {
                    device_status
                }
            );
            println!(
                "   Participant status: {}",
                if participant_status.is_empty() {
                    "UNKNOWN"
                } else {
                    participant_status
                }
            );
        }
    }

    let submit_accepted = submit_response
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    print_public_outcome_message(
        challenge_id,
        Some(work_unit_id),
        Some(&payload),
        Some(&submit_response),
        None,
    );

    if !submit_accepted {
        let error_code = submit_response
            .get("error_code")
            .and_then(|v| v.as_str())
            .unwrap_or("RESULT_NOT_ACCEPTED");

        return Err(format!(
            "Official server did not accept this package: {}",
            error_code
        ));
    }

    println!();
    println!("Official run finished.");
    println!();

    Ok(())
}

fn print_official_explain() {
    println!();
    println!("Official Challenge Mode");
    println!("=======================");
    println!();
    println!("Official Challenge Mode lets your computer contribute to a public");
    println!("MAX Prime Challenge.");
    println!();
    println!("The server divides a large search into small work units.");
    println!("Your client receives one assigned work unit, runs it locally, and");
    println!("submits only the result for that assigned work.");
    println!();
    println!("Flow:");
    println!("1. Login with MAX.");
    println!("2. Receive an official work unit.");
    println!("3. Run the assigned computation locally.");
    println!("4. Submit the result.");
    println!("5. If a possible prime is found, the server verifies it.");
    println!("6. Verified discoveries may appear in the public challenge page.");
    println!();
    println!("Important:");
    println!("- The public client must not contain server secrets.");
    println!("- The public client must not contain private MAX Login code.");
    println!("- The server controls official work assignment.");
    println!("- Local demo discoveries are not official submissions.");
    println!();
}

fn print_official_status() {
    println!();
    println!("Official Challenge Status");
    println!("=========================");
    println!();
    println!("Status: not connected yet");
    println!("Mode: skeleton only");
    println!();
    println!("This public client currently supports Local Mode.");
    println!("Official Challenge Mode is being prepared.");
    println!();
    println!("Planned official flow:");
    println!("- Login with MAX");
    println!("- get official work unit");
    println!("- run assigned work");
    println!("- submit result");
    println!("- receive verification status");
    println!("- show official discoveries");
    println!();
}

fn print_official_login_placeholder() {
    println!();
    println!("Login with MAX");
    println!("==============");
    println!();
    println!("This is a placeholder screen for the future official login.");
    println!();
    println!("What Login with MAX will do:");
    println!("- prove that you control a MAX ID;");
    println!("- allow the server to assign official work units;");
    println!("- connect official results to your participant identity.");
    println!();
    println!("What it will not send by default:");
    println!("- your name;");
    println!("- your email;");
    println!("- your phone number;");
    println!("- your personal profile.");
    println!();
    println!("A public nickname may be optional later, only if you want to appear");
    println!("in a public ranking after a verified discovery.");
    println!();
    println!("No private MAX Login implementation is included in this public client.");
    println!();
}

fn print_official_preview() {
    println!();
    println!("+------------------------------------------------------+");
    println!("| MAX Prime Challenge                                  |");
    println!("| Official Challenge Mode                              |");
    println!("+------------------------------------------------------+");
    println!();
    println!("Official Mode: NOT CONNECTED YET");
    println!("--------------------------------------------------------");
    println!("Step 1: Login with MAX                         [todo]");
    println!("Step 2: Receive official work unit             [todo]");
    println!("Step 3: Run assigned computation locally       [todo]");
    println!("Step 4: Submit result                          [todo]");
    println!("Step 5: Server verification                    [todo]");
    println!("Step 6: Public discovery page                  [todo]");
    println!();
    println!("[ Login with MAX ]");
    println!("[ Get Official Work ]        -> official-get-work");
    println!("[ Submit Result ]            -> official-submit-result");
    println!("[ View Official Discoveries ]");
    println!();
    println!("Privacy:");
    println!("The public client will not send name, email, phone number, or");
    println!("personal profile by default.");
    println!();
    println!("Security:");
    println!("No server secrets, HF tokens, database credentials, or private");
    println!("MAX Login implementation belong inside the public client.");
    println!();
    println!("+------------------------------------------------------+");
    println!();
}

fn print_gui_preview() {
    println!();
    println!("+======================================================================+");
    println!("| MAX Prime Challenge Public Client                                    |");
    println!("| GUI Preview / Product Map                                            |");
    println!("+======================================================================+");
    println!();

    println!("This is not the final graphical app yet.");
    println!("It is a safe text preview of how the public client is being organized.");
    println!();

    println!("+---------------------------+");
    println!("| 1. Local Demo             |");
    println!("+---------------------------+");
    println!("Purpose:");
    println!("   Simple local test for normal users.");
    println!();
    println!("What it does:");
    println!("   - creates a random local n0;");
    println!("   - tests MAX Prime N candidates;");
    println!("   - shows expected primes, observed primes and enrichment;");
    println!("   - saves local discoveries only on this computer.");
    println!();
    println!("Commands:");
    println!("   max_prime_public_client local-demo");
    println!("   max_prime_public_client local-demo 1500 20");
    println!("   max_prime_public_client discoveries");
    println!("   max_prime_public_client export-current-run");
    println!();

    println!("+---------------------------+");
    println!("| 2. Advanced Local         |");
    println!("+---------------------------+");
    println!("Purpose:");
    println!("   Reproducible local experiments for technical users and researchers.");
    println!();
    println!("What it does:");
    println!("   - reads an experiment JSON;");
    println!("   - supports n0, step, iterations, test_N, test_d;");
    println!("   - supports CRT ON/OFF;");
    println!("   - uses n_raw = n0 + i * step;");
    println!("   - if CRT is ON, uses n_effective = R + M * n_raw;");
    println!("   - exports an advanced result JSON.");
    println!();
    println!("Safe preview commands:");
    println!("   max_prime_public_client advanced-local-preview examples/local_advanced_experiment_example.json");
    println!("   max_prime_public_client advanced-local-preview examples/local_advanced_experiment_crt_example.json");
    println!();
    println!("Run commands:");
    println!(
        "   max_prime_public_client advanced-local examples/local_advanced_experiment_example.json"
    );
    println!("   max_prime_public_client advanced-local examples/local_advanced_experiment_crt_example.json");
    println!();

    println!("+---------------------------+");
    println!("| 3. Official Challenge     |");
    println!("+---------------------------+");
    println!("Purpose:");
    println!("   Future public participation mode controlled by the MAX Prime server.");
    println!();
    println!("Current status:");
    println!("   Skeleton only. Not connected yet.");
    println!();
    println!("Important rules:");
    println!("   - the public client must not contain secrets;");
    println!("   - the public client must not contain private MAX Login code;");
    println!("   - official n0, step, CRT and work units come from the server;");
    println!("   - local discoveries are not official submissions;");
    println!("   - official hits must be assigned, submitted and verified server-side.");
    println!();
    println!("Commands:");
    println!("   max_prime_public_client official-explain");
    println!("   max_prime_public_client official-status");
    println!("   max_prime_public_client official-config");
    println!("   max_prime_public_client official-device");
    println!("   max_prime_public_client official-login-start");
    println!("   max_prime_public_client official-login-status");
    println!("   max_prime_public_client official-get-work");
    println!("   max_prime_public_client official-submit-result");
    println!("   max_prime_public_client official-login-placeholder");
    println!("   max_prime_public_client official-preview");
    println!();

    println!("+---------------------------+");
    println!("| Current files             |");
    println!("+---------------------------+");
    println!("Local discoveries:");
    println!("   discoveries/local_discoveries.json");
    println!("Current run state:");
    println!("   app_state/current_run.json");
    println!("Exports:");
    println!("   exports/");
    println!("Examples:");
    println!("   examples/local_advanced_experiment_example.json");
    println!("   examples/local_advanced_experiment_crt_example.json");
    println!();

    println!("Recommended next action:");
    println!("   max_prime_public_client self-check");
    println!("   max_prime_public_client advanced-local-preview examples/local_advanced_experiment_crt_example.json");
    println!();
}

fn print_next() {
    println!();
    println!("Next product steps");
    println!("==================");
    println!();
    println!("Phase 1: public client shell");
    println!("- human welcome screen;");
    println!("- local mode explanation;");
    println!("- official challenge explanation;");
    println!("- privacy explanation;");
    println!("- discoveries model;");
    println!("- local-demo command.");
    println!();
    println!("Phase 2: participant protocol");
    println!("- Login with MAX;");
    println!("- participant token;");
    println!("- client device ID;");
    println!("- authenticated get-work;");
    println!("- authenticated submit-result.");
    println!();
    println!("Phase 3: GUI");
    println!("- welcome screen;");
    println!("- Login with MAX button;");
    println!("- Start contributing button;");
    println!("- progress view;");
    println!("- discoveries view;");
    println!("- advanced technical details.");
    println!("- export JSON files for proof and sharing.");
    println!();
}

fn local_demo(iterations: usize, n_digits: usize) -> Result<(), String> {
    println!();
    println!("Local Demo Search");
    println!("=================");
    println!();
    println!("This is a private local demo.");
    println!("No MAX Login is required.");
    println!("No result is submitted to the official server.");
    println!();
    println!("Candidate type: N only");
    println!("Iterations: {}", iterations);
    println!("Random starting n digits: {}", n_digits);
    println!("Engine: dashu-int");
    println!();

    let started_at = now_unix();

    let mut state = CurrentRunState {
        status: "running".to_string(),
        mode: "local-demo".to_string(),
        experiment_id: "LOCAL-DEMO".to_string(),
        candidate_type: "N".to_string(),
        iterations_total: iterations,
        iterations_done: 0,
        n_digits,
        hits_found: 0,
        hits_exported: 0,
        best_digits: 0,
        best_sha256: String::new(),
        test_n: true,
        test_d: false,
        filter_enabled: false,
        filter: None,
        expected_n_primes: 0.0,
        observed_n_primes: 0,
        n_enrichment: 0.0,
        expected_d_primes: 0.0,
        observed_d_primes: 0,
        d_enrichment: 0.0,
        hits: Vec::new(),
        engine: "dashu-int".to_string(),
        started_at_unix: started_at,
        updated_at_unix: started_at,
        completed_at_unix: 0,
        message: "Local demo running. No official server submission.".to_string(),
    };

    save_current_run_state(&state)?;

    let n0_str = random_decimal_string(n_digits);
    let n0 = UBig::from_str(&n0_str).map_err(|e| format!("Cannot parse n0: {}", e))?;

    let mut found: Vec<LocalDiscovery> = Vec::new();
    let mut expected_n_primes: f64 = 0.0;

    for i in 0..iterations {
        let n = &n0 + UBig::from(i as u64);
        let candidate = n_candidate_from_n(&n);
        let candidate_digits = decimal_digits(&candidate);

        expected_n_primes += 1.0 / ((candidate_digits as f64) * std::f64::consts::LN_10);

        if is_probable_prime(&candidate) {
            let digits = candidate_digits;
            let sha = sha256_decimal(&candidate);

            println!(
                "Hit found: N | iteration {} | {} digits | sha256 {}",
                i, digits, sha
            );

            if digits > state.best_digits {
                state.best_digits = digits;
                state.best_sha256 = sha.clone();
            }

            found.push(LocalDiscovery {
                mode: "local-demo".to_string(),
                candidate_type: "N".to_string(),
                i,
                n: n.to_string(),
                candidate: candidate.to_string(),
                digits,
                sha256: sha,
                found_at_unix: now_unix(),
                note: "Probable prime found by local demo. Not an official challenge submission. Engine: dashu-int.".to_string(),
            });
        }

        state.expected_n_primes = expected_n_primes;
        state.observed_n_primes = found.len();
        state.n_enrichment = if expected_n_primes > 0.0 {
            found.len() as f64 / expected_n_primes
        } else {
            0.0
        };
        state.iterations_done = i + 1;
        state.hits_found = found.len();
        state.hits_exported = found.len();
        state.hits = found.clone();
        state.updated_at_unix = now_unix();

        if i == 0 || (i + 1) % 100 == 0 || i + 1 == iterations {
            save_current_run_state(&state)?;
            println!(
                "Progress: {}/{} | current N digits: {} | hits: {}",
                i + 1,
                iterations,
                candidate_digits,
                found.len()
            );
        }
    }

    if !found.is_empty() {
        append_local_discoveries(found.clone())?;
    }

    state.status = "completed".to_string();
    state.iterations_done = iterations;
    state.hits_found = found.len();
    state.hits_exported = found.len();
    state.observed_n_primes = found.len();
    state.expected_n_primes = expected_n_primes;
    state.n_enrichment = if expected_n_primes > 0.0 {
        found.len() as f64 / expected_n_primes
    } else {
        0.0
    };
    state.hits = found.clone();
    state.updated_at_unix = now_unix();
    state.completed_at_unix = state.updated_at_unix;
    state.message = format!(
        "Local demo completed. Hits: {}. N enrichment: {:.3}×. Engine: dashu-int.",
        found.len(),
        state.n_enrichment
    );
    save_current_run_state(&state)?;

    println!();
    println!("Local Demo completed");
    println!("====================");
    println!();
    println!("Iterations tested: {}", iterations);
    println!("Probable primes found: {}", found.len());
    println!("Expected random N primes: {:.6}", expected_n_primes);
    println!("N enrichment: {:.3}×", state.n_enrichment);
    println!("Engine: dashu-int");
    println!();
    println!("Saved locally:");
    println!("   {}", LOCAL_DISCOVERIES_PATH);
    println!("   {}", CURRENT_RUN_STATE_PATH);
    println!();

    Ok(())
}

fn copy_local_prime(index: usize) -> Result<(), String> {
    let items = load_local_discoveries();

    if index == 0 || index > items.len() {
        return Err(format!("Discovery index not found: {}", index));
    }

    println!("{}", items[index - 1].candidate);
    Ok(())
}

fn copy_local_sha(index: usize) -> Result<(), String> {
    let items = load_local_discoveries();

    if index == 0 || index > items.len() {
        return Err(format!("Discovery index not found: {}", index));
    }

    println!("{}", items[index - 1].sha256);
    Ok(())
}

fn export_file(src_path: &str, export_prefix: &str) -> Result<(), String> {
    if !Path::new(src_path).exists() {
        return Err(format!("Source file not found: {}", src_path));
    }

    fs::create_dir_all("exports").map_err(|e| format!("Cannot create exports folder: {}", e))?;

    let ts = now_unix();
    let dst_path = format!("exports/{}_{}.json", export_prefix, ts);

    fs::copy(src_path, &dst_path).map_err(|e| format!("Cannot export JSON: {}", e))?;

    println!();
    println!("JSON exported.");
    println!("Source:");
    println!("   {}", src_path);
    println!("Export:");
    println!("   {}", dst_path);
    println!();

    Ok(())
}

fn export_current_run() -> Result<(), String> {
    export_file(CURRENT_RUN_STATE_PATH, "current_run")
}

fn export_local_discoveries() -> Result<(), String> {
    export_file(LOCAL_DISCOVERIES_PATH, "local_discoveries")
}

fn clear_local_discoveries() -> Result<(), String> {
    if Path::new(LOCAL_DISCOVERIES_PATH).exists() {
        fs::remove_file(LOCAL_DISCOVERIES_PATH)
            .map_err(|e| format!("Cannot remove local discoveries: {}", e))?;
    }

    println!();
    println!("Local discoveries cleared.");
    println!("Storage removed:");
    println!("   {}", LOCAL_DISCOVERIES_PATH);
    println!();

    Ok(())
}

fn check_json_file(path: &str) -> String {
    if !Path::new(path).exists() {
        return "missing".to_string();
    }

    match fs::read_to_string(path) {
        Ok(txt) => match serde_json::from_str::<serde_json::Value>(&txt) {
            Ok(_) => "ok json".to_string(),
            Err(_) => "invalid json".to_string(),
        },
        Err(_) => "cannot read".to_string(),
    }
}

fn check_path_exists(path: &str) -> String {
    if Path::new(path).exists() {
        "ok".to_string()
    } else {
        "missing".to_string()
    }
}

fn self_check_mode() -> Result<(), String> {
    println!();
    println!("MAX Prime Public Client Self Check");
    println!("==================================");
    println!();

    println!("Core folders:");
    println!("   app_state: {}", check_path_exists("app_state"));
    println!("   discoveries: {}", check_path_exists("discoveries"));
    println!("   exports: {}", check_path_exists("exports"));
    println!("   examples: {}", check_path_exists("examples"));
    println!("   logs: {}", check_path_exists("logs"));
    println!("   checkpoints: {}", check_path_exists("checkpoints"));
    println!();

    println!("Important files:");
    println!(
        "   app_state/current_run.json: {}",
        check_json_file(CURRENT_RUN_STATE_PATH)
    );
    println!(
        "   app_state/official_client_config.json: {}",
        check_json_file(OFFICIAL_CLIENT_CONFIG_PATH)
    );
    println!(
        "   discoveries/local_discoveries.json: {}",
        check_json_file(LOCAL_DISCOVERIES_PATH)
    );
    println!(
        "   examples/local_advanced_experiment_example.json: {}",
        check_json_file("examples/local_advanced_experiment_example.json")
    );
    println!(
        "   examples/local_advanced_experiment_crt_example.json: {}",
        check_json_file("examples/local_advanced_experiment_crt_example.json")
    );
    println!();

    println!("Official local config:");
    match load_or_create_official_client_config() {
        Ok(cfg) => {
            println!("   client_device_id: {}", cfg.client_device_id);
            println!("   official_api_base: {}", cfg.official_api_base);
            println!("   max_login_status: {}", cfg.max_login_status);
            println!("   login_session_status: {}", cfg.login_session_status);
            println!(
                "   participant_token_status: {}",
                cfg.participant_token_status
            );
        }
        Err(e) => {
            println!("   error: {}", e);
        }
    }
    println!();

    println!("Available local modes:");
    println!("   local-demo: ok");
    println!("   advanced-local-preview: ok");
    println!("   advanced-local: ok");
    println!("   gui-preview: ok");
    println!();

    println!("Available official skeleton commands:");
    println!("   official-config: ok");
    println!("   official-device: ok");
    println!("   official-login-start: real MAX Login registration start");
    println!("   official-login-status: real MAX Login registration poll");
    println!("   official-get-work: participant token status check");
    println!("   official-submit-result: integrated inside official-run-once");
    println!();

    println!("Security check:");
    println!("   No HF token expected in this client.");
    println!("   No database credentials expected in this client.");
    println!("   No private MAX Login implementation expected in this client.");
    println!("   Official work assignment must remain server-controlled.");
    println!();

    println!("Self-check completed.");
    println!();

    Ok(())
}

fn print_theory_note() {
    println!();
    println!("MAX Prime Theory — N and d");
    println!("==========================");
    println!();
    println!("Plain explanation:");
    println!("   MAX Prime local experiments can test two related candidate types: N and d.");
    println!();
    println!("   N is the main MAX Prime Challenge target.");
    println!("   It is the value used to measure the prime-producing strength of the");
    println!("   MAX Prime polynomial family.");
    println!();
    println!("   d is a related auxiliary value.");
    println!("   It can be useful for technical exploration, but it is not the main");
    println!("   official Challenge target.");
    println!();
    println!("Important limits:");
    println!("   Local experiments are private experiments.");
    println!("   They are not official Challenge submissions.");
    println!("   Found candidates are probable primes tested by Miller-Rabin with fixed bases.");
    println!("   They are not public mathematical certifications.");
    println!();
    println!("How to think about it:");
    println!("   Local experiments are the training ground.");
    println!("   The official Challenge is the real public participation mode.");
    println!();
    println!("Full background:");
    println!("   Official website:");
    println!("   https://www.max-russo.com");
    println!();
    println!();
}

// Optimized structural sieve and persistent-offset engine.
const CRTCOMP_SAFECRT50: [u64; 50] = [
    31, 43, 59, 67, 71, 89, 101, 103, 107, 113, 149, 151, 167, 173, 181, 193, 211, 233, 239, 241,
    251, 263, 269, 277, 283, 311, 353, 359, 367, 373, 383, 401, 433, 463, 479, 491, 509, 569, 571,
    577, 599, 647, 661, 691, 701, 709, 733, 739, 743, 751,
];

#[cfg(test)]
#[derive(Clone, Default)]
struct CrtCompArmStats {
    rejected_before_build: usize,
    built: usize,
    entered_mr: usize,
    hits: usize,
    build_s: f64,
    mr_s: f64,
    total_s: f64,
}

fn crtcomp_pow_mod(mut base: u64, mut exp: u64, modu: u64) -> u64 {
    if modu == 1 {
        return 0;
    }
    let mut result = 1u64;
    base %= modu;

    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modu as u128) as u64;
        }
        base = ((base as u128 * base as u128) % modu as u128) as u64;
        exp >>= 1;
    }
    result
}

fn crtcomp_inv_mod(a: u64, p: u64) -> Option<u64> {
    if p < 2 || a % p == 0 {
        None
    } else {
        Some(crtcomp_pow_mod(a % p, p - 2, p))
    }
}

fn crtcomp_legendre(a: u64, p: u64) -> u64 {
    crtcomp_pow_mod(a % p, (p - 1) / 2, p)
}

fn crtcomp_tonelli_shanks(n: u64, p: u64) -> Option<u64> {
    if p == 2 {
        return Some(n & 1);
    }

    let n = n % p;
    if n == 0 {
        return Some(0);
    }

    if crtcomp_legendre(n, p) != 1 {
        return None;
    }

    if p % 4 == 3 {
        return Some(crtcomp_pow_mod(n, (p + 1) / 4, p));
    }

    let mut q = p - 1;
    let mut s = 0u32;
    while q % 2 == 0 {
        q /= 2;
        s += 1;
    }

    let mut z = 2u64;
    while crtcomp_legendre(z, p) != p - 1 {
        z += 1;
    }

    let mut c = crtcomp_pow_mod(z, q, p);
    let mut x = crtcomp_pow_mod(n, (q + 1) / 2, p);
    let mut t = crtcomp_pow_mod(n, q, p);
    let mut m = s;

    while t != 1 {
        let mut i = 1u32;
        let mut t2i = ((t as u128 * t as u128) % p as u128) as u64;

        while i < m && t2i != 1 {
            t2i = ((t2i as u128 * t2i as u128) % p as u128) as u64;
            i += 1;
        }

        if i == m {
            return None;
        }

        let b = crtcomp_pow_mod(c, 1u64 << (m - i - 1), p);
        x = ((x as u128 * b as u128) % p as u128) as u64;
        let b2 = ((b as u128 * b as u128) % p as u128) as u64;
        t = ((t as u128 * b2 as u128) % p as u128) as u64;
        c = b2;
        m = i;
    }

    Some(x)
}

fn crtcomp_poly_mod(n: u64, p: u64) -> u64 {
    let nn = n as u128;
    ((31u128 + 6u128 * nn * (nn + 1u128)) % p as u128) as u64
}

fn crtcomp_bad_n_classes(p: u64) -> Vec<u64> {
    if p <= 3 {
        let mut out = Vec::new();
        for n in 0..p {
            if crtcomp_poly_mod(n, p) == 0 {
                out.push(n);
            }
        }
        return out;
    }

    // 6*N(n) = (6n+3)^2 + 177
    let rhs = (p - (177 % p)) % p;
    let Some(root) = crtcomp_tonelli_shanks(rhs, p) else {
        return Vec::new();
    };
    let Some(inv6) = crtcomp_inv_mod(6 % p, p) else {
        return Vec::new();
    };

    let mut out = Vec::with_capacity(2);

    let a = ((root + p - (3 % p)) % p) as u128;
    let n1 = ((a * inv6 as u128) % p as u128) as u64;
    if crtcomp_poly_mod(n1, p) == 0 {
        out.push(n1);
    }

    let root2 = if root == 0 { 0 } else { p - root };
    let b = ((root2 + p - (3 % p)) % p) as u128;
    let n2 = ((b * inv6 as u128) % p as u128) as u64;

    if n2 != n1 && crtcomp_poly_mod(n2, p) == 0 {
        out.push(n2);
    }

    out
}

fn crtcomp_primes_up_to(limit: usize) -> Vec<u64> {
    if limit < 2 {
        return Vec::new();
    }

    let mut composite = vec![false; limit + 1];
    let mut p = 2usize;

    while p * p <= limit {
        if !composite[p] {
            let mut k = p * p;
            while k <= limit {
                composite[k] = true;
                k += p;
            }
        }
        p += 1;
    }

    (2..=limit)
        .filter(|&x| !composite[x])
        .map(|x| x as u64)
        .collect()
}

fn crtcomp_ubig_mod_u64(v: &UBig, p: u64) -> u64 {
    u64::try_from(v % UBig::from(p)).expect("remainder must fit u64")
}

#[cfg(test)]
fn crtcomp_ubig_mod_u64_legacy(v: &UBig, p: u64) -> u64 {
    (v % UBig::from(p))
        .to_string()
        .parse::<u64>()
        .expect("remainder must fit u64")
}

#[derive(Clone, Debug)]
struct CrtCompScheduleEntry {
    p: u64,
    bad_classes: [u64; 2],
    bad_class_count: u8,
    step_mod: u64,
    inv_step: Option<u64>,
}

#[derive(Clone, Debug)]
struct CrtCompStructuralSchedule {
    entries: Vec<CrtCompScheduleEntry>,
}

#[derive(Clone, Debug)]
struct CrtCompPersistentEntryState {
    next_offsets: [usize; 2],
}

/// Mutable cursor state for one consecutive scan.  The compiled schedule stays
/// immutable and can therefore be shared by independent scans.
#[derive(Clone, Debug)]
struct CrtCompPersistentState {
    entries: Vec<CrtCompPersistentEntryState>,
    reject_all: bool,
}

fn crtcomp_compile_schedule(
    primes: &[u64],
    step_n: &UBig,
    skip_safecrt: bool,
) -> CrtCompStructuralSchedule {
    let mut entries = Vec::new();

    for &p in primes {
        // D is compiled without the SAFECRT50 moduli, so its hot marking loop
        // never has to perform this membership test.
        if skip_safecrt && CRTCOMP_SAFECRT50.contains(&p) {
            continue;
        }
        let bad = crtcomp_bad_n_classes(p);
        if bad.is_empty() {
            continue;
        }
        debug_assert!(bad.len() <= 2);
        let mut bad_classes = [0; 2];
        bad_classes[..bad.len()].copy_from_slice(&bad);
        let step_mod = crtcomp_ubig_mod_u64(step_n, p);
        let inv_step = crtcomp_inv_mod(step_mod, p);
        entries.push(CrtCompScheduleEntry {
            p,
            bad_classes,
            bad_class_count: bad.len() as u8,
            step_mod,
            inv_step,
        });
    }

    CrtCompStructuralSchedule { entries }
}

#[cfg(test)]
fn crtcomp_safe_residue(p: u64) -> u64 {
    for r in 0..p {
        if crtcomp_poly_mod(r, p) != 0 {
            return r;
        }
    }
    panic!("No safe residue for prime {}", p);
}

#[cfg(test)]
fn crtcomp_build_safecrt50() -> (UBig, UBig) {
    // Costruzione CRT incrementale con M arbitrariamente grande ma p piccolo.
    let mut m = UBig::from(1u32);
    let mut r = UBig::from(0u32);

    for p in CRTCOMP_SAFECRT50 {
        let wanted = crtcomp_safe_residue(p);
        let r_mod = crtcomp_ubig_mod_u64(&r, p);
        let m_mod = crtcomp_ubig_mod_u64(&m, p);
        let inv = crtcomp_inv_mod(m_mod, p).expect("SAFECRT50 moduli must be pairwise coprime");

        let delta = (wanted + p - r_mod) % p;
        let k = ((delta as u128 * inv as u128) % p as u128) as u64;

        r = &r + &m * UBig::from(k);
        m = &m * UBig::from(p);
    }

    (m, r)
}

#[cfg(test)]
fn crtcomp_validate_safecrt50(m: &UBig, r: &UBig) -> Result<(), String> {
    for p in CRTCOMP_SAFECRT50 {
        if crtcomp_ubig_mod_u64(m, p) != 0 {
            return Err(format!("CRT validation failed: M mod {} != 0", p));
        }

        let rr = crtcomp_ubig_mod_u64(r, p);
        if crtcomp_poly_mod(rr, p) == 0 {
            return Err(format!(
                "CRT validation failed: selected residue is dead modulo {}",
                p
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn crtcomp_mark_structural(
    iterations: usize,
    start_n: &UBig,
    step_n: &UBig,
    primes: &[u64],
    skip_safecrt: bool,
) -> Vec<bool> {
    let schedule = crtcomp_compile_schedule(primes, step_n, skip_safecrt);
    crtcomp_mark_compiled(iterations, start_n, &schedule)
}

#[cfg(test)]
fn crtcomp_mark_compiled(
    iterations: usize,
    start_n: &UBig,
    schedule: &CrtCompStructuralSchedule,
) -> Vec<bool> {
    let mut rejected = vec![false; iterations];

    for entry in &schedule.entries {
        let p = entry.p;
        let bad = &entry.bad_classes[..entry.bad_class_count as usize];
        let start_mod = crtcomp_ubig_mod_u64(start_n, p);

        if entry.step_mod == 0 {
            if bad.contains(&start_mod) {
                rejected.fill(true);
                return rejected;
            }
            continue;
        }

        let inv_step = entry
            .inv_step
            .expect("nonzero step modulo prime must be invertible");

        for &bad_n in bad {
            let delta = (bad_n + p - start_mod) % p;
            let i0 = ((delta as u128 * inv_step as u128) % p as u128) as usize;

            let stride = p as usize;
            let mut i = i0;
            while i < iterations {
                rejected[i] = true;
                i += stride;
            }
        }
    }

    rejected
}

fn crtcomp_initialize_persistent_state(
    start_n: &UBig,
    schedule: &CrtCompStructuralSchedule,
) -> CrtCompPersistentState {
    let mut reject_all = false;
    let entries = schedule
        .entries
        .iter()
        .map(|entry| {
            let mut next_offsets = [0usize; 2];
            let bad = &entry.bad_classes[..entry.bad_class_count as usize];
            let start_mod = crtcomp_ubig_mod_u64(start_n, entry.p);

            if entry.step_mod == 0 {
                reject_all |= bad.contains(&start_mod);
            } else {
                let inv_step = entry
                    .inv_step
                    .expect("nonzero step modulo prime must be invertible");
                for (offset, &bad_n) in next_offsets.iter_mut().zip(bad) {
                    let delta = (bad_n + entry.p - start_mod) % entry.p;
                    *offset = ((delta as u128 * inv_step as u128) % entry.p as u128) as usize;
                }
            }
            CrtCompPersistentEntryState { next_offsets }
        })
        .collect();

    CrtCompPersistentState {
        entries,
        reject_all,
    }
}

/// Marks the next consecutive window and advances every class cursor by the
/// actual window length.  In particular, this does not assume equal segments.
fn crtcomp_mark_persistent(
    iterations: usize,
    schedule: &CrtCompStructuralSchedule,
    state: &mut CrtCompPersistentState,
) -> Vec<bool> {
    assert_eq!(schedule.entries.len(), state.entries.len());
    if state.reject_all {
        return vec![true; iterations];
    }

    let mut rejected = vec![false; iterations];
    for (entry, entry_state) in schedule.entries.iter().zip(&mut state.entries) {
        if entry.step_mod == 0 {
            continue;
        }
        let stride = usize::try_from(entry.p).expect("prime must fit usize");
        for next in entry_state.next_offsets[..entry.bad_class_count as usize].iter_mut() {
            let mut i = *next;
            while i < iterations {
                rejected[i] = true;
                i += stride;
            }
            *next = i - iterations;
        }
    }
    rejected
}

// Helpers retained for mathematical regression tests.
#[cfg(test)]
fn crtcomp_pass_small_primes(n: &UBig) -> bool {
    const SMALL: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for p in SMALL {
        let bp = UBig::from(p);
        if n == &bp {
            return true;
        }
        if n % &bp == UBig::from(0u32) {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn crtcomp_mr_only(n: &UBig) -> bool {
    let zero = UBig::from(0u32);
    let one = UBig::from(1u32);
    let two = UBig::from(2u32);

    if n < &two {
        return false;
    }

    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;

    while &d % &two == zero {
        d /= &two;
        s += 1;
    }

    const BASES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for a in BASES {
        let base = UBig::from(a);
        if base >= n_minus_one {
            continue;
        }

        let mut x = modpow_dashu(&base, &d, n);

        if x == one || x == n_minus_one {
            continue;
        }

        let mut passed = false;

        for _ in 1..s {
            x = modpow_dashu(&x, &two, n);
            if x == n_minus_one {
                passed = true;
                break;
            }
        }

        if !passed {
            return false;
        }
    }

    true
}

fn is_probable_prime_ring_max(n: &UBig) -> bool {
    use dashu_int::fast_div::ConstDivisor;

    let zero = UBig::from(0u32);
    let one = UBig::from(1u32);
    let two = UBig::from(2u32);

    if n < &two {
        return false;
    }

    const BASES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for p in BASES {
        let small = UBig::from(p);
        if n == &small {
            return true;
        }
        if n % &small == zero {
            return false;
        }
    }

    // Every MAX candidate is 7 mod 12, hence 3 mod 4.
    assert_eq!(n % UBig::from(4u32), UBig::from(3u32));

    let minus_one = n - &one;
    let d = &minus_one / &two;

    // Prepare the modulus ONCE for all twelve bases.
    let ring = ConstDivisor::new(n.clone());

    for a in BASES {
        let base = UBig::from(a);

        if base >= minus_one {
            continue;
        }

        let x = ring.reduce(base).pow(&d).residue();

        if x != one && x != minus_one {
            return false;
        }
    }

    true
}

/// General 12-base Miller--Rabin using one prepared dashu modulus.  Unlike
/// `is_probable_prime_ring_max`, this routine makes no assumption about the
/// residue class of its input and is therefore also valid for RANDOM_ODD.
fn is_probable_prime_ring_general(n: &UBig) -> bool {
    use dashu_int::fast_div::ConstDivisor;

    const BASES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    let zero = UBig::from(0u32);
    let one = UBig::from(1u32);
    let two = UBig::from(2u32);
    if n < &two {
        return false;
    }
    for p in BASES {
        let small = UBig::from(p);
        if n == &small {
            return true;
        }
        if n % &small == zero {
            return false;
        }
    }

    let minus_one = n - &one;
    let mut d = minus_one.clone();
    let mut s = 0usize;
    while &d % &two == zero {
        d /= &two;
        s += 1;
    }
    let ring = ConstDivisor::new(n.clone());
    for base in BASES {
        let a = UBig::from(base);
        if a >= minus_one {
            continue;
        }
        let mut x = ring.reduce(a).pow(&d).residue();
        if x == one || x == minus_one {
            continue;
        }
        let mut passed = false;
        for _ in 1..s {
            x = ring.reduce(x).sqr().residue();
            if x == minus_one {
                passed = true;
                break;
            }
        }
        if !passed {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn crtcomp_run_arm_core<F>(
    iterations: usize,
    start_n: &UBig,
    step_n: &UBig,
    rejected: Option<&[bool]>,
    marking_s: f64,
    mut observe_survivor: F,
) -> CrtCompArmStats
where
    F: FnMut(usize, &UBig, &UBig, bool),
{
    let total_start = std::time::Instant::now();

    let mut stats = CrtCompArmStats {
        ..Default::default()
    };

    let mut n = start_n.clone();

    for i in 0..iterations {
        if rejected.map(|m| m[i]).unwrap_or(false) {
            stats.rejected_before_build += 1;
            n += step_n;
            continue;
        }

        let build_start = std::time::Instant::now();
        let candidate = n_candidate_from_n(&n);
        stats.build_s += build_start.elapsed().as_secs_f64();
        stats.built += 1;

        if !crtcomp_pass_small_primes(&candidate) {
            observe_survivor(i, &n, &candidate, false);
            n += step_n;
            continue;
        }

        stats.entered_mr += 1;

        let mr_start = std::time::Instant::now();
        let prime = crtcomp_mr_only(&candidate);
        stats.mr_s += mr_start.elapsed().as_secs_f64();

        if prime {
            stats.hits += 1;
        }

        observe_survivor(i, &n, &candidate, prime);
        n += step_n;
    }

    stats.total_s = total_start.elapsed().as_secs_f64() + marking_s;
    stats
}

// Candidate cursor used by the optimized engine.
struct CrtCompCandidateCursor {
    index: usize,
    candidate: UBig,
    delta: UBig,
    second_difference: UBig,
}

impl CrtCompCandidateCursor {
    fn new(start_n: &UBig, step_n: &UBig) -> Self {
        let twelve_step = step_n * UBig::from(12u32);
        let six_step = step_n * UBig::from(6u32);
        let delta = &twelve_step * start_n + &six_step * (step_n + UBig::from(1u32));
        Self {
            index: 0,
            candidate: n_candidate_from_n(start_n),
            delta,
            second_difference: &twelve_step * step_n,
        }
    }

    fn at(&mut self, index: usize) -> &UBig {
        let gap = index
            .checked_sub(self.index)
            .expect("survivor indices must be nondecreasing within a window");
        match gap {
            0 => {}
            1 => {
                self.candidate += &self.delta;
                self.delta += &self.second_difference;
            }
            _ => {
                let k = UBig::from(u64::try_from(gap).expect("gap must fit u64"));
                let triangle = (gap as u128) * ((gap - 1) as u128) / 2;
                let triangle = UBig::from(triangle);
                self.candidate += &self.delta * &k;
                self.candidate += &self.second_difference * &triangle;
                self.delta += &self.second_difference * &k;
            }
        }
        self.index = index;
        &self.candidate
    }
}

// Helpers retained for regression tests.
#[cfg(test)]
const MAX_RANDOM_RESERVOIR: usize = 4_000;
#[cfg(test)]
const MAX_RANDOM_MAX_ROUND_STRIDE: u64 = 10_000_000;

#[cfg(test)]
fn random_odd_with_bits_from_rng<R: Rng + ?Sized>(bits: usize, rng: &mut R) -> UBig {
    let bytes_len = bits.div_ceil(8);
    let excess = bytes_len * 8 - bits;
    let mut bytes = vec![0u8; bytes_len];
    rng.fill(bytes.as_mut_slice());
    bytes[0] &= 0xff >> excess;
    bytes[0] |= 1u8 << (7 - excess);
    *bytes.last_mut().expect("positive bit length") |= 1;
    UBig::from_be_bytes(&bytes)
}

#[cfg(test)]
fn random_odd_with_bits(bits: usize) -> UBig {
    random_odd_with_bits_from_rng(bits, &mut rand::thread_rng())
}

#[derive(Clone, Debug)]
#[cfg(test)]
struct RandomPresieveBatch {
    product: u64,
}

#[cfg(test)]
fn compile_random_presieve(odd_primes: &[u32]) -> Vec<RandomPresieveBatch> {
    let mut batches = Vec::new();
    let mut product = 1u64;
    for &prime in odd_primes {
        let prime = u64::from(prime);
        if let Some(next) = product.checked_mul(prime) {
            product = next;
        } else {
            batches.push(RandomPresieveBatch { product });
            product = prime;
        }
    }
    if product > 1 {
        batches.push(RandomPresieveBatch { product });
    }
    batches
}

#[cfg(test)]
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

#[cfg(test)]
fn random_odd_rejected_by_presieve(candidate: &UBig, batches: &[RandomPresieveBatch]) -> bool {
    // One BigInt-by-word remainder covers every prime packed into the batch.
    // The following gcd is word-sized, eliminating one BigInt division per
    // small prime while preserving exactly the same survivor set.
    batches.iter().any(|batch| {
        let remainder = candidate % batch.product;
        gcd_u64(remainder, batch.product) != 1
    })
}

fn print_usage() {
    println!();
    println!("Usage:");
    println!("  max_prime_public_client welcome");
    println!("  max_prime_public_client modes");
    println!("  max_prime_public_client privacy");
    println!("  max_prime_public_client theory");
    println!("  max_prime_public_client explain-n");
    println!("  max_prime_public_client gui-preview");
    println!("  max_prime_public_client self-check");
    println!("  max_prime_public_client official-explain");
    println!("  max_prime_public_client official-status");
    println!("  max_prime_public_client official-config");
    println!("  max_prime_public_client official-device");
    println!("  max_prime_public_client official-login-start");
    println!("  max_prime_public_client official-login-status");
    println!("  max_prime_public_client official-run-once <challenge_id>");
    println!("  max_prime_public_client official-get-work");
    println!("  max_prime_public_client official-submit-result");
    println!("  max_prime_public_client official-login-placeholder");
    println!("  max_prime_public_client official-preview");
    println!("  max_prime_public_client status");
    println!("  max_prime_public_client discoveries");
    println!("  max_prime_public_client discoveries-all");

    println!("  max_prime_public_client local-demo [iterations] [n_digits]");
    println!("  max_prime_public_client advanced-local-preview <experiment.json>");
    println!("  max_prime_public_client advanced-local <experiment.json>");
    println!("  max_prime_public_client copy-local-prime <index>");
    println!("  max_prime_public_client copy-local-sha <index>");
    println!("  max_prime_public_client clear-local-discoveries");
    println!("  max_prime_public_client export-current-run");
    println!("  max_prime_public_client export-local-discoveries");
    println!("  max_prime_public_client next");
    println!();
}

fn parse_usize_arg(args: &[String], pos: usize, default_value: usize) -> usize {
    args.get(pos)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default_value)
}

#[cfg(test)]
fn primes_up_to(limit: u32) -> Vec<u32> {
    if limit < 2 {
        return Vec::new();
    }

    let mut is_prime = vec![true; (limit as usize) + 1];
    is_prime[0] = false;
    is_prime[1] = false;

    let mut p = 2usize;

    while p * p <= limit as usize {
        if is_prime[p] {
            let mut multiple = p * p;

            while multiple <= limit as usize {
                is_prime[multiple] = false;
                multiple += p;
            }
        }

        p += 1;
    }

    is_prime
        .iter()
        .enumerate()
        .filter_map(|(i, &prime)| if prime { Some(i as u32) } else { None })
        .collect()
}

#[cfg(test)]
fn decimal_mod_u32(text: &str, modulus: u32) -> Result<u32, String> {
    if modulus == 0 {
        return Err("decimal_mod_u32 modulus cannot be zero.".to_string());
    }

    let mut r = 0u64;
    let m = modulus as u64;

    for b in text.bytes() {
        if !b.is_ascii_digit() {
            return Err(format!("Invalid decimal integer: {}", text));
        }

        r = (r * 10 + (b - b'0') as u64) % m;
    }

    Ok(r as u32)
}

#[cfg(test)]
fn small_mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }

    let mut result = 1u64;
    base %= modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exp >>= 1;
    }

    result
}

#[cfg(test)]
fn small_mod_inverse_prime(value: u64, prime: u64) -> Option<u64> {
    let value = value % prime;

    if value == 0 {
        return None;
    }

    Some(small_mod_pow(value, prime - 2, prime))
}

#[cfg(test)]
fn tonelli_shanks_u64(n: u64, p: u64) -> Option<u64> {
    if p == 2 {
        return Some(n % 2);
    }

    let n = n % p;

    if n == 0 {
        return Some(0);
    }

    if small_mod_pow(n, (p - 1) / 2, p) != 1 {
        return None;
    }

    if p % 4 == 3 {
        return Some(small_mod_pow(n, (p + 1) / 4, p));
    }

    let mut q = p - 1;
    let mut s = 0u32;

    while q % 2 == 0 {
        q /= 2;
        s += 1;
    }

    let mut z = 2u64;

    while small_mod_pow(z, (p - 1) / 2, p) != p - 1 {
        z += 1;
    }

    let mut c = small_mod_pow(z, q, p);
    let mut x = small_mod_pow(n, (q + 1) / 2, p);
    let mut t = small_mod_pow(n, q, p);
    let mut m = s;

    while t != 1 {
        let mut i = 1u32;
        let mut t2i = (t * t) % p;

        while t2i != 1 {
            t2i = (t2i * t2i) % p;
            i += 1;

            if i >= m {
                return None;
            }
        }

        let exponent = 1u64 << (m - i - 1);
        let b = small_mod_pow(c, exponent, p);

        x = (x * b) % p;
        let b2 = (b * b) % p;
        t = (t * b2) % p;
        c = b2;
        m = i;
    }

    Some(x)
}

#[cfg(test)]
fn max_bad_n_residues(prime: u32) -> Vec<u32> {
    let p = prime as u64;

    /*
     * N(n) = 6*n^2 + 6*n + 31.
     *
     * Multiply by 6:
     *
     *   6*N(n) = (6*n + 3)^2 + 177
     *
     * Therefore, for p != 2,3:
     *
     *   N(n) == 0 (mod p)
     *
     * iff
     *
     *   (6*n + 3)^2 == -177 (mod p).
     *
     * We solve one modular square-root problem and obtain at most
     * two forbidden residue classes for n modulo p.
     */

    if prime == 2 || prime == 3 {
        let mut roots = Vec::new();

        for n in 0..prime {
            let n64 = n as u64;
            let value = (6 * n64 * n64 + 6 * n64 + 31) % p;

            if value == 0 {
                roots.push(n);
            }
        }

        return roots;
    }

    let rhs = (p - (177 % p)) % p;

    let Some(root_y) = tonelli_shanks_u64(rhs, p) else {
        return Vec::new();
    };

    let inv6 =
        small_mod_inverse_prime(6, p).expect("6 must be invertible for primes other than 2 and 3");

    let mut roots = Vec::with_capacity(2);

    let y1 = root_y;
    let y2 = if root_y == 0 { 0 } else { p - root_y };

    for y in [y1, y2] {
        let shifted = (y + p - (3 % p)) % p;
        let n_root = (shifted * inv6) % p;

        if !roots.contains(&(n_root as u32)) {
            roots.push(n_root as u32);
        }
    }

    roots
}

#[cfg(test)]
fn mark_structural_residue_classes(
    iterations: usize,
    n0_txt: &str,
    step_txt: &str,
    primes: &[u32],
) -> Result<Vec<bool>, String> {
    let mut composite = vec![false; iterations];

    for p in primes {
        let p64 = *p as u64;

        let bad_n_residues = max_bad_n_residues(*p);

        if bad_n_residues.is_empty() {
            continue;
        }

        let n0_mod = decimal_mod_u32(n0_txt, *p)? as u64;
        let step_mod = decimal_mod_u32(step_txt, *p)? as u64;

        if step_mod == 0 {
            if bad_n_residues.iter().any(|r| *r as u64 == n0_mod) {
                composite.fill(true);
            }

            continue;
        }

        let inv_step = small_mod_inverse_prime(step_mod, p64)
            .ok_or_else(|| format!("Cannot invert step modulo prime {}", p))?;

        for bad_n in bad_n_residues {
            let delta = (bad_n as u64 + p64 - n0_mod) % p64;
            let first_i = (delta * inv_step) % p64;

            let mut i = first_i as usize;

            while i < iterations {
                composite[i] = true;
                i += *p as usize;
            }
        }
    }

    Ok(composite)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_welcome();
        return;
    }

    let result = match args[1].as_str() {
        "welcome" => {
            print_welcome();
            Ok(())
        }
        "modes" => {
            print_modes();
            Ok(())
        }
        "privacy" => {
            print_privacy();
            Ok(())
        }
        "theory" => {
            print_theory_note();
            Ok(())
        }
        "explain-n" => {
            print_explain_n();
            Ok(())
        }
        "status" => {
            print_status();
            Ok(())
        }
        "discoveries" => {
            print_discoveries();
            Ok(())
        }
        "discoveries-all" => {
            print_discoveries_all();
            Ok(())
        }
        "gui-preview" => {
            print_gui_preview();
            Ok(())
        }
        "self-check" => self_check_mode(),
        "official-explain" => {
            print_official_explain();
            Ok(())
        }
        "official-status" => {
            print_official_status();
            Ok(())
        }
        "official-config" => official_config_mode(),
        "official-device" => official_device_mode(),
        "official-login-start" => official_login_start_mode(),
        "official-login-status" => official_login_status_mode(),
        "official-run-once" => {
            if let Some(challenge_id) = args.get(2) {
                official_run_once_mode(challenge_id.as_str())
            } else {
                Err("Missing challenge_id. Usage: max_prime_public_client official-run-once <challenge_id>".to_string())
            }
        }
        "official-get-work" => official_get_work_mode(),
        "official-participant-status" | "official-refresh-status" => {
            official_participant_status_mode()
        }
        "official-set-nickname" => {
            let nickname = if args.len() >= 3 {
                args[2..].join(" ")
            } else {
                "".to_string()
            };
            official_set_nickname_mode(&nickname)
        }
        "official-clear-nickname" => official_set_nickname_mode(""),
        "official-logout" => official_logout_mode(),
        "official-submit-result" => official_submit_result_mode(),
        "official-login-placeholder" => {
            print_official_login_placeholder();
            Ok(())
        }
        "official-preview" => {
            print_official_preview();
            Ok(())
        }
        "next" => {
            print_next();
            Ok(())
        }

        "local-demo" => {
            let iterations = parse_usize_arg(&args, 2, 1500);
            let n_digits = parse_usize_arg(&args, 3, 20);
            local_demo(iterations, n_digits)
        }
        "advanced-local-preview" => {
            let config_path = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("examples/local_advanced_experiment_example.json");
            preview_advanced_local(config_path)
        }
        "advanced-local" => {
            let config_path = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("examples/local_advanced_experiment_example.json");
            run_advanced_local(config_path)
        }
        "copy-local-prime" => {
            let idx = parse_usize_arg(&args, 2, 0);
            copy_local_prime(idx)
        }
        "clear-local-discoveries" => clear_local_discoveries(),
        "export-current-run" => export_current_run(),
        "export-local-discoveries" => export_local_discoveries(),
        "copy-local-sha" => {
            let idx = parse_usize_arg(&args, 2, 0);
            copy_local_sha(idx)
        }

        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("Unknown command: {}", other)),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {}", e);
        print_usage();
        std::process::exit(1);
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn general_prepared_miller_rabin_matches_reference() {
        let cases = [
            0u64, 1, 2, 3, 4, 5, 9, 17, 25, 37, 41, 97, 341, 561, 1_105, 65_537,
        ];
        for value in cases {
            let n = UBig::from(value);
            assert_eq!(
                is_probable_prime_ring_general(&n),
                is_probable_prime(&n),
                "n={value}"
            );
        }
        for _ in 0..32 {
            let n = random_odd_with_bits(257);
            assert_eq!(is_probable_prime_ring_general(&n), is_probable_prime(&n));
        }
    }

    #[test]
    fn seeded_random_odd_generation_is_reproducible_and_exact_width() {
        let mut first = rand::rngs::StdRng::seed_from_u64(42);
        let mut second = rand::rngs::StdRng::seed_from_u64(42);
        for bits in [64usize, 257, 3_318] {
            let a = random_odd_with_bits_from_rng(bits, &mut first);
            let b = random_odd_with_bits_from_rng(bits, &mut second);
            assert_eq!(a, b);
            assert_eq!(a.bit_len(), bits);
            assert_eq!(&a % UBig::from(2u32), UBig::from(1u32));
        }
    }

    #[test]
    fn optimized_random_presieve_matches_ubig_division() {
        let primes: Vec<u32> = primes_up_to(10_000)
            .into_iter()
            .filter(|&p| p != 2)
            .collect();
        let batches = compile_random_presieve(&primes);
        assert!(batches.len() < primes.len() / 2);
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for _ in 0..32 {
            let candidate = random_odd_with_bits_from_rng(521, &mut rng);
            let legacy = primes
                .iter()
                .any(|&p| &candidate % UBig::from(p) == UBig::from(0u32));
            assert_eq!(
                random_odd_rejected_by_presieve(&candidate, &batches),
                legacy
            );
        }
    }

    #[test]
    fn max_b_round_progressions_are_disjoint() {
        let starts: Vec<u64> = (0..3)
            .map(|round| round * MAX_RANDOM_MAX_ROUND_STRIDE)
            .collect();
        assert_eq!(starts, [0, 10_000_000, 20_000_000]);
        assert!(starts
            .windows(2)
            .all(|pair| pair[0] + (MAX_RANDOM_RESERVOIR as u64) < pair[1]));
    }

    #[test]
    fn general_prepared_miller_rabin_matches_pr12_max_engine() {
        let start =
            parse_ubig_decimal("MAX equivalence start", &format!("1{}", "0".repeat(149))).unwrap();
        let mut cursor = CrtCompCandidateCursor::new(&start, &UBig::from(1u32));
        for i in 0..64 {
            let candidate = cursor.at(i);
            assert_eq!(
                is_probable_prime_ring_general(candidate),
                is_probable_prime_ring_max(candidate),
                "MAX index={i}"
            );
        }
    }

    #[test]
    fn accepts_canonical_official_api_base() {
        assert!(validate_official_api_base(OFFICIAL_API_BASE).is_ok());
    }

    #[test]
    fn rejects_different_official_api_base() {
        assert!(validate_official_api_base("https://example.com/max/prime").is_err());
    }

    #[test]
    fn rejects_http_official_api_base() {
        assert!(validate_official_api_base("http://www.max-russo.com/max/prime").is_err());
    }

    #[test]
    fn rejects_different_official_api_host() {
        assert!(validate_official_api_base("https://max-russo.com/max/prime").is_err());
    }

    #[test]
    fn rejects_trailing_slash_in_official_api_base() {
        assert!(validate_official_api_base("https://www.max-russo.com/max/prime/").is_err());
    }

    #[test]
    fn invalid_official_api_base_error_does_not_echo_secrets() {
        let participant_token = "participant-secret";
        let api_base = format!("https://attacker.example/{participant_token}");
        let error = validate_official_api_base(&api_base).unwrap_err();

        assert!(!error.contains(participant_token));
        assert!(error.contains(OFFICIAL_API_BASE));
    }

    #[test]
    fn accepts_official_relative_heartbeat_endpoint() {
        assert_eq!(
            official_heartbeat_url(
                "api-prime-assignment-heartbeat.php",
                "https://www.max-russo.com/max/prime"
            )
            .unwrap(),
            "https://www.max-russo.com/max/prime/api-prime-assignment-heartbeat.php"
        );
    }

    #[test]
    fn accepts_https_same_origin_heartbeat_endpoint() {
        let endpoint = "https://www.max-russo.com/max/prime/api-prime-assignment-heartbeat.php";
        assert_eq!(
            official_heartbeat_url(endpoint, "https://www.max-russo.com/max/prime").unwrap(),
            endpoint
        );
    }

    #[test]
    fn rejects_http_heartbeat_endpoint() {
        let error = official_heartbeat_url(
            "http://www.max-russo.com/max/prime/api-prime-assignment-heartbeat.php",
            "https://www.max-russo.com/max/prime",
        )
        .unwrap_err();
        assert!(error.contains("HTTPS"));
    }

    #[test]
    fn rejects_https_cross_origin_heartbeat_endpoint() {
        let error = official_heartbeat_url(
            "https://attacker.example/api-prime-assignment-heartbeat.php",
            "https://www.max-russo.com/max/prime",
        )
        .unwrap_err();
        assert!(error.contains("API origin"));
    }

    #[test]
    fn invalid_heartbeat_error_does_not_echo_tokens() {
        let participant_token = "participant-secret";
        let assignment_token = "assignment-secret";
        let endpoint = format!("http://attacker.example/{participant_token}/{assignment_token}");
        let error =
            official_heartbeat_url(&endpoint, "https://www.max-russo.com/max/prime").unwrap_err();

        assert!(!error.contains(participant_token));
        assert!(!error.contains(assignment_token));
    }

    #[test]
    fn get_work_url_does_not_contain_participant_token() {
        let base = "https://www.max-russo.com/max/prime";
        let challenge_id = "challenge";
        let client_device_id = "device";
        let url = format!(
            "{}/api-prime-get-work.php?challenge_id={}&client_device_id={}",
            base,
            official_url_encode(challenge_id),
            official_url_encode(client_device_id)
        );

        assert!(!url.contains("participant_token"));
        assert!(!url.contains("participant-secret"));
        assert_eq!(
            participant_authorization("participant-secret"),
            "Bearer participant-secret"
        );
    }

    #[test]
    fn redacts_secrets_recursively() {
        let input = serde_json::json!({
            "assignment": {"assignment_token": "a", "nested": [{"api_secret": "b"}]},
            "participant_token": "c",
            "safe": "visible"
        });
        let redacted = official_redact_secrets(&input);
        let text = redacted.to_string();

        assert!(!text.contains("\"a\"") && !text.contains("\"b\"") && !text.contains("\"c\""));
        assert_eq!(redacted["safe"], "visible");
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_storage_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("max-prime-security-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_private_dir(dir.to_str().unwrap()).unwrap();
        let file = dir.join("session.json");
        write_sensitive_text(file.to_str().unwrap(), "secret").unwrap();

        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

// This module deliberately lives next to the current engine instead of being a
// second implementation used by production.  The functions above are the
// frozen oracle that future engine changes must continue to match.
#[cfg(test)]
mod engine_equivalence_tests {
    use super::*;

    #[test]
    fn max_euler_jacobi_and_prepared_ring_agree() {
        // For prime MAX candidates:
        // 3^((N-1)/2) mod N == N-1.
        // The corresponding base-2 sign is determined by N mod 8.
        let one = UBig::from(1u32);
        let two = UBig::from(2u32);
        let three = UBig::from(3u32);
        let eight = UBig::from(8u32);

        let mut checked = 0usize;

        for n in 0..400u64 {
            let candidate = n_candidate_from_n(&UBig::from(n));

            assert_eq!(
                is_probable_prime(&candidate),
                is_probable_prime_ring_max(&candidate)
            );

            if !is_probable_prime(&candidate) {
                continue;
            }

            checked += 1;

            let exp = (&candidate - &one) / &two;

            assert_eq!(modpow_dashu(&three, &exp, &candidate), &candidate - &one);

            let expected_two = if &candidate % &eight == UBig::from(7u32) {
                one.clone()
            } else {
                &candidate - &one
            };

            assert_eq!(modpow_dashu(&two, &exp, &candidate), expected_two);
        }

        assert!(checked >= 5);
    }

    #[test]
    fn fixed_time_ring_equivalence_test() {
        fn check_progression(name: &str, start: &UBig, step: &UBig, count: usize) {
            let mut original_hits = Vec::new();
            let mut optimized_hits = Vec::new();

            let mut cursor = CrtCompCandidateCursor::new(start, step);

            for i in 0..count {
                let candidate = cursor.at(i).clone();

                assert_eq!(
                    &candidate % UBig::from(12u32),
                    UBig::from(7u32),
                    "{name}: unexpected MAX residue"
                );

                let original = is_probable_prime(&candidate);

                let optimized = is_probable_prime_ring_max(&candidate);

                assert_eq!(original, optimized, "{name}: ring mismatch at {i}");

                if crtcomp_pass_small_primes(&candidate) {
                    assert_eq!(
                        original,
                        crtcomp_mr_only(&candidate),
                        "{name}: MR-only mismatch at {i}"
                    );
                }

                if original {
                    let digest = Sha256::digest(candidate.to_string().as_bytes());
                    original_hits.push((i, format!("{digest:x}")));
                }

                if optimized {
                    let digest = Sha256::digest(candidate.to_string().as_bytes());
                    optimized_hits.push((i, format!("{digest:x}")));
                }
            }

            assert_eq!(
                original_hits, optimized_hits,
                "{name}: hit index/hash mismatch"
            );
        }

        let b_start = parse_ubig_decimal("B test start", &format!("1{}", "0".repeat(149))).unwrap();

        check_progression("B_300_DIGITS", &b_start, &UBig::from(1u32), 80);

        let b_large =
            parse_ubig_decimal("B large test start", &format!("1{}", "0".repeat(499))).unwrap();

        check_progression("B_1000_DIGITS", &b_large, &UBig::from(1u32), 24);

        let (m, r) = crtcomp_build_safecrt50();

        let d_raw =
            parse_ubig_decimal("D raw test start", &format!("1{}", "0".repeat(249))).unwrap();

        let d_start = &r + &m * d_raw;

        check_progression("D_SAFECRT50", &d_start, &m, 48);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CandidateTrace {
        survivor_indices: Vec<usize>,
        n_values: Vec<UBig>,
        candidates: Vec<UBig>,
        mr_results: Vec<bool>,
        hit_indices: Vec<usize>,
    }

    fn candidate_is_divisible_directly(n: &UBig, p: u64) -> bool {
        n_candidate_from_n(n) % UBig::from(p) == UBig::from(0u32)
    }

    #[test]
    fn direct_ubig_mod_matches_legacy_decimal_reduction() {
        let values = [
            UBig::from(0u32),
            UBig::from(1u32),
            UBig::from(u64::MAX),
            parse_ubig_decimal("large", "9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999").unwrap(),
        ];
        let moduli = [2u64, 3, 31, 59, 751, 65_537, 4_294_967_291, u64::MAX - 58];
        for value in &values {
            for &p in &moduli {
                assert_eq!(
                    crtcomp_ubig_mod_u64(value, p),
                    crtcomp_ubig_mod_u64_legacy(value, p)
                );
            }
        }
        for &p in &moduli {
            for value in [
                UBig::from(p - 1),
                UBig::from(p),
                UBig::from(p) + UBig::from(1u32),
            ] {
                assert_eq!(
                    crtcomp_ubig_mod_u64(&value, p),
                    crtcomp_ubig_mod_u64_legacy(&value, p)
                );
            }
        }
    }

    fn direct_mask(
        iterations: usize,
        start: &UBig,
        step: &UBig,
        primes: &[u64],
        complementary_safecrt50: bool,
    ) -> Vec<bool> {
        (0..iterations)
            .map(|i| {
                let n = start + step * UBig::from(i as u64);
                primes.iter().any(|&p| {
                    (!complementary_safecrt50 || !CRTCOMP_SAFECRT50.contains(&p))
                        && candidate_is_divisible_directly(&n, p)
                })
            })
            .collect()
    }

    fn oracle_trace(start: &UBig, step: &UBig, mask: &[bool]) -> CandidateTrace {
        let survivor_indices: Vec<_> = mask
            .iter()
            .enumerate()
            .filter_map(|(i, rejected)| (!rejected).then_some(i))
            .collect();
        let n_values: Vec<_> = survivor_indices
            .iter()
            .map(|&i| start + step * UBig::from(i as u64))
            .collect();
        let candidates: Vec<_> = n_values.iter().map(n_candidate_from_n).collect();
        let mr_results: Vec<_> = candidates.iter().map(is_probable_prime).collect();
        let hit_indices = survivor_indices
            .iter()
            .zip(&mr_results)
            .filter_map(|(&i, &hit)| hit.then_some(i))
            .collect();

        CandidateTrace {
            survivor_indices,
            n_values,
            candidates,
            mr_results,
            hit_indices,
        }
    }

    fn engine_trace(start: &UBig, step: &UBig, mask: &[bool]) -> CandidateTrace {
        let mut survivor_indices = Vec::new();
        let mut n_values = Vec::new();
        let mut candidates = Vec::new();
        let mut mr_results = Vec::new();
        let mut hit_indices = Vec::new();

        let stats = crtcomp_run_arm_core(
            mask.len(),
            start,
            step,
            Some(mask),
            0.0,
            |i, n, candidate, probable_prime| {
                survivor_indices.push(i);
                n_values.push(n.clone());
                candidates.push(candidate.clone());
                mr_results.push(probable_prime);
                if probable_prime {
                    hit_indices.push(i);
                }
            },
        );

        assert_eq!(stats.built, survivor_indices.len());
        assert_eq!(stats.rejected_before_build + stats.built, mask.len());
        assert_eq!(stats.hits, hit_indices.len());

        CandidateTrace {
            survivor_indices,
            n_values,
            candidates,
            mr_results,
            hit_indices,
        }
    }

    fn segmented_mask(
        total: usize,
        segment_size: usize,
        start: &UBig,
        step: &UBig,
        primes: &[u64],
        complementary_safecrt50: bool,
    ) -> Vec<bool> {
        let mut result = Vec::with_capacity(total);
        let mut offset = 0usize;
        while offset < total {
            let len = segment_size.min(total - offset);
            let segment_start = start + step * UBig::from(offset as u64);
            result.extend(crtcomp_mark_structural(
                len,
                &segment_start,
                step,
                primes,
                complementary_safecrt50,
            ));
            offset += len;
        }
        result
    }

    fn assert_persistent_sequence(
        lengths: &[usize],
        start: &UBig,
        step: &UBig,
        primes: &[u64],
        complementary_safecrt50: bool,
    ) {
        let total: usize = lengths.iter().sum();
        let schedule = crtcomp_compile_schedule(primes, step, complementary_safecrt50);
        let one_shot = crtcomp_mark_compiled(total, start, &schedule);
        let mut legacy_segments = Vec::with_capacity(total);
        let mut persistent_segments = Vec::with_capacity(total);
        let mut state = crtcomp_initialize_persistent_state(start, &schedule);
        let mut offset = 0usize;

        for &len in lengths {
            let segment_start = start + step * UBig::from(offset as u64);
            legacy_segments.extend(crtcomp_mark_compiled(len, &segment_start, &schedule));
            persistent_segments.extend(crtcomp_mark_persistent(len, &schedule, &mut state));
            offset += len;
        }
        assert_eq!(one_shot, legacy_segments, "legacy concatenation mismatch");
        assert_eq!(
            one_shot, persistent_segments,
            "persistent concatenation mismatch"
        );
    }

    #[test]
    fn max_formula_and_square_identity_hold() {
        let fixed = [0u64, 1, 2, 7, 31, 999, 65_537, 1_000_003];
        for n64 in fixed {
            let n = UBig::from(n64);
            let candidate = n_candidate_from_n(&n);
            let expanded = UBig::from(6u32) * &n * &n + UBig::from(6u32) * &n + UBig::from(31u32);
            let square_term = UBig::from(6u32) * &n + UBig::from(3u32);
            assert_eq!(candidate, expanded, "expanded formula failed for n={n64}");
            assert_eq!(
                UBig::from(6u32) * &candidate,
                &square_term * &square_term + UBig::from(177u32),
                "square identity failed for n={n64}"
            );
        }
    }

    #[test]
    fn structural_residue_classes_match_brute_force() {
        for p in crtcomp_primes_up_to(2_000) {
            let mut calculated = crtcomp_bad_n_classes(p);
            calculated.sort_unstable();
            let brute_force: Vec<_> = (0..p)
                .filter(|&n| candidate_is_divisible_directly(&UBig::from(n), p))
                .collect();
            assert_eq!(calculated, brute_force, "forbidden classes modulo {p}");
            for n in calculated {
                assert!(
                    candidate_is_divisible_directly(&UBig::from(n), p),
                    "class {n} modulo {p}"
                );
                for k in [0u64, 1, 7, 101] {
                    assert!(candidate_is_divisible_directly(&UBig::from(n + k * p), p));
                }
            }
        }
    }

    #[test]
    fn structural_masks_match_direct_oracle_for_starts_steps_and_limits() {
        let configurations = [
            ("0", "1", 37usize),
            ("17", "7", 127),
            ("123456789012345678901234567890", "19", 509),
            ("987654321098765432109876543210", "210", 1_009),
        ];
        for (start_text, step_text, limit) in configurations {
            let start = parse_ubig_decimal("test start", start_text).unwrap();
            let step = parse_ubig_decimal("test step", step_text).unwrap();
            let primes = crtcomp_primes_up_to(limit);
            let actual = crtcomp_mark_structural(1_337, &start, &step, &primes, false);
            assert_eq!(actual, direct_mask(1_337, &start, &step, &primes, false));

            let primes32: Vec<_> = primes.iter().map(|&p| p as u32).collect();
            assert_eq!(
                actual,
                mark_structural_residue_classes(1_337, start_text, step_text, &primes32).unwrap()
            );
        }
    }

    #[test]
    fn structural_mask_is_independent_of_segmentation() {
        let start = parse_ubig_decimal("test start", "123456789012345678901").unwrap();
        let step = UBig::from(37u32);
        let primes = crtcomp_primes_up_to(1_009);
        let whole = crtcomp_mark_structural(4_096, &start, &step, &primes, false);
        let whole_trace = engine_trace(&start, &step, &whole[..256]);
        for segment_size in [17usize, 64, 127, 1_000] {
            let segmented = segmented_mask(4_096, segment_size, &start, &step, &primes, false);
            assert_eq!(
                whole, segmented,
                "byte-for-byte mask mismatch for segment size {segment_size}"
            );
            assert_eq!(whole_trace, engine_trace(&start, &step, &segmented[..256]));
        }
    }

    #[test]
    fn incremental_candidate_cursor_matches_original_for_skips_windows_b_and_d() {
        let big_start =
            parse_ubig_decimal("incremental B start", &format!("1{}", "0".repeat(499))).unwrap();
        let (m, r) = crtcomp_build_safecrt50();
        let d_start = &r + &m * &big_start;
        let cases = [
            ("B-small", UBig::from(17u32), UBig::from(1u32), false),
            ("B-big", big_start.clone(), UBig::from(37u32), false),
            ("D", d_start, &m * UBig::from(11u32), true),
            ("zero-step", UBig::from(0u32), UBig::from(0u32), false),
        ];
        let primes = crtcomp_primes_up_to(509);
        for (name, start, step, complementary) in cases {
            for window_len in [1usize, 17, 64, 127, 257] {
                let mut window_start = start.clone();
                for window in 0..3usize {
                    let actual_mask = crtcomp_mark_structural(
                        window_len,
                        &window_start,
                        &step,
                        &primes,
                        complementary,
                    );
                    let masks = [
                        actual_mask,
                        (0..window_len).map(|i| i % 5 == 0 || i % 7 == 0).collect(),
                        vec![false; window_len],
                        vec![true; window_len],
                    ];
                    for mask in masks {
                        let mut cursor = CrtCompCandidateCursor::new(&window_start, &step);
                        for (i, rejected) in mask.iter().enumerate() {
                            if *rejected {
                                continue;
                            }
                            let n = &window_start + &step * UBig::from(i as u64);
                            let oracle = n_candidate_from_n(&n);
                            assert_eq!(
                                cursor.at(i),
                                &oracle,
                                "{name} window={window} len={window_len} i={i}"
                            );
                            // Same primality result, including 0 and repeated n.
                            if name == "B-small" && i < 8 {
                                assert_eq!(
                                    is_probable_prime(cursor.at(i)),
                                    is_probable_prime(&oracle)
                                );
                            }
                        }
                    }
                    window_start += &step * UBig::from(window_len as u64);
                }
            }
        }
    }

    #[test]
    fn persistent_offsets_match_compiled_recompute_for_variable_segments_b_and_d() {
        let sequences: &[&[usize]] = &[
            &[17, 64, 127, 1_000],
            &[1, 1, 1, 1, 1],
            &[1_000, 17, 4_096, 3, 511],
        ];
        let primes = crtcomp_primes_up_to(2_003);
        let b_start = parse_ubig_decimal("B start", "123456789012345678901234567890").unwrap();
        let b_step = UBig::from(37u32);
        let (m, r) = crtcomp_build_safecrt50();
        let d_start = &r + &m * UBig::from(43u32);
        let d_step = &m * UBig::from(11u32);

        for lengths in sequences {
            assert_persistent_sequence(lengths, &b_start, &b_step, &primes, false);
            assert_persistent_sequence(lengths, &d_start, &d_step, &primes, true);
        }
    }

    #[test]
    fn persistent_offsets_cover_empty_degenerate_and_named_prime_cases() {
        let start = UBig::from(59u32);
        let step_zero = UBig::from(0u32);
        assert_persistent_sequence(&[1, 17, 3], &start, &step_zero, &[], false);
        // Includes p=2, p=3, p=59, entries with zero/one/two forbidden
        // classes, and a segment both shorter and longer than each small p.
        assert_persistent_sequence(
            &[1, 64, 7, 127],
            &start,
            &step_zero,
            &[2, 3, 5, 7, 31, 59],
            false,
        );

        let step = UBig::from(59u32);
        assert_persistent_sequence(
            &[17, 1, 127, 3],
            &UBig::from(7u32),
            &step,
            &[2, 3, 5, 59],
            false,
        );
    }

    #[test]
    fn safecrt50_progression_and_complementary_sieve_match_oracles() {
        let (m, r) = crtcomp_build_safecrt50();
        crtcomp_validate_safecrt50(&m, &r).unwrap();
        for p in CRTCOMP_SAFECRT50 {
            assert_eq!(crtcomp_ubig_mod_u64(&m, p), 0, "M modulo {p}");
        }

        let primes = crtcomp_primes_up_to(2_003);
        for raw_start in [0u64, 1, 29, 10_007] {
            for raw_step in [1u64, 7, 64] {
                let effective_start = &r + &m * UBig::from(raw_start);
                let effective_step = &m * UBig::from(raw_step);
                for i in 0..257u64 {
                    let n = &effective_start + &effective_step * UBig::from(i);
                    for p in CRTCOMP_SAFECRT50 {
                        assert_ne!(
                            n_candidate_from_n(&n) % UBig::from(p),
                            UBig::from(0u32),
                            "SAFECRT50 candidate {i} divisible modulo {p}"
                        );
                    }
                }

                let actual =
                    crtcomp_mark_structural(513, &effective_start, &effective_step, &primes, true);
                assert_eq!(
                    actual,
                    direct_mask(513, &effective_start, &effective_step, &primes, true)
                );
            }
        }
    }

    #[test]
    fn complementary_mask_is_independent_of_segmentation() {
        let (m, r) = crtcomp_build_safecrt50();
        let start = &r + &m * UBig::from(43u32);
        let step = &m * UBig::from(11u32);
        let primes = crtcomp_primes_up_to(2_003);
        let whole = crtcomp_mark_structural(4_096, &start, &step, &primes, true);
        // A short prefix is enough to compare every expensive BigInt/MR field;
        // the complete 4096-entry mask is still compared byte-for-byte above.
        let whole_trace = engine_trace(&start, &step, &whole[..64]);
        for segment_size in [17usize, 64, 127, 1_000] {
            let segmented = segmented_mask(4_096, segment_size, &start, &step, &primes, true);
            assert_eq!(
                whole, segmented,
                "complementary mask mismatch for segment size {segment_size}"
            );
            assert_eq!(whole_trace, engine_trace(&start, &step, &segmented[..64]));
        }
    }

    #[test]
    fn b_and_d_pipeline_traces_match_current_engine_oracle() {
        let b_start = UBig::from(10_000u32);
        let b_step = UBig::from(13u32);
        let b_primes = crtcomp_primes_up_to(509);
        let b_mask = crtcomp_mark_structural(750, &b_start, &b_step, &b_primes, false);
        assert_eq!(
            engine_trace(&b_start, &b_step, &b_mask),
            oracle_trace(&b_start, &b_step, &b_mask)
        );

        let (m, r) = crtcomp_build_safecrt50();
        let d_start = &r + &m * UBig::from(3u32);
        let d_step = &m * UBig::from(5u32);
        let d_primes = crtcomp_primes_up_to(1_009);
        let d_mask = crtcomp_mark_structural(300, &d_start, &d_step, &d_primes, true);
        assert_eq!(
            engine_trace(&d_start, &d_step, &d_mask),
            oracle_trace(&d_start, &d_step, &d_mask)
        );
    }
}

// Test privati di equivalenza. Nessuna connessione al server.
#[cfg(test)]
mod private_engine_scale_tests {
    use super::*;
    use std::time::Instant;

    fn cfg() -> OfficialClientConfig {
        serde_json::from_value(serde_json::json!({
            "mode": "offline",
            "official_api_base": "https://www.max-russo.com/max/prime",
            "client_device_id": "OFFLINE",
            "participant_id": "OFFLINE",
            "participant_token": "TEST-ONLY",
            "participant_token_status": "registered",
            "token_id": "",
            "max_id": "",
            "max_id_hash": "",
            "public_nickname": "",
            "public_display_name": "",
            "max_login_status": "",
            "registration_id": "",
            "registration_status": "",
            "login_session_id": "",
            "login_session_status": "",
            "login_started_at_unix": 0,
            "login_expires_at_unix": 0,
            "qr_text": "",
            "deeplink": "",
            "callback_url": "",
            "created_at_unix": 0,
            "updated_at_unix": 0,
            "note": "offline test"
        }))
        .unwrap()
    }

    fn fixture(
        name: &str,
        n_digits: usize,
        iterations: usize,
        test_n: bool,
        test_d: bool,
        crt: bool,
        m: u32,
        r: u32,
    ) -> serde_json::Value {
        let n0 = format!("2{}", "0".repeat(n_digits - 1));

        serde_json::json!({
            "assignment": {
                "assignment_id": format!("TEST-{name}"),
                "assignment_token": "TEST-ONLY"
            },
            "work_unit": {
                "challenge_id": "OFFLINE",
                "campaign_id": "OFFLINE",
                "work_unit_id": name,
                "work_unit_index": 1,
                "n0": n0,
                "step": "17",
                "start_i": 11,
                "iterations": iterations,
                "test_n": test_n,
                "test_d": test_d,
                "filter": {
                    "enabled": crt,
                    "modulus_m": m.to_string(),
                    "remainder_r": r.to_string(),
                    "original_moduli": [],
                    "original_remainders": []
                }
            }
        })
    }

    fn normalize(mut v: serde_json::Value) -> serde_json::Value {
        v["elapsed_s"] = serde_json::json!(0.0);
        v["result"]["elapsed_s"] = serde_json::json!(0.0);
        v["result_json"]["elapsed_s"] = serde_json::json!(0.0);
        v
    }

    fn compare(
        name: &str,
        n_digits: usize,
        iterations: usize,
        test_n: bool,
        test_d: bool,
        crt: bool,
        m: u32,
        r: u32,
    ) {
        let work = fixture(name, n_digits, iterations, test_n, test_d, crt, m, r);
        let config = cfg();

        let t0 = Instant::now();
        let old = official_compute_work_unit_payload_legacy(&work, &config).unwrap();
        let old_s = t0.elapsed().as_secs_f64();

        let t1 = Instant::now();
        let new = official_compute_work_unit_payload_optimized(&work, &config).unwrap();
        let new_s = t1.elapsed().as_secs_f64();

        assert_eq!(
            normalize(old.clone()),
            normalize(new.clone()),
            "Payload mismatch in {name}"
        );

        println!(
            "CASE={} EQUIVALENCE=OK \
             N_DIGITS={} ITERATIONS={} \
             HITS={} LEGACY_S={:.6} \
             OPT_S={:.6} SPEEDUP={:.4}x",
            name,
            n_digits,
            iterations,
            old["hits"].as_array().unwrap().len(),
            old_s,
            new_s,
            old_s / new_s,
        );
    }

    #[test]
    #[ignore = "Offline official small-package regression"]
    fn official_small_package_sieve_regression() {
        let config = cfg();

        let mut cases = vec![
            (
                "2000_CRT",
                fixture("OFFICIAL-2000-CRT", 1000, 25, true, false, true, 101, 3),
            ),
            (
                "2000_NO_CRT",
                fixture("OFFICIAL-2000-NO-CRT", 1000, 25, true, false, false, 1, 0),
            ),
            (
                "5000_CRT",
                fixture("OFFICIAL-5000-CRT", 2500, 25, true, false, true, 101, 3),
            ),
        ];

        let mut positive = fixture("OFFICIAL-120-POSITIVE", 60, 25, true, false, false, 1, 0);

        positive["work_unit"]["n0"] = serde_json::json!(format!("2{}", "0".repeat(59)));

        positive["work_unit"]["step"] = serde_json::json!("17");

        positive["work_unit"]["start_i"] = serde_json::json!(0);

        positive["work_unit"]["iterations"] = serde_json::json!(25);

        positive["work_unit"]["filter"]["enabled"] = serde_json::json!(false);

        positive["work_unit"]["filter"]["modulus_m"] = serde_json::json!("1");

        positive["work_unit"]["filter"]["remainder_r"] = serde_json::json!("0");

        cases.push(("120_POSITIVE", positive));

        for (name, work) in cases {
            let start = std::time::Instant::now();

            let legacy = official_compute_work_unit_payload_legacy(&work, &config).unwrap();

            let legacy_s = start.elapsed().as_secs_f64();

            let start = std::time::Instant::now();

            let optimized = official_compute_work_unit_payload_optimized(&work, &config).unwrap();

            let optimized_s = start.elapsed().as_secs_f64();

            // La funzione normalize già esistente
            // elimina soltanto i tempi di esecuzione.
            assert_eq!(
                normalize(legacy.clone()),
                normalize(optimized.clone()),
                "Official JSON differs: {name}"
            );

            if name == "120_POSITIVE" {
                let expected_sha =
                    "c03def80bc187f910a449aacbb6d81cccfbb5e6e576efba9681d6b0976c222e9";

                let hits = optimized["hits"].as_array().unwrap();

                assert!(
                    hits.iter().any(|hit| {
                        hit["candidate_type"] == "N"
                            && hit["i"] == 12
                            && hit["sha256"] == expected_sha
                    }),
                    "Known positive hit missing"
                );

                println!("OFFICIAL_POSITIVE_SHA256=OK");
            }

            println!(
                "OFFICIAL_CASE={} LEGACY_S={:.6} OPTIMIZED_S={:.6} SPEEDUP={:.3}x HITS={} EQUIVALENCE=OK",
                name,
                legacy_s,
                optimized_s,
                legacy_s / optimized_s,
                optimized["hits"].as_array().unwrap().len()
            );
        }

        println!("OFFICIAL_SMALL_PACKAGE_ALL_CASES=OK");
    }

    #[test]
    fn offline_dispatch_selects_requested_engine() {
        let work = fixture("OFFLINE-DISPATCH", 30, 31, true, true, true, 101, 3);

        let config = cfg();

        let selected = true;

        let actual = official_compute_work_unit_payload(&work, &config).unwrap();

        let reference = if selected {
            official_compute_work_unit_payload_optimized(&work, &config).unwrap()
        } else {
            official_compute_work_unit_payload_legacy(&work, &config).unwrap()
        };

        assert_eq!(
            normalize(actual),
            normalize(reference),
            "Dispatcher returned a different payload"
        );

        println!(
            "OFFLINE_DISPATCH=OK SELECTED={}",
            if selected { "OPTIMIZED" } else { "LEGACY" }
        );
    }

    #[test]
    fn small_official_regression() {
        compare("SMALL_N_AND_D", 30, 31, true, true, false, 1, 0);

        compare("SMALL_ARBITRARY_CRT", 30, 31, true, true, true, 101, 3);

        compare("SMALL_D_ONLY", 30, 25, false, true, true, 77, 13);

        println!("SMALL_CASES=OK");
    }

    #[test]
    #[ignore]
    fn large_official_scale_regression() {
        // Circa 2000 cifre: il crivello viene attivato.
        compare("2000_N_NO_CRT", 1000, 500, true, false, false, 1, 0);

        compare("2000_N_ARBITRARY_CRT", 1000, 500, true, false, true, 101, 3);

        // Le prove successive controllano soprattutto
        // equivalenza e compatibilita su grandi numeri.
        compare("5000_N", 2500, 40, true, false, false, 1, 0);

        compare(
            "5000_N_AND_D_ARBITRARY_CRT",
            2500,
            25,
            true,
            true,
            true,
            101,
            3,
        );

        compare("10000_N_AND_D", 5000, 6, true, true, false, 1, 0);

        compare("10000_N_ARBITRARY_CRT", 5000, 6, true, false, true, 101, 3);

        println!("LARGE_SCALE_CASES=OK");
    }
}

#[cfg(test)]
mod private_sieve_reuse_25_lab {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore = "Run explicitly: isolated 25-package benchmark"]
    fn compare_fresh_shared_and_persistent_sieve() {
        const PACKAGES: usize = 8;
        const PACKAGE_SIZE: usize = 25;

        // Ordine non consecutivo: simula pacchetti
        // distribuiti che arrivano fuori sequenza.
        const RANDOM_ORDER: [usize; PACKAGES] = [3, 0, 7, 1, 5, 2, 6, 4];

        let limit = std::env::var("MAX_PRIME_SIEVE_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(500_000);

        assert!((100..=5_000_000).contains(&limit));

        let n0 = parse_ubig_decimal("lab n0", &format!("2{}", "0".repeat(999))).unwrap();

        let m = UBig::from(101u32);
        let r = UBig::from(3u32);

        let base = &r + &m * &n0;
        let step = &m * UBig::from(17u32);

        let total = PACKAGES * PACKAGE_SIZE;

        println!("SIEVE_REUSE_25_LAB=START");
        println!("packages={PACKAGES}");
        println!("package_size={PACKAGE_SIZE}");
        println!("positions={total}");
        println!("sieve_limit={limit}");
        println!(
            "initial_N_digits={}",
            decimal_digits(&n_candidate_from_n(&base))
        );

        let starts: Vec<UBig> = (0..PACKAGES)
            .map(|w| &base + &step * UBig::from((w * PACKAGE_SIZE) as u64))
            .collect();

        println!("=== PRIME TABLE ===");

        let table_started = Instant::now();
        let primes = crtcomp_primes_up_to(limit);
        let table_s = table_started.elapsed().as_secs_f64();

        println!("prime_count={}", primes.len());
        println!("prime_table_s={table_s:.6}");

        println!("=== FRESH SIEVE PER PACKAGE ===");

        let fresh_started = Instant::now();

        let fresh: Vec<Vec<bool>> = starts
            .iter()
            .map(|start| {
                let schedule = crtcomp_compile_schedule(&primes, &step, false);

                crtcomp_mark_compiled(PACKAGE_SIZE, start, &schedule)
            })
            .collect();

        let fresh_s = fresh_started.elapsed().as_secs_f64();

        println!("fresh_compile_and_mark_s={fresh_s:.6}");

        println!("=== SHARED SCHEDULE: RANDOM ORDER ===");

        let shared_started = Instant::now();

        let schedule = crtcomp_compile_schedule(&primes, &step, false);

        let shared_build_s = shared_started.elapsed().as_secs_f64();

        let shared_mark_started = Instant::now();

        let mut random_masks = vec![Vec::<bool>::new(); PACKAGES];

        for &window in &RANDOM_ORDER {
            random_masks[window] = crtcomp_mark_compiled(PACKAGE_SIZE, &starts[window], &schedule);
        }

        let shared_mark_s = shared_mark_started.elapsed().as_secs_f64();

        assert_eq!(fresh, random_masks, "Random-order shared schedule differs");

        println!("shared_schedule_build_s={shared_build_s:.6}");
        println!("shared_random_mark_s={shared_mark_s:.6}");

        println!("RANDOM_ORDER_MASKS_EQUAL=YES");

        println!("=== PERSISTENT: CONSECUTIVE WINDOWS ===");

        let persistent_started = Instant::now();

        let mut persistent_state = crtcomp_initialize_persistent_state(&base, &schedule);

        let persistent_init_s = persistent_started.elapsed().as_secs_f64();

        let persistent_mark_started = Instant::now();

        let persistent_masks: Vec<Vec<bool>> = (0..PACKAGES)
            .map(|_| crtcomp_mark_persistent(PACKAGE_SIZE, &schedule, &mut persistent_state))
            .collect();

        let persistent_mark_s = persistent_mark_started.elapsed().as_secs_f64();

        assert_eq!(fresh, persistent_masks, "Persistent masks differ");

        println!("persistent_state_init_s={persistent_init_s:.6}");
        println!("persistent_mark_s={persistent_mark_s:.6}");

        println!("PERSISTENT_MASKS_EQUAL=YES");

        println!("=== COUNT SURVIVORS ===");

        let rejected = fresh.iter().flatten().filter(|&&bad| bad).count();

        let survivors = total - rejected;

        println!("rejected={rejected}");
        println!("survivors={survivors}");

        println!("=== MILLER-RABIN EQUIVALENCE ===");

        // Riferimento senza crivello:
        // tutti i 200 candidati vengono verificati.
        let baseline_started = Instant::now();

        let mut baseline_hits = Vec::new();

        for i in 0..total {
            let effective = &base + &step * UBig::from(i as u64);

            let candidate = n_candidate_from_n(&effective);

            if is_probable_prime_ring_max(&candidate) {
                baseline_hits.push((i, sha256_decimal(&candidate)));
            }
        }

        let baseline_mr_s = baseline_started.elapsed().as_secs_f64();

        // Stessi 200 indici: saltiamo soltanto
        // quelli eliminati dal crivello.
        let survivor_started = Instant::now();

        let mut sieved_hits = Vec::new();

        for i in 0..total {
            if fresh[i / PACKAGE_SIZE][i % PACKAGE_SIZE] {
                continue;
            }

            let effective = &base + &step * UBig::from(i as u64);

            let candidate = n_candidate_from_n(&effective);

            if is_probable_prime_ring_max(&candidate) {
                sieved_hits.push((i, sha256_decimal(&candidate)));
            }
        }

        let survivor_mr_s = survivor_started.elapsed().as_secs_f64();

        assert_eq!(baseline_hits, sieved_hits, "Hit indices or SHA-256 differ");

        println!("baseline_mr_s={baseline_mr_s:.6}");
        println!("survivors_mr_s={survivor_mr_s:.6}");
        println!("hits={}", baseline_hits.len());
        println!("HITS_AND_SHA256_EQUAL=YES");

        println!("=== COST MODEL FOR 8 PACKAGES ===");

        let fresh_total = table_s + fresh_s + survivor_mr_s;

        let shared_random_total = table_s + shared_build_s + shared_mark_s + survivor_mr_s;

        let persistent_total =
            table_s + shared_build_s + persistent_init_s + persistent_mark_s + survivor_mr_s;

        println!("fresh_total_model_s={fresh_total:.6}");
        println!("shared_random_total_model_s={shared_random_total:.6}");
        println!("persistent_total_model_s={persistent_total:.6}");
        println!("no_sieve_model_s={baseline_mr_s:.6}");

        println!(
            "fresh_over_shared_random={:.6}x",
            fresh_total / shared_random_total
        );

        println!(
            "fresh_over_persistent={:.6}x",
            fresh_total / persistent_total
        );

        println!(
            "no_sieve_over_shared_random={:.6}x",
            baseline_mr_s / shared_random_total
        );

        println!(
            "no_sieve_over_persistent={:.6}x",
            baseline_mr_s / persistent_total
        );

        println!("ALL_MASKS_EQUAL=YES");
        println!("SIEVE_REUSE_25_LAB=OK");
        println!("NOTE: isolated cost model, not official GUI timing");
        println!("NOTE: memory cache cannot survive separate CLI processes");
    }
}
