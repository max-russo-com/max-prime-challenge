use dashu_int::UBig;
use rand::Rng;
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

    for i in 0..cfg.iterations {
        let n_raw = &n0 + (&step * UBig::from(i as u64));

        let n_effective = if resolved_filter.enabled {
            &remainder_r + (&modulus_m * &n_raw)
        } else {
            n_raw.clone()
        };

        if cfg.test_n {
            let candidate = n_candidate_from_n(&n_effective);
            let digits = decimal_digits(&candidate);
            expected_n_primes += expected_prime_probability_from_digits(digits);

            if is_probable_prime(&candidate) {
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

            if is_probable_prime(&candidate) {
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

fn official_compute_work_unit_payload(
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
