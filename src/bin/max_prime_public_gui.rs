#![allow(dead_code)]
use eframe::egui;
use qrcode::{Color, QrCode};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

const OFFICIAL_CLIENT_CONFIG_PATH: &str = "app_state/official_client_config.json";
const CURRENT_RUN_STATE_PATH: &str = "app_state/current_run.json";
const LOCAL_DISCOVERIES_PATH: &str = "discoveries/local_discoveries.json";
const OFFICIAL_CONTINUOUS_MAX_PACKAGES: usize = 1_000_000;
const LAST_OFFICIAL_OUTCOME_PATH: &str = "app_state/last_official_outcome.json";

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Home,
    AdvancedLocal,
    OfficialMode,
    SelfCheck,
}

struct MaxPrimeGuiApp {
    tab: Tab,
    theme_dark: bool,
    status_message: String,
    advanced_preview_text: String,
    self_check_text: String,
    custom_experiment_id: String,
    custom_n0: String,
    custom_step: String,
    custom_iterations: String,
    custom_test_n: bool,
    custom_test_d: bool,
    custom_filter_mode: String,
    custom_m: String,
    custom_r: String,
    custom_original_moduli: String,
    custom_original_remainders: String,
    advanced_run_running: bool,
    advanced_run_rx: Option<mpsc::Receiver<String>>,
    advanced_stop_flag: Option<Arc<AtomicBool>>,
    results_text: String,
    official_challenge_id: String,
    official_run_running: bool,
    official_run_rx: Option<mpsc::Receiver<String>>,
    official_stop_flag: Option<Arc<AtomicBool>>,
    official_run_log: String,
    official_current_work: String,
    official_summary: String,
    official_hit_details: String,
    official_completed_units: usize,
    official_requested_units: usize,
    official_auto_select: bool,
    official_server_status: String,
    official_live_terminal: String,
    official_work_stream: String,
    official_detected_challenge: String,
    official_registration_status: String,
    official_registration_log: String,
    official_registration_qr_text: String,
    official_registration_poll_rx: Option<mpsc::Receiver<String>>,
    official_registration_poll_running: bool,
    official_nickname_input: String,
}

impl Default for MaxPrimeGuiApp {
    fn default() -> Self {
        let mut app = Self {
            tab: Tab::Home,
            theme_dark: false,
            status_message: "Ready. GUI prototype loaded.".to_string(),
            advanced_preview_text: "No advanced preview loaded yet. Click Preview standard test or Preview CRT test.".to_string(),
            self_check_text: String::new(),
                    custom_experiment_id: "GUI-CUSTOM-ADVANCED-001".to_string(),
            custom_n0: "10000000000000000000".to_string(),
            custom_step: "1234567".to_string(),
            custom_iterations: "300".to_string(),
            custom_test_n: true,
            custom_test_d: false,
            custom_filter_mode: "off".to_string(),
            custom_m: "59".to_string(),
            custom_r: "2".to_string(),
            custom_original_moduli: "7, 11, 13".to_string(),
            custom_original_remainders: "2, 3, 5".to_string(),
            advanced_run_running: false,
            advanced_run_rx: None,
            advanced_stop_flag: None,
            results_text: "No results loaded yet. Run an experiment, then click Show results.".to_string(),
            official_challenge_id: "AUTO".to_string(),
            official_run_running: false,
            official_run_rx: None,
            official_stop_flag: None,
            official_run_log: "Official Challenge log. Technical output will appear here during official runs.\n".to_string(),
            official_current_work: "No work unit is running yet.".to_string(),
            official_summary: "Ready. Run 1 package, run 5 packages, or start contributing.".to_string(),
            official_hit_details: "No hit found in this GUI session yet.".to_string(),
            official_completed_units: 0,
            official_requested_units: 0,
            official_auto_select: true,
            official_server_status: "No server status loaded yet.".to_string(),
            official_live_terminal: "Full technical client output will appear here during official runs.\n".to_string(),
            official_work_stream: "Live Work\n\nEach assigned package will appear here.\n".to_string(),
            official_detected_challenge: "MAX Login OK. No active public Challenge detected yet.".to_string(),
            official_registration_status: "MAX Login status is read from the local secure config.".to_string(),
            official_registration_log: "MAX Login connects this computer to one participant identity.\nClick Register with MAX Login to generate a fresh QR Code.\nThe participant token is stored only locally and must never be published.\n".to_string(),
            official_registration_qr_text: String::new(),
            official_registration_poll_rx: None,
            official_registration_poll_running: false,
            official_nickname_input: String::new(),
};

        app.refresh_self_check();
        app
    }
}

impl MaxPrimeGuiApp {
    fn prime_apply_visuals_gui(ctx: &egui::Context, dark_mode: bool) {
        let mut style = (*ctx.style()).clone();

        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(30.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(17.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(16.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(15.0, egui::FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );

        ctx.set_style(style);

        if dark_mode {
            let mut visuals = egui::Visuals::dark();

            /*
             * Dark mode, slightly lighter than the first version.
             * Still MAX/prime-admin style, but less black and easier on the eyes.
             */
            visuals.window_fill = egui::Color32::from_rgb(22, 28, 39);
            visuals.panel_fill = egui::Color32::from_rgb(22, 28, 39);
            visuals.extreme_bg_color = egui::Color32::from_rgb(18, 29, 44);
            visuals.faint_bg_color = egui::Color32::from_rgb(30, 42, 60);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(25, 35, 52);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(31, 45, 66);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(42, 68, 99);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(56, 92, 130);
            visuals.selection.bg_fill = egui::Color32::from_rgb(38, 125, 255);
            visuals.hyperlink_color = egui::Color32::from_rgb(216, 243, 255);

            ctx.set_visuals(visuals);
        } else {
            let mut visuals = egui::Visuals::light();

            visuals.window_fill = egui::Color32::from_rgb(238, 244, 252);
            visuals.panel_fill = egui::Color32::from_rgb(238, 244, 252);
            visuals.extreme_bg_color = egui::Color32::from_rgb(224, 234, 247);
            visuals.faint_bg_color = egui::Color32::from_rgb(248, 251, 255);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(255, 255, 255);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(245, 249, 255);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(230, 242, 255);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(210, 229, 255);
            visuals.selection.bg_fill = egui::Color32::from_rgb(11, 95, 255);
            visuals.hyperlink_color = egui::Color32::from_rgb(0, 74, 173);

            ctx.set_visuals(visuals);
        }
    }

    fn prime_action_button_gui(
        ui: &mut egui::Ui,
        text: &str,
        kind: &str,
        enabled: bool,
    ) -> egui::Response {
        let dark = ui.visuals().dark_mode;

        let active_fill = match kind {
            "primary" => {
                if dark {
                    egui::Color32::from_rgb(35, 105, 220)
                } else {
                    egui::Color32::from_rgb(31, 111, 235)
                }
            }
            "success" => {
                if dark {
                    egui::Color32::from_rgb(35, 145, 85)
                } else {
                    egui::Color32::from_rgb(35, 150, 85)
                }
            }
            "danger" => {
                if dark {
                    egui::Color32::from_rgb(170, 55, 55)
                } else {
                    egui::Color32::from_rgb(190, 55, 55)
                }
            }
            "warning" => {
                if dark {
                    egui::Color32::from_rgb(185, 105, 30)
                } else {
                    egui::Color32::from_rgb(175, 92, 18)
                }
            }
            "neutral" => {
                if dark {
                    egui::Color32::from_rgb(70, 85, 105)
                } else {
                    egui::Color32::from_rgb(220, 230, 242)
                }
            }
            _ => {
                if dark {
                    egui::Color32::from_rgb(70, 85, 105)
                } else {
                    egui::Color32::from_rgb(220, 230, 242)
                }
            }
        };

        let disabled_fill = if dark {
            egui::Color32::from_rgb(55, 62, 72)
        } else {
            egui::Color32::from_rgb(205, 216, 230)
        };

        let fill = if enabled { active_fill } else { disabled_fill };

        let text_color = if !enabled {
            if dark {
                egui::Color32::from_rgb(205, 215, 230)
            } else {
                egui::Color32::from_rgb(35, 48, 66)
            }
        } else {
            match kind {
                "neutral" => {
                    if dark {
                        egui::Color32::WHITE
                    } else {
                        egui::Color32::from_rgb(25, 40, 60)
                    }
                }
                _ => egui::Color32::WHITE,
            }
        };

        let stroke = if enabled {
            egui::Stroke::new(1.0_f32, active_fill)
        } else {
            egui::Stroke::new(
                1.0_f32,
                if dark {
                    egui::Color32::from_rgb(80, 90, 105)
                } else {
                    egui::Color32::from_rgb(190, 200, 215)
                },
            )
        };

        ui.add_enabled(
            enabled,
            egui::Button::new(egui::RichText::new(text).strong().color(text_color))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(8.0)
                .min_size(egui::vec2(150.0, 36.0)),
        )
    }

    fn prime_card_gui<R>(
        ui: &mut egui::Ui,
        title: &str,
        label: &str,
        add_contents: impl FnOnce(&mut egui::Ui) -> R,
    ) -> R {
        let dark = ui.visuals().dark_mode;

        let card_fill = if dark {
            egui::Color32::from_rgb(25, 35, 52)
        } else {
            egui::Color32::from_rgb(255, 255, 255)
        };

        let card_stroke = if dark {
            egui::Color32::from_rgb(52, 72, 105)
        } else {
            egui::Color32::from_rgb(196, 212, 232)
        };

        egui::Frame::group(ui.style())
            .fill(card_fill)
            .stroke(egui::Stroke::new(1.0_f32, card_stroke))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                let dark = ui.visuals().dark_mode;

                let overline_color = if dark {
                    egui::Color32::from_rgb(159, 183, 216)
                } else {
                    egui::Color32::from_rgb(116, 146, 188)
                };

                let title_color = if dark {
                    egui::Color32::from_rgb(236, 244, 255)
                } else {
                    egui::Color32::from_rgb(38, 55, 79)
                };

                if !label.trim().is_empty() {
                    ui.label(
                        egui::RichText::new(label.to_uppercase())
                            .size(11.0)
                            .strong()
                            .color(overline_color),
                    );
                }

                if !title.trim().is_empty() {
                    ui.label(
                        egui::RichText::new(title)
                            .size(17.5)
                            .strong()
                            .color(title_color),
                    );
                }

                ui.add_space(6.0);
                add_contents(ui)
            })
            .inner
    }

    fn prime_badge_gui(ui: &mut egui::Ui, text: &str, kind: &str) {
        let dark = ui.visuals().dark_mode;

        let (color, fill) = if dark {
            match kind {
                "ok" => (
                    egui::Color32::from_rgb(62, 232, 139),
                    egui::Color32::from_rgba_unmultiplied(62, 232, 139, 24),
                ),
                "bad" => (
                    egui::Color32::from_rgb(255, 107, 107),
                    egui::Color32::from_rgba_unmultiplied(255, 107, 107, 24),
                ),
                "warn" => (
                    egui::Color32::from_rgb(255, 209, 102),
                    egui::Color32::from_rgba_unmultiplied(255, 209, 102, 24),
                ),
                "blue" => (
                    egui::Color32::from_rgb(88, 194, 255),
                    egui::Color32::from_rgba_unmultiplied(88, 194, 255, 24),
                ),
                _ => (
                    egui::Color32::from_rgb(216, 231, 255),
                    egui::Color32::from_rgba_unmultiplied(122, 184, 255, 24),
                ),
            }
        } else {
            match kind {
                "ok" => (
                    egui::Color32::from_rgb(0, 125, 74),
                    egui::Color32::from_rgb(226, 250, 238),
                ),
                "bad" => (
                    egui::Color32::from_rgb(178, 39, 39),
                    egui::Color32::from_rgb(255, 236, 236),
                ),
                "warn" => (
                    egui::Color32::from_rgb(156, 106, 0),
                    egui::Color32::from_rgb(255, 245, 214),
                ),
                "blue" => (
                    egui::Color32::from_rgb(0, 102, 184),
                    egui::Color32::from_rgb(230, 243, 255),
                ),
                _ => (
                    egui::Color32::from_rgb(66, 83, 107),
                    egui::Color32::from_rgb(239, 244, 251),
                ),
            }
        };

        egui::Frame::new()
            .fill(fill)
            .stroke(egui::Stroke::new(1.0_f32, color.gamma_multiply(0.75)))
            .corner_radius(egui::CornerRadius::same(255))
            .inner_margin(egui::Margin::symmetric(10, 5))
            .show(ui, |ui| {
                ui.label(egui::RichText::new(text).strong().size(12.5).color(color));
            });
    }

    fn prime_tab_button_gui(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
        let dark = ui.visuals().dark_mode;

        let (fill, stroke, text_color) = if dark {
            if selected {
                (
                    egui::Color32::from_rgb(36, 89, 168),
                    egui::Color32::from_rgb(78, 136, 230),
                    egui::Color32::from_rgb(245, 250, 255),
                )
            } else {
                (
                    egui::Color32::from_rgb(22, 28, 39),
                    egui::Color32::from_rgb(62, 80, 110),
                    egui::Color32::from_rgb(205, 220, 240),
                )
            }
        } else {
            if selected {
                (
                    egui::Color32::from_rgb(211, 232, 255),
                    egui::Color32::from_rgb(111, 165, 232),
                    egui::Color32::from_rgb(24, 56, 102),
                )
            } else {
                (
                    egui::Color32::from_rgb(244, 247, 252),
                    egui::Color32::from_rgb(198, 212, 232),
                    egui::Color32::from_rgb(70, 82, 100),
                )
            }
        };

        ui.add(
            egui::Button::new(
                egui::RichText::new(label)
                    .size(15.0)
                    .strong()
                    .color(text_color),
            )
            .fill(fill)
            .stroke(egui::Stroke::new(1.0_f32, stroke))
            .corner_radius(egui::CornerRadius::same(6))
            .min_size(egui::vec2(92.0, 28.0)),
        )
    }

    fn prime_status_badge_gui(ui: &mut egui::Ui, ok: bool, ok_text: &str, bad_text: &str) {
        if ok {
            Self::prime_badge_gui(ui, ok_text, "ok");
        } else {
            Self::prime_badge_gui(ui, bad_text, "warn");
        }
    }

    fn read_json_status(path: &str) -> String {
        if !Path::new(path).exists() {
            return "missing".to_string();
        }

        match fs::read_to_string(path) {
            Ok(txt) => match serde_json::from_str::<Value>(&txt) {
                Ok(_) => "ok json".to_string(),
                Err(_) => "invalid json".to_string(),
            },
            Err(_) => "cannot read".to_string(),
        }
    }

    fn path_status(path: &str) -> String {
        if Path::new(path).exists() {
            "ok".to_string()
        } else {
            "missing".to_string()
        }
    }

    fn theory_note_text_gui() -> String {
        [
            "MAX Prime Theory — N and d",
            "==========================",
            "",
            "Simple explanation:",
            "N is the main MAX Prime Challenge target.",
            "It is the value used to measure the prime-producing strength of the MAX Prime polynomial family.",
            "",
            "d is a related auxiliary value.",
            "It can be useful for technical exploration, but it is not the main official Challenge target.",
            "",
            "Local experiments are private experiments.",
            "They do not create official Challenge work.",
            "They do not submit official results.",
            "Found candidates are probable primes, not public mathematical certifications.",
            "",
            "Full background:",
            "Official website: https://www.max-russo.com",
                    ].join("\n")
    }

    fn refresh_self_check(&mut self) {
        let mut lines = Vec::new();

        lines.push("MAX Prime Challenge Public GUI Diagnostics".to_string());
        lines.push("================================".to_string());
        lines.push(String::new());

        lines.push("Core folders:".to_string());
        lines.push(format!("app_state: {}", Self::path_status("app_state")));
        lines.push(format!("discoveries: {}", Self::path_status("discoveries")));
        lines.push(format!("exports: {}", Self::path_status("exports")));
        lines.push(format!("examples: {}", Self::path_status("examples")));
        lines.push(format!("logs: {}", Self::path_status("logs")));
        lines.push(format!("checkpoints: {}", Self::path_status("checkpoints")));
        lines.push(String::new());

        lines.push("Important files:".to_string());
        lines.push(format!(
            "{}: {}",
            CURRENT_RUN_STATE_PATH,
            Self::read_json_status(CURRENT_RUN_STATE_PATH)
        ));
        lines.push(format!(
            "{}: {}",
            OFFICIAL_CLIENT_CONFIG_PATH,
            Self::read_json_status(OFFICIAL_CLIENT_CONFIG_PATH)
        ));
        lines.push(format!(
            "{}: {}",
            LOCAL_DISCOVERIES_PATH,
            Self::read_json_status(LOCAL_DISCOVERIES_PATH)
        ));
        lines.push(format!(
            "examples/local_advanced_experiment_example.json: {}",
            Self::read_json_status("examples/local_advanced_experiment_example.json")
        ));
        lines.push(format!(
            "examples/local_advanced_experiment_crt_example.json: {}",
            Self::read_json_status("examples/local_advanced_experiment_crt_example.json")
        ));
        lines.push(String::new());

        lines.push("GUI status: ok".to_string());
        lines.push(
            "Official Challenge participation: enabled for server-assigned work units".to_string(),
        );
        lines.push("Private MAX Login/admin code: not included".to_string());
        lines.push("HF token: not included".to_string());

        self.self_check_text = lines.join("\n");
    }

    fn now_unix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    fn extract_after_prefix_gui(text: &str, prefix: &str) -> String {
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                return rest.trim().to_string();
            }
        }
        "(not found)".to_string()
    }

    fn gcd_u128_gui(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            let r = a % b;
            a = b;
            b = r;
        }
        a
    }

    fn egcd_i128_gui(a: i128, b: i128) -> (i128, i128, i128) {
        if b == 0 {
            (a, 1, 0)
        } else {
            let (g, x1, y1) = Self::egcd_i128_gui(b, a % b);
            (g, y1, x1 - (a / b) * y1)
        }
    }

    fn mod_inverse_u128_gui(a: u128, m: u128) -> Result<u128, String> {
        if m <= 1 {
            return Err("CRT modulus must be greater than 1.".to_string());
        }

        if a > i128::MAX as u128 || m > i128::MAX as u128 {
            return Err(
                "CRT modular inverse currently supports original moduli within i128 range."
                    .to_string(),
            );
        }

        let (g, x, _) = Self::egcd_i128_gui(a as i128, m as i128);
        if g != 1 {
            return Err(format!(
                "CRT inverse does not exist: {} and {} are not coprime.",
                a, m
            ));
        }

        Ok(x.rem_euclid(m as i128) as u128)
    }

    fn mul_mod_u128_gui(mut a: u128, mut b: u128, m: u128) -> u128 {
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

    fn parse_decimal_list_gui(label: &str, text: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();

        for raw in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            if !t.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("{} contains a non-decimal value: {}", label, t));
            }
            out.push(t.to_string());
        }

        if out.is_empty() {
            return Err(format!("{} cannot be empty.", label));
        }

        Ok(out)
    }

    fn compute_crt_from_pairs_gui(
        moduli_txt: &[String],
        remainders_txt: &[String],
    ) -> Result<(String, String), String> {
        if moduli_txt.len() != remainders_txt.len() {
            return Err(format!(
                "CRT multi-filter requires same count of moduli and remainders. Got {} moduli and {} remainders.",
                moduli_txt.len(),
                remainders_txt.len()
            ));
        }

        let mut m_acc: u128 = 1;
        let mut r_acc: u128 = 0;

        for (idx, (m_txt, r_txt)) in moduli_txt.iter().zip(remainders_txt.iter()).enumerate() {
            let m2 = m_txt
                .parse::<u128>()
                .map_err(|e| format!("Cannot parse CRT modulus {}: {}", idx + 1, e))?;
            let r2 = r_txt
                .parse::<u128>()
                .map_err(|e| format!("Cannot parse CRT remainder {}: {}", idx + 1, e))?;

            if m2 <= 1 {
                return Err(format!("CRT modulus {} must be greater than 1.", idx + 1));
            }

            if r2 >= m2 {
                return Err(format!(
                    "CRT remainder {} must be smaller than modulus {}. Got {} modulo {}.",
                    idx + 1,
                    idx + 1,
                    r2,
                    m2
                ));
            }

            let g = Self::gcd_u128_gui(m_acc, m2);
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

            let inv = Self::mod_inverse_u128_gui(m_acc % m2, m2)?;
            let k = Self::mul_mod_u128_gui(diff, inv, m2);

            let add = m_acc
                .checked_mul(k)
                .ok_or_else(|| "CRT cumulative remainder overflowed u128. Use cumulative M/R for very large CRT products.".to_string())?;

            let new_m = m_acc
                .checked_mul(m2)
                .ok_or_else(|| "CRT cumulative modulus overflowed u128. Use cumulative M/R for very large CRT products.".to_string())?;

            r_acc = (r_acc + add) % new_m;
            m_acc = new_m;
        }

        Ok((m_acc.to_string(), r_acc.to_string()))
    }

    fn build_custom_advanced_json_gui(&mut self) -> Result<String, String> {
        let iterations_u64 = match self.custom_iterations.trim().parse::<u64>() {
            Ok(v) if v > 0 => v,
            Ok(_) => return Err("iterations must be greater than zero.".to_string()),
            Err(_) => return Err("iterations must be a normal positive integer.".to_string()),
        };

        if !self.custom_test_n && !self.custom_test_d {
            return Err("select at least one target: test N or test d.".to_string());
        }

        if self.custom_n0.trim().is_empty()
            || !self.custom_n0.trim().chars().all(|c| c.is_ascii_digit())
        {
            return Err("n0 must contain only digits.".to_string());
        }

        if self.custom_step.trim().is_empty()
            || !self.custom_step.trim().chars().all(|c| c.is_ascii_digit())
        {
            return Err("step must contain only digits.".to_string());
        }

        let filter_mode = self.custom_filter_mode.as_str();

        let filter_json = match filter_mode {
            "off" => {
                json!({
                    "enabled": false,
                    "modulus_m": "1",
                    "remainder_r": "0",
                    "original_moduli": [],
                    "original_remainders": []
                })
            }
            "cumulative" => {
                if self.custom_m.trim().is_empty()
                    || !self.custom_m.trim().chars().all(|c| c.is_ascii_digit())
                {
                    return Err("CRT cumulative M must contain only digits.".to_string());
                }
                if self.custom_r.trim().is_empty()
                    || !self.custom_r.trim().chars().all(|c| c.is_ascii_digit())
                {
                    return Err("CRT cumulative R must contain only digits.".to_string());
                }
                if self.custom_m.trim() == "0" {
                    return Err("CRT cumulative M must be greater than zero.".to_string());
                }

                json!({
                    "enabled": true,
                    "modulus_m": self.custom_m.trim(),
                    "remainder_r": self.custom_r.trim(),
                    "original_moduli": [],
                    "original_remainders": []
                })
            }
            "multi" => {
                let original_moduli = Self::parse_decimal_list_gui(
                    "CRT original moduli",
                    &self.custom_original_moduli,
                )?;
                let original_remainders = Self::parse_decimal_list_gui(
                    "CRT original remainders",
                    &self.custom_original_remainders,
                )?;
                let (computed_m, computed_r) =
                    Self::compute_crt_from_pairs_gui(&original_moduli, &original_remainders)?;

                self.custom_m = computed_m.clone();
                self.custom_r = computed_r.clone();

                json!({
                    "enabled": true,
                    "modulus_m": computed_m,
                    "remainder_r": computed_r,
                    "original_moduli": original_moduli,
                    "original_remainders": original_remainders
                })
            }
            _ => {
                return Err(
                    "unknown CRT mode. Use OFF, cumulative M/R or multi-filter.".to_string()
                );
            }
        };

        let experiment_json = json!({
            "experiment_id": self.custom_experiment_id.trim(),
            "n0": self.custom_n0.trim(),
            "step": self.custom_step.trim(),
            "iterations": iterations_u64,
            "test_n": self.custom_test_n,
            "test_d": self.custom_test_d,
            "filter": filter_json
        });

        let txt = serde_json::to_string_pretty(&experiment_json)
            .map_err(|e| format!("cannot serialize experiment JSON: {}", e))?;

        let custom_path = "examples/gui_custom_advanced_experiment.json";

        fs::write(custom_path, txt).map_err(|e| format!("cannot write {}: {}", custom_path, e))?;

        Ok(custom_path.to_string())
    }

    fn summarize_advanced_run_output_gui(raw: &str, stopped: bool) -> String {
        let status = if stopped {
            "Advanced experiment stopped"
        } else {
            "Advanced experiment completed"
        };

        let mut useful_lines = Vec::new();

        for line in raw.lines() {
            let t = line.trim();
            if t.starts_with("Experiment ID:")
                || t.starts_with("Iterations:")
                || t.starts_with("Iterations tested:")
                || t.starts_with("Candidate type:")
                || t.starts_with("Probable primes found:")
                || t.starts_with("N primes:")
                || t.starts_with("d primes:")
                || t.starts_with("N enrichment:")
                || t.starts_with("d enrichment:")
                || t.starts_with("Best size:")
                || t.starts_with("Best SHA-256:")
                || t.starts_with("Saved to:")
                || t.starts_with("GUI state saved to:")
                || t.starts_with("Hit found:")
            {
                useful_lines.push(t.to_string());
            }
        }

        let useful = if useful_lines.is_empty() {
            "No compact summary was found in the CLI output.\nThe command finished, but the GUI could not extract a clean summary yet.".to_string()
        } else {
            useful_lines.join("\n")
        };

        format!(
            "{}\n============================\n\n{}\n\nNote:\nThis was a local Advanced experiment.\nNo official server submission was made.\n\nFull technical output is intentionally not shown here.",
            status,
            useful
        )
    }

    fn start_advanced_run_gui(&mut self) {
        if self.advanced_run_running {
            self.status_message = "Advanced experiment is already running.".to_string();
            return;
        }

        let config_path = match self.build_custom_advanced_json_gui() {
            Ok(v) => v,
            Err(e) => {
                self.status_message = format!("Cannot start Advanced experiment: {}", e);
                self.advanced_preview_text = format!("Cannot start Advanced experiment.\n\n{}", e);
                return;
            }
        };

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_thread = stop_flag.clone();
        let (tx, rx) = mpsc::channel::<String>();

        self.advanced_run_running = true;
        self.advanced_stop_flag = Some(stop_flag);
        self.advanced_run_rx = Some(rx);
        self.status_message = "Advanced experiment running...".to_string();
        self.advanced_preview_text = format!(
            "Advanced experiment running...\n\nConfig file:\n{}\n\nYou can click Stop to interrupt the local process.",
            config_path
        );

        thread::spawn(move || {
            let mut child = match Command::new("./target/release/max_prime_public_client")
                .args(["advanced-local", &config_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(format!("Advanced experiment failed to start.\n\n{}", e));
                    return;
                }
            };

            let mut stopped = false;

            loop {
                if stop_flag_thread.load(Ordering::SeqCst) {
                    stopped = true;
                    let _ = child.kill();
                    break;
                }

                match child.try_wait() {
                    Ok(Some(_status)) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(250)),
                    Err(e) => {
                        let _ =
                            tx.send(format!("Advanced experiment error while waiting.\n\n{}", e));
                        return;
                    }
                }
            }

            match child.wait_with_output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let mut raw = String::new();
                    raw.push_str(&stdout);
                    if !stderr.trim().is_empty() {
                        raw.push_str("\n\nSTDERR:\n");
                        raw.push_str(&stderr);
                    }
                    let summary = Self::summarize_advanced_run_output_gui(&raw, stopped);
                    let _ = tx.send(summary);
                }
                Err(e) => {
                    let _ = tx.send(format!(
                        "Advanced experiment ended, but output could not be read.\n\n{}",
                        e
                    ));
                }
            }
        });
    }

    fn stop_advanced_run_gui(&mut self) {
        if !self.advanced_run_running {
            self.status_message = "No Advanced experiment is running.".to_string();
            return;
        }

        if let Some(flag) = &self.advanced_stop_flag {
            flag.store(true, Ordering::SeqCst);
            self.status_message =
                "Stop requested. Waiting for local process to exit...".to_string();
        }
    }

    fn poll_advanced_run_gui(&mut self) {
        if let Some(rx) = &self.advanced_run_rx {
            match rx.try_recv() {
                Ok(msg) => {
                    self.advanced_preview_text = msg;
                    self.advanced_run_running = false;
                    self.advanced_run_rx = None;
                    self.advanced_stop_flag = None;
                    self.status_message = "Advanced experiment finished.".to_string();
                    self.refresh_self_check();
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.advanced_preview_text =
                        "Advanced experiment channel disconnected.".to_string();
                    self.advanced_run_running = false;
                    self.advanced_run_rx = None;
                    self.advanced_stop_flag = None;
                    self.status_message = "Advanced experiment ended unexpectedly.".to_string();
                }
            }
        }
    }

    fn value_to_short_string_gui(v: Option<&Value>) -> String {
        match v {
            Some(Value::String(x)) => x.clone(),
            Some(Value::Number(x)) => x.to_string(),
            Some(Value::Bool(x)) => x.to_string(),
            Some(_) => "(complex value)".to_string(),
            None => "(missing)".to_string(),
        }
    }

    fn show_latest_results_gui(&mut self) {
        let full_json = match self.latest_run_full_export_json_gui() {
            Ok(v) => v,
            Err(e) => {
                self.results_text = format!("Latest run results\n==================\n\n{}", e);
                self.advanced_preview_text = self.results_text.clone();
                self.status_message = "Cannot load latest full run results.".to_string();
                return;
            }
        };

        let experiment_id = Self::value_to_short_string_gui(full_json.get("experiment_id"));
        let mode = Self::value_to_short_string_gui(full_json.get("mode"));
        let iterations_done = Self::value_to_short_string_gui(full_json.get("iterations_done"));
        let candidate_type = Self::value_to_short_string_gui(full_json.get("candidate_type"));

        let expected_n = full_json
            .get("expected_n_primes")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let observed_n = full_json
            .get("observed_n_primes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let n_enrichment = full_json
            .get("n_enrichment")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let expected_d = full_json
            .get("expected_d_primes")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let observed_d = full_json
            .get("observed_d_primes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let d_enrichment = full_json
            .get("d_enrichment")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let hits = full_json
            .get("hits")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut output = String::new();

        output.push_str("Latest experiment results\n");
        output.push_str("=========================\n\n");

        output.push_str("Summary\n");
        output.push_str("-------\n");
        output.push_str(&format!("Experiment ID: {}\n", experiment_id));
        output.push_str(&format!("Mode: {}\n", mode));
        output.push_str(&format!("Candidate type: {}\n", candidate_type));
        output.push_str(&format!("Iterations tested: {}\n", iterations_done));
        output.push_str(&format!("Hits exported: {}\n", hits.len()));
        output.push('\n');

        output.push_str("Enrichment\n");
        output.push_str("----------\n");
        output.push_str(&format!("Expected N primes: {:.6}\n", expected_n));
        output.push_str(&format!("Observed N primes: {}\n", observed_n));
        output.push_str(&format!("N enrichment: {:.3}×\n", n_enrichment));
        output.push_str(&format!("Expected d primes: {:.6}\n", expected_d));
        output.push_str(&format!("Observed d primes: {}\n", observed_d));
        output.push_str(&format!("d enrichment: {:.3}×\n", d_enrichment));
        output.push('\n');

        output.push_str("Prime candidates\n");
        output.push_str("----------------\n");

        if hits.is_empty() {
            output.push_str("No prime candidates exported for the latest run.\n");
        } else {
            for (idx, hit) in hits.iter().enumerate() {
                let candidate_type = Self::value_to_short_string_gui(hit.get("candidate_type"));
                let n_value = Self::value_to_short_string_gui(hit.get("n"));
                let digits = Self::value_to_short_string_gui(hit.get("digits"));
                let sha256 = Self::value_to_short_string_gui(hit.get("sha256"));
                let candidate = Self::value_to_short_string_gui(hit.get("candidate"));

                output.push_str(&format!("Prime #{}\n", idx + 1));
                output.push_str("------------------\n");
                output.push_str(&format!("type: {}\n", candidate_type));
                output.push_str(&format!("n: {}\n", n_value));
                output.push_str(&format!("digits: {}\n", digits));
                output.push_str(&format!("sha256: {}\n", sha256));
                output.push_str("candidate:\n");
                output.push_str(&candidate);
                output.push_str("\n\n");
            }
        }

        output.push_str("Export\n");
        output.push_str("------\n");
        output.push_str("Click Export results to choose where to save the full JSON file.\n");
        output.push_str("Only the latest experiment will be exported.\n");

        self.results_text = output.clone();
        self.advanced_preview_text = output;
        self.status_message = format!(
            "Latest experiment loaded: {} hits, N enrichment {:.3}×.",
            hits.len(),
            n_enrichment
        );
    }

    fn find_string_deep_gui(value: &Value, key: &str) -> Option<String> {
        match value {
            Value::Object(map) => {
                if let Some(v) = map.get(key) {
                    if let Some(txt) = v.as_str() {
                        if !txt.trim().is_empty() {
                            return Some(txt.to_string());
                        }
                    } else if v.is_number() || v.is_boolean() {
                        return Some(v.to_string());
                    }
                }

                for child in map.values() {
                    if let Some(found) = Self::find_string_deep_gui(child, key) {
                        return Some(found);
                    }
                }

                None
            }
            Value::Array(items) => {
                for child in items {
                    if let Some(found) = Self::find_string_deep_gui(child, key) {
                        return Some(found);
                    }
                }

                None
            }
            _ => None,
        }
    }

    fn safe_file_part_gui(input: &str) -> String {
        let cleaned: String = input
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let trimmed = cleaned.trim_matches('_');

        if trimmed.is_empty() {
            "unknown".to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn extract_submit_payload_path_from_hit_details_gui(text: &str) -> Option<String> {
        for line in text.lines() {
            let trimmed = line.trim();

            if let Some(rest) = trimmed.strip_prefix("Submit payload:") {
                let path = rest.trim();

                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
        }

        None
    }

    fn redact_public_export_secrets_gui(value: &mut Value) {
        match value {
            Value::Object(map) => {
                let sensitive_keys = [
                    "assignment_id",
                    "assignment_token",
                    "client_id",
                    "client_device_id",
                    "participant_id",
                    "participant_token",
                    "token_id",
                    "registration_id",
                    "device_secret",
                    "local_secret",
                    "secret",
                    "password",
                    "authorization",
                ];

                for key in sensitive_keys {
                    if map.contains_key(key) {
                        map.insert(
                            key.to_string(),
                            Value::String("REDACTED_PUBLIC_EXPORT".to_string()),
                        );
                    }
                }

                for child in map.values_mut() {
                    Self::redact_public_export_secrets_gui(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    Self::redact_public_export_secrets_gui(child);
                }
            }
            _ => {}
        }
    }

    fn export_official_winning_hit_data_gui(&mut self) {
        let payload_path =
            Self::extract_submit_payload_path_from_hit_details_gui(&self.official_hit_details);

        let submit_payload_json = match payload_path.as_ref() {
            Some(path) => match fs::read_to_string(path) {
                Ok(txt) => match serde_json::from_str::<Value>(&txt) {
                    Ok(v) => v,
                    Err(e) => json!({
                        "parse_error": e.to_string(),
                        "raw_text": txt
                    }),
                },
                Err(e) => json!({
                    "read_error": e.to_string(),
                    "path": path
                }),
            },
            None => Value::Null,
        };

        let last_official_outcome_json = match fs::read_to_string(LAST_OFFICIAL_OUTCOME_PATH) {
            Ok(txt) => match serde_json::from_str::<Value>(&txt) {
                Ok(v) => v,
                Err(e) => json!({
                    "parse_error": e.to_string(),
                    "raw_text": txt
                }),
            },
            Err(e) => json!({
                "read_error": e.to_string(),
                "path": LAST_OFFICIAL_OUTCOME_PATH
            }),
        };

        let mut submit_payload_json = submit_payload_json;
        let mut last_official_outcome_json = last_official_outcome_json;

        Self::redact_public_export_secrets_gui(&mut submit_payload_json);
        Self::redact_public_export_secrets_gui(&mut last_official_outcome_json);

        let challenge_id = Self::find_string_deep_gui(&submit_payload_json, "challenge_id")
            .or_else(|| Self::find_string_deep_gui(&last_official_outcome_json, "challenge_id"))
            .unwrap_or_else(|| "challenge".to_string());

        let work_unit_id = Self::find_string_deep_gui(&submit_payload_json, "work_unit_id")
            .or_else(|| Self::find_string_deep_gui(&last_official_outcome_json, "work_unit_id"))
            .unwrap_or_else(|| "work_unit".to_string());

        let safe_challenge_id = Self::safe_file_part_gui(&challenge_id);
        let safe_work_unit_id = Self::safe_file_part_gui(&work_unit_id);

        let suggested_name = format!(
            "MAXPrime_{}_{}_winning_hit_data.json",
            safe_challenge_id, safe_work_unit_id
        );

        let export_json = json!({
            "export_type": "MAX_PRIME_OFFICIAL_WINNING_HIT_DATA",
            "exported_at_unix": Self::now_unix(),
            "purpose": "Public inspection and local reproducibility of an official MAX Prime probable-prime hit.",
            "challenge_id": challenge_id,
            "work_unit_id": work_unit_id,
            "source_files": {
                "last_official_outcome_path": LAST_OFFICIAL_OUTCOME_PATH,
                "submit_payload_path": payload_path.clone()
            },
            "official_summary_text": self.official_summary,
            "official_hit_details_text": self.official_hit_details,
            "last_official_outcome": last_official_outcome_json,
            "submit_payload": submit_payload_json,
            "public_export_note": "Operational identifiers and local tokens are redacted because they are not required for mathematical reproducibility.",
            "reproducibility_note": "This export contains the official hit data currently available to the GUI, including the submit payload when available. Technical reviewers can inspect the candidate, digits, SHA-256 and work-unit data and recompute the result locally when the required parameters are present."
        });

        let save_path = rfd::FileDialog::new()
            .set_title("Export winning hit data")
            .add_filter("MAX Prime winning hit JSON", &["json"])
            .set_file_name(&suggested_name)
            .save_file();

        let Some(path) = save_path else {
            self.status_message = "Export winning hit data cancelled.".to_string();
            return;
        };

        let txt = match serde_json::to_string_pretty(&export_json) {
            Ok(v) => v,
            Err(e) => {
                self.status_message = format!(
                    "Export winning hit data failed while serializing JSON: {}",
                    e
                );
                return;
            }
        };

        if let Err(e) = fs::write(&path, txt) {
            self.status_message =
                format!("Export winning hit data failed while writing file: {}", e);
            return;
        }

        self.status_message = format!("Winning hit data exported: {}", path.display());
        self.official_hit_details.push_str(&format!(
            "\nWinning hit data exported:\n{}\n",
            path.display()
        ));
    }

    fn export_latest_results_gui(&mut self) {
        let full_json = match self.latest_run_full_export_json_gui() {
            Ok(v) => v,
            Err(e) => {
                self.status_message = format!("Export failed: {}", e);
                self.advanced_preview_text = format!("Export failed\n=============\n\n{}", e);
                return;
            }
        };

        let experiment_id = full_json
            .get("experiment_id")
            .and_then(|v| v.as_str())
            .unwrap_or("latest_run");
        let safe_experiment_id: String = experiment_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let suggested_name = format!("{}_full_result.json", safe_experiment_id);

        let save_path = rfd::FileDialog::new()
            .set_title("Save MAX Prime full latest run result")
            .add_filter("JSON full result", &["json"])
            .set_file_name(&suggested_name)
            .save_file();

        let Some(path) = save_path else {
            self.status_message = "Export cancelled.".to_string();
            self.advanced_preview_text = "Export cancelled.\n\nNo file was saved.".to_string();
            return;
        };

        let txt = match serde_json::to_string_pretty(&full_json) {
            Ok(v) => v,
            Err(e) => {
                self.status_message = format!("Export failed while serializing full JSON: {}", e);
                return;
            }
        };

        if let Err(e) = fs::write(&path, txt) {
            self.status_message = format!("Export failed while writing file: {}", e);
            self.advanced_preview_text = format!(
                "Export failed\n=============\n\nCould not write:\n{}\n\nError:\n{}",
                path.display(),
                e
            );
            return;
        }

        let hits_exported = full_json
            .get("hits_exported")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let n_enrichment = full_json
            .get("n_enrichment")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        self.status_message = format!("Full latest run exported: {}", path.display());
        self.advanced_preview_text = format!(
            "Full latest run exported\n========================\n\nSaved file:\n{}\n\nHits exported: {}\nN enrichment: {:.3}×\n\nThis file contains the latest experiment summary and all prime candidates from that run.",
            path.display(),
            hits_exported,
            n_enrichment
        );
    }

    fn collect_hit_values_for_latest_export_gui(value: &Value, out: &mut Vec<Value>) {
        match value {
            Value::Object(map) => {
                let looks_like_hit = map.get("candidate").is_some()
                    && map.get("sha256").is_some()
                    && map.get("digits").is_some();

                if looks_like_hit {
                    out.push(Value::Object(map.clone()));
                }

                for child in map.values() {
                    Self::collect_hit_values_for_latest_export_gui(child, out);
                }
            }
            Value::Array(items) => {
                for child in items {
                    Self::collect_hit_values_for_latest_export_gui(child, out);
                }
            }
            _ => {}
        }
    }

    fn latest_run_full_export_json_gui(&self) -> Result<Value, String> {
        let current_txt = fs::read_to_string(CURRENT_RUN_STATE_PATH).map_err(|e| {
            format!(
                "cannot read latest run summary {}: {}",
                CURRENT_RUN_STATE_PATH, e
            )
        })?;

        let current_json: Value = serde_json::from_str(&current_txt)
            .map_err(|e| format!("cannot parse latest run summary JSON: {}", e))?;

        let discoveries_json: Value = match fs::read_to_string(LOCAL_DISCOVERIES_PATH) {
            Ok(discoveries_txt) => serde_json::from_str(&discoveries_txt)
                .map_err(|e| format!("cannot parse local discoveries JSON: {}", e))?,
            Err(_) => Value::Array(Vec::new()),
        };

        let mut all_hits = Vec::new();
        Self::collect_hit_values_for_latest_export_gui(&discoveries_json, &mut all_hits);

        let summary_mode = current_json
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let summary_candidate_type = current_json
            .get("candidate_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let summary_hits_found = current_json
            .get("hits_found")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let current_run_hits = current_json
            .get("hits")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let experiment_id_from_summary = current_json
            .get("experiment_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let experiment_id = if experiment_id_from_summary.is_empty() {
            self.custom_experiment_id.trim()
        } else {
            experiment_id_from_summary
        };

        let started_at = current_json
            .get("started_at_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completed_at = current_json
            .get("completed_at_unix")
            .and_then(|v| v.as_u64())
            .or_else(|| current_json.get("updated_at_unix").and_then(|v| v.as_u64()))
            .unwrap_or(0);

        let mut filtered_hits: Vec<Value> = all_hits
            .iter()
            .filter(|hit| {
                let mode_ok = if summary_mode.is_empty() {
                    true
                } else {
                    hit.get("mode").and_then(|v| v.as_str()).unwrap_or("") == summary_mode
                };

                let type_ok = if summary_candidate_type.is_empty() {
                    true
                } else {
                    hit.get("candidate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        == summary_candidate_type
                };

                let note = hit.get("note").and_then(|v| v.as_str()).unwrap_or("");
                let experiment_ok = if experiment_id.is_empty() {
                    true
                } else {
                    note.contains(experiment_id)
                        || hit
                            .get("experiment_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            == experiment_id
                };

                let found_at = hit
                    .get("found_at_unix")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let time_ok = if started_at > 0 && completed_at > 0 && found_at > 0 {
                    found_at + 10 >= started_at && found_at <= completed_at + 10
                } else {
                    true
                };

                mode_ok && type_ok && experiment_ok && time_ok
            })
            .cloned()
            .collect();

        if filtered_hits.is_empty() && summary_hits_found > 0 {
            let mut candidates: Vec<Value> = all_hits
                .iter()
                .filter(|hit| {
                    let mode_ok = if summary_mode.is_empty() {
                        true
                    } else {
                        hit.get("mode").and_then(|v| v.as_str()).unwrap_or("") == summary_mode
                    };

                    let type_ok = if summary_candidate_type.is_empty() {
                        true
                    } else {
                        hit.get("candidate_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            == summary_candidate_type
                    };

                    let note = hit.get("note").and_then(|v| v.as_str()).unwrap_or("");
                    let experiment_ok = if experiment_id.is_empty() {
                        true
                    } else {
                        note.contains(experiment_id)
                            || hit
                                .get("experiment_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                == experiment_id
                    };

                    mode_ok && type_ok && experiment_ok
                })
                .cloned()
                .collect();

            candidates.sort_by_key(|hit| {
                hit.get("found_at_unix")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            });

            if summary_hits_found <= candidates.len() {
                filtered_hits = candidates[candidates.len() - summary_hits_found..].to_vec();
            } else {
                filtered_hits = candidates;
            }
        }

        if !current_run_hits.is_empty() {
            filtered_hits = current_run_hits;
        }

        let expected_n = current_json
            .get("expected_n_primes")
            .cloned()
            .unwrap_or(Value::from(0.0));
        let observed_n = current_json
            .get("observed_n_primes")
            .cloned()
            .unwrap_or(Value::from(0));
        let n_enrichment = current_json
            .get("n_enrichment")
            .cloned()
            .unwrap_or(Value::from(0.0));
        let expected_d = current_json
            .get("expected_d_primes")
            .cloned()
            .unwrap_or(Value::from(0.0));
        let observed_d = current_json
            .get("observed_d_primes")
            .cloned()
            .unwrap_or(Value::from(0));
        let d_enrichment = current_json
            .get("d_enrichment")
            .cloned()
            .unwrap_or(Value::from(0.0));

        let iterations_total_value = current_json
            .get("iterations_total")
            .cloned()
            .unwrap_or(Value::Null);
        let iterations_done_value = current_json
            .get("iterations_done")
            .cloned()
            .unwrap_or(Value::Null);
        let candidate_type_value = current_json
            .get("candidate_type")
            .cloned()
            .unwrap_or(Value::Null);
        let test_n_value = current_json.get("test_n").cloned().unwrap_or(Value::Null);
        let test_d_value = current_json.get("test_d").cloned().unwrap_or(Value::Null);
        let filter_enabled_value = current_json
            .get("filter_enabled")
            .cloned()
            .unwrap_or(Value::Null);
        let filter_value = current_json.get("filter").cloned().unwrap_or(Value::Null);
        let hits_found_value = current_json
            .get("hits_found")
            .cloned()
            .unwrap_or(Value::from(filtered_hits.len()));
        let best_digits_value = current_json
            .get("best_digits")
            .cloned()
            .unwrap_or(Value::Null);
        let best_sha256_value = current_json
            .get("best_sha256")
            .cloned()
            .unwrap_or(Value::Null);
        let started_at_value = current_json
            .get("started_at_unix")
            .cloned()
            .unwrap_or(Value::Null);
        let completed_at_value = current_json
            .get("completed_at_unix")
            .cloned()
            .unwrap_or(Value::Null);
        let message_value = current_json.get("message").cloned().unwrap_or(Value::Null);
        let mode_value = current_json
            .get("mode")
            .cloned()
            .unwrap_or(Value::String("advanced-local".to_string()));
        let status_value = current_json
            .get("status")
            .cloned()
            .unwrap_or(Value::String("completed".to_string()));
        let engine_value = current_json
            .get("engine")
            .cloned()
            .unwrap_or(Value::String("dashu-int".to_string()));
        let main_target_value = Value::String("N".to_string());
        let auxiliary_target_value = Value::String("d".to_string());
        let prime_status_value = Value::String("probable_prime".to_string());
        let local_experiment_only_value = Value::Bool(true);
        let official_submission_value = Value::Bool(false);
        let official_website_value = Value::String("https://www.max-russo.com".to_string());

        let export_json = json!({
            "export_type": "MAX_PRIME_LATEST_LOCAL_EXPERIMENT_FULL_RESULT",
            "exported_at_unix": Self::now_unix(),

            "summary": {
                "experiment_id": experiment_id,
                "engine": engine_value.clone(),
                "main_target": main_target_value.clone(),
                "auxiliary_target": auxiliary_target_value.clone(),
                "prime_status": prime_status_value.clone(),
                "local_experiment_only": local_experiment_only_value.clone(),
                "official_submission": official_submission_value.clone(),
                "mode": mode_value.clone(),
                "status": status_value.clone(),
                "candidate_type": candidate_type_value.clone(),
                "iterations_total": iterations_total_value.clone(),
                "iterations_done": iterations_done_value.clone(),
                "hits_found": hits_found_value.clone(),
                "hits_exported": filtered_hits.len(),
                "observed_n_primes": observed_n.clone(),
                "expected_n_primes": expected_n.clone(),
                "n_enrichment": n_enrichment.clone(),
                "observed_d_primes": observed_d.clone(),
                "expected_d_primes": expected_d.clone(),
                "d_enrichment": d_enrichment.clone(),
                "best_digits": best_digits_value.clone(),
                "best_sha256": best_sha256_value.clone(),
                "message": message_value.clone()
            },

            "experiment_id": experiment_id,
            "mode": mode_value,
            "status": status_value,
            "engine": engine_value,
            "main_target": main_target_value,
            "auxiliary_target": auxiliary_target_value,
            "prime_status": prime_status_value,
            "local_experiment_only": local_experiment_only_value,
            "official_submission": official_submission_value,
            "iterations_total": iterations_total_value,
            "iterations_done": iterations_done_value,
            "candidate_type": candidate_type_value,
            "test_n": test_n_value,
            "test_d": test_d_value,
            "filter_enabled": filter_enabled_value,
            "filter": filter_value,
            "expected_n_primes": expected_n,
            "observed_n_primes": observed_n,
            "n_enrichment": n_enrichment,
            "expected_d_primes": expected_d,
            "observed_d_primes": observed_d,
            "d_enrichment": d_enrichment,
            "hits_found": hits_found_value,
            "hits_exported": filtered_hits.len(),
            "best_digits": best_digits_value,
            "best_sha256": best_sha256_value,
            "started_at_unix": started_at_value,
            "completed_at_unix": completed_at_value,
            "message": message_value,

            "theory_note": {
                "plain_explanation": "N is the main MAX Prime Challenge target. d is a related auxiliary value useful for technical exploration. For background and official information, visit the official website.",
                "main_target": "N",
                "auxiliary_target": "d",
                "local_experiment_only": true,
                "official_challenge_submission": false,
                "official_website": official_website_value
            },

            "limits": {
                "prime_status": "probable_prime",
                "primality_test": "Miller-Rabin with fixed bases",
                "official_submission": false,
                "public_certification": false,
                "server_verified": false
            },

            "hits": filtered_hits,

            "source": {
                "latest_run_summary": CURRENT_RUN_STATE_PATH,
                "hit_source_internal": LOCAL_DISCOVERIES_PATH
            },
            "note": "Full export of the latest local experiment only. This is not an official challenge submission."
        });

        Ok(export_json)
    }

    fn top_tabs(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if Self::prime_tab_button_gui(ui, matches!(self.tab, Tab::Home), "Home").clicked() {
                self.tab = Tab::Home;
            }

            if Self::prime_tab_button_gui(ui, matches!(self.tab, Tab::AdvancedLocal), "Local Test")
                .clicked()
            {
                self.tab = Tab::AdvancedLocal;
            }

            if Self::prime_tab_button_gui(
                ui,
                matches!(self.tab, Tab::OfficialMode),
                "Official Challenge",
            )
            .clicked()
            {
                self.tab = Tab::OfficialMode;
            }
        });
        ui.add_space(2.0);
    }

    fn home_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("MAX Prime Challenge");
        ui.separator();

        ui.label(
            egui::RichText::new("Run local tests. Join official public Challenges.")
                .size(20.0)
                .strong(),
        );

        ui.add_space(14.0);

        Self::prime_card_gui(ui, "Local Test", "Private", |ui| {
            ui.label("Try MAX Prime calculations on your computer.");
            ui.label("Nothing is submitted to the official server.");
        });

        ui.add_space(12.0);

        Self::prime_card_gui(ui, "Official Challenge", "Public", |ui| {
            ui.label("Receive official work packages from the MAX Prime server.");
            ui.label("Your computer computes locally and submits the result.");
        });

        ui.add_space(12.0);

        Self::prime_card_gui(ui, "Official website", "Info", |ui| {
            ui.hyperlink("https://www.max-russo.com");

            ui.collapsing("About this public client", |ui| {
                ui.label("This app cannot create, sign, publish, or modify official Challenges.");
                ui.label(
                    "It contains no admin tools, no private MAX Login code, and no server secrets.",
                );
            });
        });
    }

    fn advanced_local_ui(&mut self, ui: &mut egui::Ui) {
        self.poll_advanced_run_gui();

        ui.heading("Local Test");
        ui.label("Run a private local experiment.");
        ui.label("These results are not submitted to the official server.");
        ui.collapsing("What are N and d?", |ui| {
            ui.monospace(Self::theory_note_text_gui());
        });
        ui.separator();

        egui::Grid::new("advanced_custom_params_grid_simple")
            .num_columns(2)
            .spacing([18.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                ui.label("Experiment ID");
                ui.add(
                    egui::TextEdit::singleline(&mut self.custom_experiment_id).desired_width(560.0),
                );
                ui.end_row();

                ui.label("n0");
                ui.add(egui::TextEdit::singleline(&mut self.custom_n0).desired_width(560.0));
                ui.end_row();

                ui.label("step");
                ui.add(egui::TextEdit::singleline(&mut self.custom_step).desired_width(560.0));
                ui.end_row();

                ui.label("iterations");
                ui.add(
                    egui::TextEdit::singleline(&mut self.custom_iterations).desired_width(180.0),
                );
                ui.end_row();

                ui.label("Targets");
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.custom_test_n, "N");
                    ui.checkbox(&mut self.custom_test_d, "d");
                });
                ui.end_row();

                ui.label("CRT mode");
                ui.vertical(|ui| {
                    ui.radio_value(&mut self.custom_filter_mode, "off".to_string(), "CRT OFF");
                    ui.radio_value(
                        &mut self.custom_filter_mode,
                        "cumulative".to_string(),
                        "CRT cumulative M/R",
                    );
                    ui.radio_value(
                        &mut self.custom_filter_mode,
                        "multi".to_string(),
                        "CRT multi-filter",
                    );
                });
                ui.end_row();

                if self.custom_filter_mode == "cumulative" {
                    ui.label("CRT cumulative M");
                    ui.add(egui::TextEdit::singleline(&mut self.custom_m).desired_width(420.0));
                    ui.end_row();

                    ui.label("CRT cumulative R");
                    ui.add(egui::TextEdit::singleline(&mut self.custom_r).desired_width(420.0));
                    ui.end_row();
                }

                if self.custom_filter_mode == "multi" {
                    ui.label("Original moduli");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.custom_original_moduli)
                            .desired_width(560.0),
                    );
                    ui.end_row();

                    ui.label("Original remainders");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.custom_original_remainders)
                            .desired_width(560.0),
                    );
                    ui.end_row();

                    ui.label("Computed M/R");
                    ui.label(format!("M = {}    R = {}", self.custom_m, self.custom_r));
                    ui.end_row();
                }
            });

        ui.add_space(12.0);

        ui.horizontal_wrapped(|ui| {
            let run_enabled = !self.advanced_run_running;
            if ui
                .add_enabled(run_enabled, egui::Button::new("Run experiment"))
                .clicked()
            {
                self.start_advanced_run_gui();
            }

            let stop_enabled = self.advanced_run_running;
            if ui
                .add_enabled(
                    stop_enabled,
                    egui::Button::new(egui::RichText::new("Stop after current package").strong()),
                )
                .clicked()
            {
                self.stop_advanced_run_gui();
            }

            if ui.button("Show results").clicked() {
                self.show_latest_results_gui();
            }

            if ui.button("Export results").clicked() {
                self.export_latest_results_gui();
            }
        });

        ui.add_space(8.0);
        ui.label(format!("Status: {}", self.status_message));
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.monospace(&self.advanced_preview_text);
            });
    }

    fn official_client_binary_path_gui() -> String {
        "./target/release/max_prime_public_client".to_string()
    }

    fn extract_line_after_label_gui(text: &str, label: &str) -> String {
        let mut take_next = false;

        for line in text.lines() {
            let trimmed = line.trim();

            if take_next && !trimmed.is_empty() {
                return trimmed.to_string();
            }

            if trimmed == label || trimmed.starts_with(label) {
                let rest = trimmed.trim_start_matches(label).trim();
                if !rest.is_empty() {
                    return rest.to_string();
                }
                take_next = true;
            }
        }

        "-".to_string()
    }

    fn extract_value_after_prefix_gui(text: &str, prefix: &str) -> String {
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                return rest.trim().to_string();
            }
        }
        "-".to_string()
    }

    fn extract_submit_payload_path_gui(text: &str) -> Option<String> {
        let mut take_next = false;

        for line in text.lines() {
            let trimmed = line.trim();

            if take_next && trimmed.ends_with("_submit_payload.json") {
                return Some(trimmed.to_string());
            }

            if trimmed.starts_with("Submit payload saved:") {
                let rest = trimmed.trim_start_matches("Submit payload saved:").trim();
                if rest.ends_with("_submit_payload.json") {
                    return Some(rest.to_string());
                }
                take_next = true;
            }
        }

        None
    }

    fn official_stream_final_line_gui(raw: &str, run_index: usize, requested: usize) -> String {
        let lower = raw.to_lowercase();

        let no_work_or_no_active = raw.contains("Server did not assign work")
            || raw.contains("CHALLENGE_COMPLETED")
            || lower.contains("challenge is completed")
            || lower.contains("no active challenge")
            || lower.contains("not assignable")
            || lower.contains("no work")
            || lower.contains("no_work");

        if no_work_or_no_active {
            return format!(
                "■ Run {}/{} | no new work assigned | server says challenge unavailable/completed\n",
                run_index,
                requested
            );
        }

        let work_unit = Self::extract_line_after_label_gui(raw, "Work assigned:");
        let accepted = Self::extract_value_after_prefix_gui(raw, "Accepted:");
        let has_hit = Self::extract_value_after_prefix_gui(raw, "Has hit:");
        let hit_count = Self::extract_value_after_prefix_gui(raw, "Hit count:");
        let completed = Self::extract_value_after_prefix_gui(raw, "Challenge completed:");
        let mode = Self::extract_value_after_prefix_gui(raw, "Server mode:");

        let accepted_ok = accepted.eq_ignore_ascii_case("true");
        let hit_yes =
            has_hit.eq_ignore_ascii_case("true") || hit_count.parse::<usize>().unwrap_or(0) > 0;

        if hit_yes {
            return format!(
                "★ Run {}/{} | {} | HIT FOUND | accepted={} | hit_count={} | completed={} | mode={}\n",
                run_index,
                requested,
                work_unit,
                accepted,
                hit_count,
                completed,
                mode
            );
        }

        if accepted_ok {
            return format!(
                "✓ Run {}/{} | {} | submitted OK | no hit | challenge open\n",
                run_index, requested, work_unit
            );
        }

        format!(
            "⚠ Run {}/{} | {} | submitted but not accepted | accepted={} | completed={} | mode={}\n",
            run_index,
            requested,
            work_unit,
            accepted,
            completed,
            mode
        )
    }

    fn read_last_official_outcome_message_gui() -> Option<String> {
        let txt = fs::read_to_string(LAST_OFFICIAL_OUTCOME_PATH).ok()?;
        let j: Value = serde_json::from_str(&txt).ok()?;

        let kind = j.get("outcome_kind").and_then(|v| v.as_str()).unwrap_or("");
        let challenge_id = j
            .get("challenge_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let work_unit_id = j
            .get("work_unit_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let official_url = j
            .get("official_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://www.max-russo.com");
        let server_message = j
            .get("server_message")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut out = String::new();

        match kind {
            "winner" => {
                out.push_str("CONGRATULATIONS — YOUR COMPUTER FOUND A MAX PRIME HIT!\n");
                out.push_str("=====================================================\n\n");
                out.push_str("The official server accepted and auto-verified your result.\n");
                out.push_str("This result completed the current MAX Prime Challenge.\n\n");
                out.push_str(&format!("Challenge: {}\n", challenge_id));
                out.push_str(&format!("Winning work unit: {}\n", work_unit_id));

                if let Some(hit) = j.get("hit") {
                    out.push_str(&format!(
                        "Candidate type: {}\n",
                        hit.get("candidate_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-")
                    ));
                    out.push_str(&format!(
                        "Index i: {}\n",
                        hit.get("i").and_then(|v| v.as_str()).unwrap_or("-")
                    ));
                    out.push_str(&format!(
                        "Digits: {}\n",
                        hit.get("digits").and_then(|v| v.as_str()).unwrap_or("-")
                    ));
                    out.push_str(&format!(
                        "SHA-256: {}\n",
                        hit.get("sha256").and_then(|v| v.as_str()).unwrap_or("-")
                    ));
                }

                out.push_str("\nThank you for your contribution.\n");
                out.push_str("Official results will be published on:\n");
                out.push_str(official_url);
                out.push_str("\n\nOptional future feature: submit a name or nickname for the official contributors list.\n");
            }

            "completed" | "not_active" => {
                out.push_str("THIS CHALLENGE HAS BEEN COMPLETED\n");
                out.push_str("=================================\n\n");
                out.push_str("Another participant has found a valid MAX Prime hit.\n");
                out.push_str("Thank you for contributing compute power.\n");
                out.push_str("Your processed packages helped advance the search.\n\n");
                out.push_str(
                    "Please check the official MAX Prime Challenge page for the final result:\n",
                );
                out.push_str(official_url);
                out.push_str("\n\nYou can join the next public Challenge when available.\n");
            }

            "late_after_hit" => {
                out.push_str("PACKAGE COMPUTED AFTER CHALLENGE COMPLETION\n");
                out.push_str("===========================================\n\n");
                out.push_str("Your package was computed successfully, but the Challenge was completed before this result could be accepted.\n");
                out.push_str("This is normal in a parallel Challenge: once a valid hit is auto-verified, the server closes the Challenge.\n\n");
                out.push_str("Thank you — your client behaved correctly.\n\n");
                out.push_str(
                    "Please check the official MAX Prime Challenge page for the final result:\n",
                );
                out.push_str(official_url);
                out.push('\n');
            }

            _ => {
                out.push_str("PACKAGE SUBMITTED\n");
                out.push_str("=================\n\n");
                out.push_str("No hit was found in this package.\n");
                out.push_str("The client may continue with the next official package.\n\n");
                out.push_str("Official Challenge page:\n");
                out.push_str(official_url);
                out.push('\n');
            }
        }

        if !server_message.trim().is_empty() {
            out.push_str("\nServer message:\n");
            out.push_str(server_message);
            out.push('\n');
        }

        Some(out)
    }

    fn summarize_official_output_gui(
        raw: &str,
        run_index: usize,
        requested: usize,
    ) -> (String, String, String) {
        let lower = raw.to_lowercase();

        let no_work_or_no_active = raw.contains("Server did not assign work")
            || raw.contains("CHALLENGE_COMPLETED")
            || lower.contains("challenge is completed")
            || lower.contains("no active challenge")
            || lower.contains("not assignable")
            || lower.contains("no work")
            || lower.contains("no_work");

        if no_work_or_no_active {
            let mut current = String::new();
            if let Some(outcome_msg) = Self::read_last_official_outcome_message_gui() {
                current.push_str(&outcome_msg);
                current.push_str("\n");
            } else {
                current.push_str("No active MAX Prime Challenge is available right now.\n\n");
                current.push_str("The app is working correctly.\n");
                current.push_str("The server simply did not assign a new package.\n\n");
                current.push_str("This can happen when:\n");
                current.push_str("• the current public Challenge has already finished;\n");
                current.push_str("• no public Challenge is active at the moment;\n");
                current.push_str(
                    "• all available packages have already been assigned or submitted.\n\n",
                );
                current.push_str("Please check the official MAX Prime Challenge page for the final result or next Challenge:\n");
                current.push_str("https://www.max-russo.com\n");
            }

            let compact = format!(
                "Run {}/{} | no active work assigned | client OK | server returned no work",
                run_index, requested
            );

            return (current, compact, String::new());
        }

        let work_unit = Self::extract_line_after_label_gui(raw, "Work assigned:");
        let accepted = Self::extract_value_after_prefix_gui(raw, "Accepted:");
        let has_hit = Self::extract_value_after_prefix_gui(raw, "Has hit:");
        let hit_count = Self::extract_value_after_prefix_gui(raw, "Hit count:");
        let completed = Self::extract_value_after_prefix_gui(raw, "Challenge completed:");
        let mode = Self::extract_value_after_prefix_gui(raw, "Server mode:");
        let message = Self::extract_value_after_prefix_gui(raw, "Message:");

        let mut current = String::new();
        current.push_str(&format!("Current work unit: {}\n", work_unit));
        current.push_str(&format!("Batch progress: {} / {}\n", run_index, requested));
        current.push_str("Engine: dashu-int\n");
        current.push_str(&format!("Accepted by server: {}\n", accepted));
        current.push_str(&format!("Hit found: {}\n", has_hit));
        current.push_str(&format!("Hit count: {}\n", hit_count));
        current.push_str(&format!("Challenge completed: {}\n", completed));
        current.push_str(&format!("Server mode: {}\n", mode));
        current.push_str(&format!("Server message: {}\n", message));

        let mut compact = format!(
            "Run {}/{} | {} | accepted={} | hit={} | hit_count={} | completed={} | mode={}",
            run_index, requested, work_unit, accepted, has_hit, hit_count, completed, mode
        );

        let mut hit_details = String::new();

        if has_hit.eq_ignore_ascii_case("true") || hit_count.parse::<usize>().unwrap_or(0) > 0 {
            if let Some(outcome_msg) = Self::read_last_official_outcome_message_gui() {
                hit_details.push_str(&outcome_msg);
                hit_details.push_str("\n");
            }

            hit_details.push_str("HIT FOUND\n");
            hit_details.push_str("====================\n");
            hit_details.push_str(&format!("Work unit: {}\n", work_unit));
            hit_details.push_str(&format!("Accepted by server: {}\n", accepted));
            hit_details.push_str(&format!("Server message: {}\n", message));

            if let Some(payload_path) = Self::extract_submit_payload_path_gui(raw) {
                hit_details.push_str(&format!("Submit payload: {}\n", payload_path));

                match fs::read_to_string(&payload_path) {
                    Ok(txt) => match serde_json::from_str::<Value>(&txt) {
                        Ok(j) => {
                            if let Some(hits) = j.get("hits").and_then(|v| v.as_array()) {
                                hit_details.push_str(&format!("Hits in payload: {}\n", hits.len()));

                                for (idx, hit) in hits.iter().enumerate() {
                                    hit_details.push_str("\n");
                                    hit_details.push_str(&format!("Hit #{}\n", idx + 1));
                                    hit_details.push_str(&format!(
                                        "Candidate type: {}\n",
                                        hit.get("candidate_type")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("-")
                                    ));
                                    hit_details.push_str(&format!(
                                        "i: {}\n",
                                        hit.get("i")
                                            .map(|v| v.to_string())
                                            .unwrap_or_else(|| "-".to_string())
                                    ));
                                    hit_details.push_str(&format!(
                                        "digits: {}\n",
                                        hit.get("digits")
                                            .map(|v| v.to_string())
                                            .unwrap_or_else(|| "-".to_string())
                                    ));
                                    hit_details.push_str(&format!(
                                        "sha256: {}\n",
                                        hit.get("sha256").and_then(|v| v.as_str()).unwrap_or("-")
                                    ));

                                    if let Some(candidate) =
                                        hit.get("candidate").and_then(|v| v.as_str())
                                    {
                                        let preview = if candidate.len() > 120 {
                                            format!(
                                                "{}...{}",
                                                &candidate[..60],
                                                &candidate[candidate.len() - 40..]
                                            )
                                        } else {
                                            candidate.to_string()
                                        };
                                        hit_details
                                            .push_str(&format!("candidate preview: {}\n", preview));
                                    }
                                }
                            } else {
                                hit_details
                                    .push_str("Payload parsed, but no hits array was found.\n");
                            }
                        }
                        Err(e) => {
                            hit_details
                                .push_str(&format!("Could not parse submit payload JSON: {}\n", e));
                        }
                    },
                    Err(e) => {
                        hit_details.push_str(&format!("Could not read submit payload: {}\n", e));
                    }
                }
            } else {
                hit_details.push_str("Submit payload path not found in CLI output.\n");
            }

            compact.push_str(" | HIT DETAILS AVAILABLE");
        }

        (current, compact, hit_details)
    }

    fn official_status_url_gui(challenge_id: Option<&str>) -> String {
        match challenge_id {
            Some(id) if !id.trim().is_empty() => {
                format!(
                    "https://www.max-russo.com/max/prime/api-prime-status.php?challenge_id={}",
                    id.trim()
                )
            }
            _ => "https://www.max-russo.com/max/prime/api-prime-status.php".to_string(),
        }
    }

    fn official_http_get_text_gui(url: &str) -> Result<String, String> {
        let response = ureq::get(url)
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        response
            .into_string()
            .map_err(|e| format!("Cannot read HTTP response: {}", e))
    }

    fn run_official_cli_simple_gui(args: &[&str]) -> String {
        match Command::new(Self::official_client_binary_path_gui())
            .args(args)
            .output()
        {
            Ok(out) => {
                let mut txt = String::new();
                txt.push_str(&String::from_utf8_lossy(&out.stdout));
                if !out.stderr.is_empty() {
                    txt.push_str("\nSTDERR:\n");
                    txt.push_str(&String::from_utf8_lossy(&out.stderr));
                }
                txt
            }
            Err(e) => format!("Could not start public client.\n{}", e),
        }
    }

    fn refresh_official_registration_status_gui(&mut self) {
        let txt = Self::run_official_cli_simple_gui(&["official-config"]);
        self.official_registration_log = txt.clone();

        if txt.contains("Participant token stored locally: true")
            || txt.contains("Participant token status: registered")
        {
            self.official_registration_status =
                "MAX Login completed. This computer is registered and can request official work."
                    .to_string();
        } else if txt.contains("Registration status: pending")
            || txt.contains("pending_user_approval")
        {
            self.official_registration_status = "MAX Login registration pending. Approve with MAX App, then click Check registration.".to_string();
        } else {
            self.official_registration_status = "This client is not registered yet.".to_string();
        }
    }

    fn clear_stale_official_outcome_gui(&mut self) {
        let _ = fs::remove_file(LAST_OFFICIAL_OUTCOME_PATH);

        self.official_summary =
            "Ready. Run 1 package, run 5 packages, or start contributing.".to_string();
        self.official_hit_details = "No hit found in this GUI session yet.".to_string();
        self.official_current_work = "No work unit is running yet.".to_string();
        self.official_live_terminal =
            "Full technical client output will appear here during official runs.\n".to_string();
        self.official_work_stream =
            "Live Work\n\nEach assigned package will appear here.\n".to_string();
    }

    fn start_official_registration_gui(&mut self) {
        self.clear_stale_official_outcome_gui();

        let txt = Self::run_official_cli_simple_gui(&["official-login-start"]);
        let qr_text = Self::extract_qr_text_from_registration_log_gui(&txt);

        if txt.contains("already registered")
            || txt.contains("Participant token stored locally:\n   true")
        {
            self.official_registration_status = "MAX Login already completed. This computer is registered and can request official work.".to_string();
            self.official_registration_qr_text.clear();
        } else if txt.contains("Registration started.") || txt.contains("already pending") {
            self.official_registration_status =
                "Waiting for MAX App approval. Keep this window open.".to_string();
            self.official_registration_qr_text = qr_text;
            self.start_registration_auto_poll_gui();
        } else if txt.contains("Registration start failed") {
            self.official_registration_status =
                "MAX Login registration start failed. See technical details.".to_string();
            self.official_registration_qr_text.clear();
        } else {
            self.official_registration_status =
                "MAX Login registration command finished. See technical details.".to_string();
            self.official_registration_qr_text = qr_text;
        }

        self.official_registration_log = txt;
        self.status_message = "MAX Login QR ready. Scan it with MAX App on iPhone.".to_string();
    }

    fn poll_official_registration_gui(&mut self) {
        let txt = Self::run_official_cli_simple_gui(&["official-login-status"]);

        if txt.contains("Registration completed.")
            || txt.contains("Participant token stored locally:\n   true")
            || txt.contains("Participant token status:\n   registered")
            || txt.contains("Participant token status: registered")
        {
            self.official_registration_status =
                "MAX Login completed. This computer is registered and can request official work."
                    .to_string();
            self.official_registration_qr_text.clear();
        } else if txt.to_lowercase().contains("expired") {
            self.official_registration_status =
                "MAX Login request expired. Click Register with MAX Login again.".to_string();
            self.official_registration_qr_text.clear();
        } else if txt.contains("not completed yet") || txt.contains("pending") {
            self.official_registration_status =
                "Waiting for MAX App approval. Keep this window open.".to_string();
            // Keep the QR visible while waiting.
        } else if txt.contains("No registration is in progress") {
            self.official_registration_status =
                "No MAX Login registration is in progress. Click Register with MAX Login first."
                    .to_string();
            self.official_registration_qr_text.clear();
        } else {
            self.official_registration_status =
                "MAX Login registration status checked. See technical details.".to_string();
        }

        self.official_registration_log = txt;
        self.status_message = "MAX Login registration status checked.".to_string();
    }

    fn extract_qr_text_from_registration_log_gui(text: &str) -> String {
        let mut take_next = false;

        for line in text.lines() {
            let trimmed = line.trim();

            if take_next && !trimmed.is_empty() {
                if trimmed.starts_with("(") {
                    return String::new();
                }
                return trimmed.to_string();
            }

            if trimmed == "MAX Login QR text:" {
                take_next = true;
            }
        }

        String::new()
    }

    fn load_qr_text_from_config_gui() -> String {
        let txt = match fs::read_to_string(OFFICIAL_CLIENT_CONFIG_PATH) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };

        let json: Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };

        json.get("qr_text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn current_registration_qr_text_gui(&self) -> String {
        // Persistent QR for the current registration request.
        // Autopoll updates the technical log, but must not make the QR disappear.
        self.official_registration_qr_text.trim().to_string()
    }

    fn draw_qr_code_gui(ui: &mut egui::Ui, text: &str) {
        if text.trim().is_empty() {
            ui.label("QR Code not available yet.");
            return;
        }

        ui.add_space(8.0);
        ui.ctx().request_repaint_after(Duration::from_millis(180));

        let wait_phase = ((ui.input(|i| i.time) * 3.0) as i64).rem_euclid(4);
        let wait_dots = match wait_phase {
            0 => "",
            1 => ".",
            2 => "..",
            _ => "...",
        };

        ui.horizontal_wrapped(|ui| {
            ui.spinner();

            Self::prime_badge_gui(ui, "WAIT", "warn");

            ui.label(
                egui::RichText::new(format!("Waiting{}", wait_dots))
                    .size(22.0)
                    .strong(),
            );
        });

        ui.label(
            egui::RichText::new("Approve this request in MAX App.")
                .size(18.0)
                .strong(),
        );
        ui.label("Keep this window open. The app will continue automatically after approval.");
        ui.add_space(8.0);
        let code = match QrCode::new(text.as_bytes()) {
            Ok(v) => v,
            Err(e) => {
                ui.label(format!("Cannot render QR Code: {}", e));
                return;
            }
        };

        let qr_width = code.width();
        let quiet_zone_modules: usize = 4;
        let total_modules = qr_width + quiet_zone_modules * 2;
        let target_size = 340.0_f32;
        let cell = (target_size / total_modules as f32).floor().max(3.0);
        let size = cell * total_modules as f32;

        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        let painter = ui.painter();

        painter.rect_filled(rect, 0.0, egui::Color32::WHITE);

        let origin = rect.min
            + egui::vec2(
                cell * quiet_zone_modules as f32,
                cell * quiet_zone_modules as f32,
            );

        for y in 0..qr_width {
            for x in 0..qr_width {
                if code[(x, y)] == Color::Dark {
                    let min = origin + egui::vec2(x as f32 * cell, y as f32 * cell);
                    let module_rect = egui::Rect::from_min_size(min, egui::vec2(cell, cell));
                    painter.rect_filled(module_rect, 0.0, egui::Color32::BLACK);
                }
            }
        }
    }

    fn start_registration_auto_poll_gui(&mut self) {
        if self.official_registration_poll_running {
            return;
        }

        let client_path = Self::official_client_binary_path_gui();
        let (tx, rx) = mpsc::channel::<String>();

        self.official_registration_poll_rx = Some(rx);
        self.official_registration_poll_running = true;

        thread::spawn(move || {
            for _ in 0..90 {
                thread::sleep(Duration::from_secs(2));

                let output = Command::new(&client_path)
                    .arg("official-login-status")
                    .output();

                let txt = match output {
                    Ok(out) => {
                        let mut s = String::new();
                        s.push_str(&String::from_utf8_lossy(&out.stdout));
                        if !out.stderr.is_empty() {
                            s.push_str("\nSTDERR:\n");
                            s.push_str(&String::from_utf8_lossy(&out.stderr));
                        }
                        s
                    }
                    Err(e) => format!("Could not poll registration status: {}", e),
                };

                let completed = txt.contains("Registration completed.")
                    || txt.contains("Participant token stored locally:\n   true")
                    || txt.contains("Participant token status:\n   registered")
                    || txt.contains("Participant token status: registered");

                let expired = txt.to_lowercase().contains("expired");

                let _ = tx.send(txt);

                if completed || expired {
                    break;
                }
            }

            let _ = tx.send("__REGISTRATION_AUTO_POLL_DONE__".to_string());
        });
    }

    fn poll_registration_background_gui(&mut self) {
        if let Some(rx) = self.official_registration_poll_rx.take() {
            let mut keep_rx = true;

            while let Ok(msg) = rx.try_recv() {
                if msg == "__REGISTRATION_AUTO_POLL_DONE__" {
                    self.official_registration_poll_running = false;
                    keep_rx = false;
                    break;
                }

                if msg.contains("Registration completed.")
                    || msg.contains("Participant token stored locally:\n   true")
                    || msg.contains("Participant token status:\n   registered")
                    || msg.contains("Participant token status: registered")
                {
                    self.official_registration_status = "MAX Login completed. This computer is registered and can request official work.".to_string();
                    self.status_message = "MAX Login registration completed.".to_string();
                    self.official_registration_qr_text.clear();
                    self.official_registration_poll_running = false;
                    keep_rx = false;
                } else if msg.to_lowercase().contains("expired") {
                    self.official_registration_status =
                        "MAX Login request expired. Click Register with MAX Login again."
                            .to_string();
                    self.status_message = "MAX Login registration expired.".to_string();
                    self.official_registration_qr_text.clear();
                    self.official_registration_poll_running = false;
                    keep_rx = false;
                } else {
                    self.official_registration_status =
                        "Waiting for MAX App approval...".to_string();
                }

                self.official_registration_log = msg;
            }

            if keep_rx {
                self.official_registration_poll_rx = Some(rx);
            }
        }
    }

    fn redact_secret_gui(s: &str) -> String {
        let s = s.trim();
        if s.is_empty() {
            return "—".to_string();
        }

        if s.len() <= 22 {
            return "stored".to_string();
        }

        format!("{}…{}", &s[..12], &s[s.len().saturating_sub(8)..])
    }

    fn read_official_config_value_gui(key: &str) -> String {
        let txt = match fs::read_to_string(OFFICIAL_CLIENT_CONFIG_PATH) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };

        let json: Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };

        json.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn is_official_registered_gui(&self) -> bool {
        let participant_token = Self::read_official_config_value_gui("participant_token");
        let participant_token_status =
            Self::read_official_config_value_gui("participant_token_status");
        let participant_id = Self::read_official_config_value_gui("participant_id");

        !participant_token.trim().is_empty()
            || participant_token_status.eq_ignore_ascii_case("registered")
            || !participant_id.trim().is_empty()
    }

    fn official_login_status_text_gui(&self) -> String {
        if self.is_official_registered_gui() {
            "".to_string()
        } else {
            "MAX Login not completed yet. Register this computer before requesting official work."
                .to_string()
        }
    }

    fn draw_max_login_status_header_gui(&mut self, ui: &mut egui::Ui) {
        let participant_token = Self::read_official_config_value_gui("participant_token");
        let participant_token_status =
            Self::read_official_config_value_gui("participant_token_status");
        let participant_id = Self::read_official_config_value_gui("participant_id");
        let token_id = Self::read_official_config_value_gui("token_id");
        let client_device_id = Self::read_official_config_value_gui("client_device_id");
        let registration_id = Self::read_official_config_value_gui("registration_id");
        let max_id = Self::read_official_config_value_gui("max_id");
        let public_nickname = Self::read_official_config_value_gui("public_nickname");
        let public_display_name = Self::read_official_config_value_gui("public_display_name");

        let registered = self.is_official_registered_gui();

        Self::prime_card_gui(ui, "Start here", "Login and public identity", |ui| {
            ui.horizontal_wrapped(|ui| {
                if registered {
                    ui.label(egui::RichText::new("✅ Registered").size(25.0).strong());
                    ui.add_space(8.0);
                    ui.label("You are ready to participate.");
                } else {
                    ui.label(
                        egui::RichText::new("Not registered yet")
                            .size(25.0)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.label("Register this computer before requesting official work.");
                }
            });

            ui.add_space(12.0);

            if registered {
                ui.horizontal_wrapped(|ui| {
                    if Self::prime_action_button_gui(ui, "Update status", "primary", true).clicked()
                    {
                        let txt =
                            Self::run_official_cli_simple_gui(&["official-participant-status"]);
                        self.official_registration_log = txt;
                        self.status_message = "Status updated from server.".to_string();
                    }

                    if Self::prime_action_button_gui(ui, "Logout", "danger", true).clicked() {
                        let txt = Self::run_official_cli_simple_gui(&["official-logout"]);
                        self.official_registration_log = txt;
                        self.official_registration_status =
                            "Logged out. You can register this computer again.".to_string();
                        self.status_message = "Logged out from MAX Prime Challenge.".to_string();
                        self.official_registration_qr_text.clear();
                        self.official_nickname_input.clear();
                    }

                    ui.label(
                        "Logout disconnects only this computer. Submitted results remain valid.",
                    );
                });

                ui.add_space(16.0);
                ui.label(
                    egui::RichText::new("Your public identity")
                        .size(22.0)
                        .strong(),
                );

                egui::Grid::new("max_prime_public_identity_grid_simple_v2")
                    .num_columns(2)
                    .spacing([18.0, 9.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("MAX ID").strong());
                        ui.monospace(if max_id.is_empty() {
                            "—"
                        } else {
                            max_id.as_str()
                        });
                        ui.end_row();

                        ui.label(egui::RichText::new("Nickname").strong());
                        ui.monospace(if public_nickname.is_empty() {
                            "—"
                        } else {
                            public_nickname.as_str()
                        });
                        ui.end_row();

                        ui.label(egui::RichText::new("Shown publicly").strong());
                        ui.monospace(if public_display_name.is_empty() {
                            "—"
                        } else {
                            public_display_name.as_str()
                        });
                        ui.end_row();
                    });

                if self.official_nickname_input.trim().is_empty()
                    && !public_nickname.trim().is_empty()
                {
                    self.official_nickname_input = public_nickname.clone();
                }

                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("Nickname").strong());
                    ui.add_sized(
                        [300.0, 28.0],
                        egui::TextEdit::singleline(&mut self.official_nickname_input),
                    );

                    if Self::prime_action_button_gui(ui, "Save nickname", "primary", true).clicked()
                    {
                        let nick = self.official_nickname_input.trim().to_string();
                        let txt = Self::run_official_cli_simple_gui(&[
                            "official-set-nickname",
                            nick.as_str(),
                        ]);
                        self.official_registration_log = txt.clone();
                        self.status_message = "Nickname saved.".to_string();

                        let refreshed =
                            Self::run_official_cli_simple_gui(&["official-participant-status"]);
                        self.official_registration_log
                            .push_str("\n\n=== STATUS UPDATE ===\n");
                        self.official_registration_log.push_str(&refreshed);
                    }

                    if Self::prime_action_button_gui(ui, "Clear nickname", "neutral", true)
                        .clicked()
                    {
                        self.official_nickname_input.clear();
                        let txt = Self::run_official_cli_simple_gui(&["official-clear-nickname"]);
                        self.official_registration_log = txt.clone();
                        self.status_message = "Nickname cleared.".to_string();

                        let refreshed =
                            Self::run_official_cli_simple_gui(&["official-participant-status"]);
                        self.official_registration_log
                            .push_str("\n\n=== STATUS UPDATE ===\n");
                        self.official_registration_log.push_str(&refreshed);
                    }
                });

                ui.add_space(12.0);
                ui.collapsing("Technical details", |ui| {
                    egui::Grid::new("max_login_technical_details_grid_v2")
                        .num_columns(2)
                        .spacing([18.0, 8.0])
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Participant ID").strong());
                            ui.monospace(if participant_id.is_empty() { "—" } else { participant_id.as_str() });
                            ui.end_row();

                            ui.label(egui::RichText::new("Device ID").strong());
                            ui.monospace(if client_device_id.is_empty() { "—" } else { client_device_id.as_str() });
                            ui.end_row();

                            ui.label(egui::RichText::new("Token ID").strong());
                            ui.monospace(if token_id.is_empty() { "—" } else { token_id.as_str() });
                            ui.end_row();

                            ui.label(egui::RichText::new("Token status").strong());
                            ui.monospace(if participant_token_status.is_empty() { "registered" } else { participant_token_status.as_str() });
                            ui.end_row();

                            ui.label(egui::RichText::new("Registration ID").strong());
                            ui.monospace(if registration_id.is_empty() { "—" } else { registration_id.as_str() });
                            ui.end_row();

                            ui.label(egui::RichText::new("Participant token").strong());
                            ui.monospace(Self::redact_secret_gui(&participant_token));
                            ui.end_row();
                        });

                    ui.add_space(6.0);
                    ui.label("These values are diagnostics. Normal participation does not require reading them.");
                    ui.add_space(6.0);
                    ui.label(&self.official_registration_log);
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    if Self::prime_action_button_gui(ui, "Register with MAX Login", "primary", true)
                        .clicked()
                    {
                        self.start_official_registration_gui();
                        self.start_registration_auto_poll_gui();
                    }

                    if Self::prime_action_button_gui(ui, "Check registration", "neutral", true)
                        .clicked()
                    {
                        self.poll_official_registration_gui();
                    }
                });

                ui.add_space(10.0);
                ui.label("Scan the QR Code with MAX App. After approval, this computer can request official work.");

                let qr_text = self.current_registration_qr_text_gui();
                if !qr_text.trim().is_empty() {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Scan this QR Code with MAX App").strong());
                    Self::draw_qr_code_gui(ui, &qr_text);
                }

                ui.add_space(10.0);
                ui.collapsing("Raw registration log", |ui| {
                    ui.label(&self.official_registration_log);
                });
            }

            ui.add_space(12.0);
            ui.collapsing("How participation works", |ui| {
                ui.label("1. Register this computer with MAX Login.");
                ui.label("2. The server assigns an official work package.");
                ui.label("3. Your computer calculates the package locally.");
                ui.label("4. The result is submitted to the MAX Prime server.");
                ui.label("5. A valid hit is verified server-side before it counts.");
                ui.add_space(6.0);
                ui.label("Your MAX ID is the official public identity. The nickname is only an optional display name.");
            });
        });
    }

    fn collect_public_active_challenge_ids_gui(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                let cid = map.get("challenge_id").and_then(|v| v.as_str());
                let status = map.get("status").and_then(|v| v.as_str());

                if let (Some(cid), Some(status)) = (cid, status) {
                    if status == "PUBLIC_ACTIVE" {
                        out.push(cid.to_string());
                    }
                }

                for v in map.values() {
                    Self::collect_public_active_challenge_ids_gui(v, out);
                }
            }
            Value::Array(items) => {
                for v in items {
                    Self::collect_public_active_challenge_ids_gui(v, out);
                }
            }
            _ => {}
        }
    }

    fn discover_active_official_challenge_gui() -> Result<String, String> {
        let url = Self::official_status_url_gui(None);
        let txt = Self::official_http_get_text_gui(&url)?;
        let json: Value = serde_json::from_str(&txt)
            .map_err(|e| format!("Cannot parse server status JSON: {}", e))?;

        let mut ids = Vec::new();
        Self::collect_public_active_challenge_ids_gui(&json, &mut ids);

        ids.sort();
        ids.dedup();

        if ids.is_empty() {
            return Err(
                "No active MAX Prime Challenge is available right now.\n\nThe app is working correctly.\nCheck the official MAX Prime Challenge page for final results or the next Challenge:\nhttps://www.max-russo.com"
                    .to_string(),
            );
        }

        // Prefer a PUBLIC_ACTIVE challenge that is not completed, not paused, and still has remaining work.
        for cid in &ids {
            let detail_url = Self::official_status_url_gui(Some(cid));
            let detail_txt = match Self::official_http_get_text_gui(&detail_url) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let detail_json: Value = match serde_json::from_str(&detail_txt) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let progress = &detail_json["data"]["progress"];

            let completed = progress["completed"].as_bool().unwrap_or(false);
            let paused = progress["paused"].as_bool().unwrap_or(false);
            let remaining = progress["remaining_work_units_estimate"]
                .as_i64()
                .unwrap_or(1);
            let status = detail_json["data"]["challenge"]["status"]
                .as_str()
                .unwrap_or("");

            if status == "PUBLIC_ACTIVE" && !completed && !paused && remaining != 0 {
                return Ok(cid.clone());
            }
        }

        Err(
            "No active MAX Prime Challenge is available right now.\n\nThe app is working correctly.\nThe server has public challenges listed, but none appears to have available work right now.\n\nCheck the official MAX Prime Challenge page for final results or the next Challenge:\nhttps://www.max-russo.com"
                .to_string(),
        )
    }

    fn fetch_challenge_progress_summary_gui(challenge_id: &str) -> String {
        let url = Self::official_status_url_gui(Some(challenge_id));

        let txt = match Self::official_http_get_text_gui(&url) {
            Ok(v) => v,
            Err(e) => return format!("Could not load server status.\n{}", e),
        };

        let j: Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(e) => return format!("Could not parse server status JSON.\n{}", e),
        };

        let challenge = &j["data"]["challenge"];
        let manifest = &j["data"]["manifest"];
        let progress = &j["data"]["progress"];

        let cid = challenge["challenge_id"].as_str().unwrap_or(challenge_id);
        let title = challenge["title"].as_str().unwrap_or("-");
        let status = challenge["status"].as_str().unwrap_or("-");
        let total_work_units = manifest["total_work_units"].as_i64().unwrap_or(-1);
        let total_iterations = manifest["total_iterations"].as_i64().unwrap_or(-1);
        let package_size = manifest["package_size"].as_i64().unwrap_or(-1);
        let assigned = progress["assigned_work_units"].as_i64().unwrap_or(-1);
        let submitted = progress["submitted_results"].as_i64().unwrap_or(-1);
        let hits = progress["hits"].as_i64().unwrap_or(-1);
        let remaining = progress["remaining_work_units_estimate"]
            .as_i64()
            .unwrap_or(-1);
        let completed = progress["completed"].as_bool().unwrap_or(false);
        let paused = progress["paused"].as_bool().unwrap_or(false);

        format!(
            "Active challenge: {}\nTitle: {}\nStatus: {}\n\nWork units: submitted {} / total {}\nAssigned: {}\nRemaining estimate: {}\nHits: {}\n\nTotal iterations: {}\nPackage size: {}\nCompleted: {}\nPaused: {}",
            cid,
            title,
            status,
            submitted,
            total_work_units,
            assigned,
            remaining,
            hits,
            total_iterations,
            package_size,
            completed,
            paused
        )
    }

    fn current_line_from_cli_gui(line: &str, run_index: usize, requested: usize) -> Option<String> {
        let t = line.trim();

        let progress_header = if requested >= OFFICIAL_CONTINUOUS_MAX_PACKAGES {
            format!("Current package: {}", run_index)
        } else {
            format!("Current run: {} of {}", run_index, requested)
        };

        if t.starts_with("Step 1/4:") {
            return Some(format!(
                "{}\nRequesting a work unit from the server...",
                progress_header
            ));
        }

        if t.starts_with("Step 2/4:") {
            return Some(format!(
                "{}\nComputing the assigned work unit with dashu-int...",
                progress_header
            ));
        }

        if t.starts_with("Step 3/4:") {
            return Some(format!(
                "{}\nSubmitting the result to the server...",
                progress_header
            ));
        }

        if t.starts_with("Step 4/4:") {
            return Some(format!(
                "{}\nReading the server response...",
                progress_header
            ));
        }

        if t.contains("-WU-") {
            return Some(format!("{}\nCurrent work unit: {}", progress_header, t));
        }

        if t.starts_with("Hits found:") {
            return Some(format!("{}\n{}", progress_header, t));
        }

        if t.starts_with("Accepted:")
            || t.starts_with("Has hit:")
            || t.starts_with("Challenge completed:")
        {
            return Some(format!("{}\n{}", progress_header, t));
        }

        None
    }

    fn apply_no_active_challenge_gui(&mut self, technical_detail: &str) {
        let outcome_msg = Self::read_last_official_outcome_message_gui().unwrap_or_else(|| {
            let mut msg = String::new();
            msg.push_str("NO ACTIVE PUBLIC CHALLENGE
");
            msg.push_str("==========================

");
            msg.push_str("There is no active MAX Prime Challenge right now.

");
            msg.push_str("The app is working correctly.
");
            msg.push_str("A package can start only when the official server publishes a new active Challenge.

");
            msg.push_str("Check the official page for final results or the next Challenge:
");
            msg.push_str("https://www.max-russo.com
");
            msg
        });

        self.official_detected_challenge = "No active public Challenge detected.".to_string();

        self.official_server_status = if outcome_msg.contains("CONGRATULATIONS") {
            "Challenge completed by an auto-verified MAX Prime hit.\n\nSee Official Result for the winning hit details.".to_string()
        } else if outcome_msg.contains("THIS CHALLENGE HAS BEEN COMPLETED") {
            "Challenge completed.\n\nSee Official Result for the final result.".to_string()
        } else {
            "No active public Challenge right now.\n\nYour computer is registered and ready.\nWhen a Challenge is published, you will be able to start contributing here.".to_string()
        };

        self.official_current_work = format!(
            "No package is running.

{}

Check the official MAX Prime Challenge page:
https://www.max-russo.com",
            if technical_detail.trim().is_empty() {
                "The server did not assign a package because there is no active public Challenge."
            } else {
                technical_detail
            }
        );

        self.official_summary = outcome_msg.clone();

        self.official_hit_details = "No hit found by this app in the current GUI session.

If the Challenge has already been completed, check the official result on:
https://www.max-russo.com
"
        .to_string();

        self.official_live_terminal =
            "No client process was started because there is no active public Challenge.
"
            .to_string();

        self.official_work_stream.push_str(
            "■ No active public Challenge detected. No package was started. Check max-russo.com for final results or the next Challenge.
"
        );

        self.status_message = "No active public Challenge available. Check max-russo.com for final results or the next Challenge.".to_string();
    }

    fn start_official_server_run_gui(&mut self, count: usize) {
        if self.official_run_running {
            self.status_message = "Official Challenge run is already running.".to_string();
            return;
        }

        self.refresh_official_registration_status_gui();
        if !self.is_official_registered_gui() {
            self.status_message =
                "MAX Login required: register this computer before starting official work."
                    .to_string();
            self.official_summary = "Official work blocked locally: MAX Login registration is required. The server also rejects anonymous get-work and submit-result.".to_string();
            return;
        }

        let manual_id = self.official_challenge_id.trim().to_string();

        let challenge_id = if self.official_auto_select
            || manual_id.is_empty()
            || manual_id.eq_ignore_ascii_case("AUTO")
        {
            match Self::discover_active_official_challenge_gui() {
                Ok(id) => {
                    self.official_challenge_id = id.clone();
                    self.official_detected_challenge = format!("Current public Challenge: {}", id);
                    id
                }
                Err(e) => {
                    self.apply_no_active_challenge_gui(&e);
                    return;
                }
            }
        } else {
            manual_id
        };

        self.official_server_status = Self::fetch_challenge_progress_summary_gui(&challenge_id);

        let client_path = Self::official_client_binary_path_gui();
        let (tx, rx) = mpsc::channel::<String>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop_flag = Arc::clone(&stop_flag);

        let run_goal = if count >= OFFICIAL_CONTINUOUS_MAX_PACKAGES {
            "continuous contribution mode".to_string()
        } else {
            format!("{} requested package(s)", count)
        };

        self.official_run_running = true;
        self.official_run_rx = Some(rx);
        self.official_stop_flag = Some(stop_flag);
        self.official_requested_units = count;

        /*
         * official_completed_units is the cumulative number of packages
         * accepted during the current GUI session.
         *
         * It must not be reset every time the user starts Run 1, Run 5,
         * or continuous contribution mode. It resets naturally only when
         * the GUI application is closed and reopened.
         */
        self.status_message = format!("Official Challenge started: {}.", run_goal);
        self.official_summary = format!("Running {} for {}.", run_goal, challenge_id);
        self.official_current_work = format!(
            "Starting official contribution for active challenge:\n{}",
            challenge_id
        );

        self.official_live_terminal = format!(
            "=== LIVE TERMINAL OUTPUT ===\nChallenge ID: {}\nRequested work units: {}\nClient: {}\n\n",
            challenge_id,
            count,
            client_path
        );

        self.official_work_stream = format!(
            "=== LIVE WORK STREAM ===\nChallenge ID: {}\nRequested work units: {}\n\nLegend:\n▶ started\n→ step update\n✓ submitted OK\n★ hit found\n■ stopped/no work\n\n",
            challenge_id,
            count
        );

        self.official_run_log.push_str(&format!(
            "\n=== START OFFICIAL CHALLENGE RUN ===\nChallenge ID: {}\nRequested work units: {}\nClient: {}\n\n",
            challenge_id,
            count,
            client_path
        ));

        thread::spawn(move || {
            for n in 1..=count {
                if thread_stop_flag.load(Ordering::SeqCst) {
                    let _ = tx.send(
                        "__SUMMARY__STOP: stop requested. No new package will be started."
                            .to_string(),
                    );
                    let _ = tx.send(
                        "__STREAM__■ Stop requested. No new package will be started.\n".to_string(),
                    );
                    break;
                }

                let display_total = if count >= OFFICIAL_CONTINUOUS_MAX_PACKAGES {
                    "continuous".to_string()
                } else {
                    count.to_string()
                };

                let _ = tx.send(format!(
                    "__CURRENT__Preparing official package {} / {}...\nChallenge: {}",
                    n, display_total, challenge_id
                ));
                let _ = tx.send(format!(
                    "__STREAM__▶ Package {} / {} | waiting for assignment\n",
                    n, display_total
                ));
                let _ = tx.send(format!(
                    "__LOG__\n--- OFFICIAL PACKAGE {} / {} ---\n",
                    n, display_total
                ));

                let mut child = match Command::new(&client_path)
                    .arg("official-run-once")
                    .arg(&challenge_id)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send(format!(
                            "__CURRENT__ERROR: cannot start public client.\n{}",
                            e
                        ));
                        let _ = tx.send(format!(
                            "__SUMMARY__ERROR: cannot start public client: {}",
                            e
                        ));
                        break;
                    }
                };

                let mut combined = String::new();

                if let Some(stdout) = child.stdout.take() {
                    let reader = BufReader::new(stdout);

                    for line_result in reader.lines() {
                        match line_result {
                            Ok(line) => {
                                combined.push_str(&line);
                                combined.push('\n');

                                let _ = tx.send(format!("__LOG__{}\n", line));

                                if let Some(current) =
                                    Self::current_line_from_cli_gui(&line, n, count)
                                {
                                    let _ = tx.send(format!("__CURRENT__{}", current));

                                    let trimmed = line.trim();

                                    if trimmed.starts_with("Step 1/4:") {
                                        let _ = tx.send(
                                            "__STREAM__   → requesting official work
"
                                            .to_string(),
                                        );
                                    } else if trimmed.starts_with("Step 2/4:") {
                                        let _ = tx.send(
                                            "__STREAM__   → computing with dashu-int
"
                                            .to_string(),
                                        );
                                    } else if trimmed.starts_with("Step 3/4:") {
                                        let _ = tx.send(
                                            "__STREAM__   → submitting result to server
"
                                            .to_string(),
                                        );
                                    } else if trimmed.starts_with("Step 4/4:") {
                                        let _ = tx.send(
                                            "__STREAM__   → reading server response
"
                                            .to_string(),
                                        );
                                    } else if trimmed.starts_with("Work assigned:") {
                                        let _ = tx.send(
                                            "__STREAM__   → assignment received
"
                                            .to_string(),
                                        );
                                    } else if trimmed.contains("-WU-") {
                                        let _ = tx.send(format!(
                                            "__STREAM__   → assigned {}
",
                                            trimmed
                                        ));
                                    } else if trimmed.starts_with("Hits found:") {
                                        let hits = trimmed.trim_start_matches("Hits found:").trim();
                                        let _ = tx.send(format!(
                                            "__STREAM__   → computed | hits {}
",
                                            hits
                                        ));
                                    } else if trimmed.starts_with("Accepted:") {
                                        let accepted =
                                            trimmed.trim_start_matches("Accepted:").trim();
                                        let _ = tx.send(format!(
                                            "__STREAM__   → server accepted: {}
",
                                            accepted
                                        ));
                                    } else if trimmed.starts_with("Has hit:") {
                                        let has_hit = trimmed.trim_start_matches("Has hit:").trim();
                                        if has_hit.eq_ignore_ascii_case("true") {
                                            let _ = tx.send(
                                                "__STREAM__   → ★ HIT reported by server
"
                                                .to_string(),
                                            );
                                        }
                                    } else if trimmed.starts_with("Challenge completed:") {
                                        let completed = trimmed
                                            .trim_start_matches("Challenge completed:")
                                            .trim();
                                        if completed.eq_ignore_ascii_case("true") {
                                            let _ = tx.send(
                                                "__STREAM__   → challenge completed
"
                                                .to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(format!("__LOG__STDOUT read error: {}\n", e));
                            }
                        }
                    }
                }

                let status = match child.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx.send(format!(
                            "__SUMMARY__ERROR: public client wait failed: {}",
                            e
                        ));
                        break;
                    }
                };

                if let Some(mut stderr) = child.stderr.take() {
                    let mut stderr_text = String::new();
                    if stderr.read_to_string(&mut stderr_text).is_ok()
                        && !stderr_text.trim().is_empty()
                    {
                        combined.push_str("\nSTDERR:\n");
                        combined.push_str(&stderr_text);
                        let _ = tx.send(format!("__LOG__\nSTDERR:\n{}\n", stderr_text));
                    }
                }

                let (current, compact, hit_details) =
                    Self::summarize_official_output_gui(&combined, n, count);

                let final_stream_line = Self::official_stream_final_line_gui(&combined, n, count);

                let _ = tx.send(format!("__CURRENT__{}", current));
                let _ = tx.send(format!("__SUMMARY__{}", compact));
                let _ = tx.send(format!("__STREAM_FINAL__{}", final_stream_line));
                let _ = tx.send(format!(
                    "__STATUS__{}",
                    Self::fetch_challenge_progress_summary_gui(&challenge_id)
                ));

                if !hit_details.trim().is_empty() {
                    let _ = tx.send(format!("__HIT__{}", hit_details));
                }

                if !status.success() {
                    let _ = tx.send(format!(
                        "__SUMMARY__STOP: public client returned an error. Exit status: {}",
                        status
                    ));
                    break;
                }

                let accepted_by_server = combined
                    .lines()
                    .any(|line| line.trim().eq_ignore_ascii_case("Accepted: true"));

                if accepted_by_server {
                    let _ = tx.send("__ACCEPTED_UNIT__".to_string());
                }

                if combined.contains("Has hit: true")
                    || combined.contains("Challenge completed: true")
                    || combined.contains("CHALLENGE_COMPLETED")
                    || combined.contains("Server did not assign work")
                {
                    let _ = tx.send(
                        "__SUMMARY__STOP: hit found, challenge completed, or server did not assign more work."
                            .to_string(),
                    );
                    break;
                }

                if thread_stop_flag.load(Ordering::SeqCst) {
                    let _ = tx
                        .send("__SUMMARY__STOP: stop requested after current package.".to_string());
                    let _ = tx.send(
                        "__STREAM__■ Stop requested after current package. Contribution paused.\n"
                            .to_string(),
                    );
                    break;
                }

                thread::sleep(Duration::from_millis(500));
            }

            let _ = tx.send("__LOG__\n=== OFFICIAL CHALLENGE RUN FINISHED ===\n".to_string());
            let _ = tx.send("__MAX_PRIME_OFFICIAL_DONE__".to_string());
        });
    }

    fn poll_official_server_run_gui(&mut self) {
        if let Some(rx) = self.official_run_rx.take() {
            let mut keep_rx = true;

            while let Ok(msg) = rx.try_recv() {
                if msg == "__MAX_PRIME_OFFICIAL_DONE__" {
                    self.official_run_running = false;
                    self.official_stop_flag = None;
                    self.status_message = "Official Challenge run finished.".to_string();
                    keep_rx = false;
                    break;
                } else if let Some(rest) = msg.strip_prefix("__CURRENT__") {
                    self.official_current_work = rest.to_string();
                } else if msg == "__ACCEPTED_UNIT__" {
                    self.official_completed_units += 1;
                } else if let Some(rest) = msg.strip_prefix("__SUMMARY__") {
                    if let Some(outcome_msg) = Self::read_last_official_outcome_message_gui() {
                        if outcome_msg.contains("CONGRATULATIONS")
                            || outcome_msg.contains("THIS CHALLENGE HAS BEEN COMPLETED")
                            || outcome_msg.contains("PACKAGE COMPUTED AFTER CHALLENGE COMPLETION")
                        {
                            self.official_summary = outcome_msg;
                        } else {
                            self.official_summary = rest.to_string();
                        }
                    } else {
                        self.official_summary = rest.to_string();
                    }
                    self.official_run_log.push_str("\nSUMMARY: ");
                    self.official_run_log.push_str(rest);
                    self.official_run_log.push('\n');

                    self.official_live_terminal.push_str("\nSUMMARY: ");
                    self.official_live_terminal.push_str(rest);
                    self.official_live_terminal.push('\n');

                    // Live Work Stream is updated through __STREAM__ and __STREAM_FINAL__ messages.
                } else if let Some(rest) = msg.strip_prefix("__STREAM__") {
                    self.official_work_stream.push_str(rest);
                    self.official_live_terminal.push_str(rest);
                } else if let Some(rest) = msg.strip_prefix("__STATUS__") {
                    self.official_server_status = rest.to_string();
                } else if let Some(rest) = msg.strip_prefix("__HIT__") {
                    self.official_hit_details = rest.to_string();
                } else if let Some(rest) = msg.strip_prefix("__LOG__") {
                    self.official_run_log.push_str(rest);
                    self.official_live_terminal.push_str(rest);
                } else {
                    self.official_run_log.push_str(&msg);
                    self.official_live_terminal.push_str(&msg);
                }
            }

            if keep_rx {
                self.official_run_rx = Some(rx);
            }
        }
    }

    fn stop_official_after_current_package_gui(&mut self) {
        if let Some(flag) = &self.official_stop_flag {
            flag.store(true, Ordering::SeqCst);
            self.status_message =
                "Stop requested. The current package will finish first.".to_string();
            self.official_summary =
                "Stop requested. The app will finish the current package, submit it, then pause."
                    .to_string();
            self.official_work_stream
                .push_str("■ Stop requested by user. Current package will finish first.\n");
        } else {
            self.status_message = "No official contribution is currently running.".to_string();
        }
    }

    fn official_mode_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Official Challenge");

        ui.collapsing("Security model", |ui| {
            Self::prime_badge_gui(ui, "public client", "blue");
            Self::prime_badge_gui(ui, "MAX Login required", "ok");
            Self::prime_badge_gui(ui, "no admin tools", "warn");
            ui.add_space(6.0);
            ui.label("The server accepts only assigned, authenticated, verified official work.");
        });

        ui.add_space(8.0);

        // Removed duplicate login/introduction card #1. Single login identity card remains above.

        ui.add_space(10.0);

        self.draw_max_login_status_header_gui(ui);

        if !self.is_official_registered_gui() {
            Self::prime_card_gui(ui, "Official work locked", "Security", |ui| {
                Self::prime_badge_gui(ui, "MAX Login required", "warn");
                ui.add_space(6.0);
                ui.label(
                    "Official run buttons are disabled until MAX Login registration is completed.",
                );
            });
        }

        // Removed duplicate login/introduction card #2. Single login identity card remains above.

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Current Challenge", "Official Work", |ui| {
            ui.horizontal(|ui| {
                self.official_auto_select = true;
                ui.label("The app automatically uses the current public Challenge from the MAX Prime server.");

                if ui
                    .add_enabled(!self.official_run_running, egui::Button::new(egui::RichText::new("Refresh").strong()))
                    .clicked()
                {
                    match Self::discover_active_official_challenge_gui() {
                        Ok(id) => {
                            self.official_challenge_id = id.clone();
                            self.official_detected_challenge = format!("Current public Challenge: {}", id);
                            self.official_server_status = Self::fetch_challenge_progress_summary_gui(&id);
                            self.status_message = "Active challenge refreshed.".to_string();
                        }
                        Err(e) => {
                            self.apply_no_active_challenge_gui(&e);
                        }
                    }
                }
            });

            ui.add_space(6.0);
            ui.label(&self.official_detected_challenge);

            ui.horizontal_wrapped(|ui| {
                if Self::prime_action_button_gui(
                    ui,
                    "Run 1 package",
                    "success",
                    !self.official_run_running && self.is_official_registered_gui(),
                )
                .clicked()
                {
                    self.start_official_server_run_gui(1);
                }

                if Self::prime_action_button_gui(
                    ui,
                    "Run 5 packages",
                    "success",
                    !self.official_run_running && self.is_official_registered_gui(),
                )
                .clicked()
                {
                    self.start_official_server_run_gui(5);
                }

                if Self::prime_action_button_gui(
                    ui,
                    "Start contributing",
                    "primary",
                    !self.official_run_running && self.is_official_registered_gui(),
                )
                .clicked()
                {
                    self.start_official_server_run_gui(OFFICIAL_CONTINUOUS_MAX_PACKAGES);
                }

                if Self::prime_action_button_gui(
                    ui,
                    "Stop after current package",
                    "warning",
                    self.official_run_running,
                )
                .clicked()
                {
                    self.stop_official_after_current_package_gui();
                }
            });

            ui.add_space(8.0);
            ui.label("Run 1 package: quick connection and computation test.");
            ui.label("Run 5 packages: short controlled contribution test.");
            ui.label("Start contributing: keep working until stopped or until the Challenge ends.");
        });

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Challenge Progress", "Status", |ui| {
            let mut progress_view = self.official_server_status.clone();

            if progress_view.contains("CONGRATULATIONS") {
                progress_view = "Challenge completed by an auto-verified MAX Prime hit.\n\nSee Official Result for the winning hit details.".to_string();
            }

            ui.add(
                egui::TextEdit::multiline(&mut progress_view)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
        });

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Current Package", "Work unit", |ui| {
            let continuous_mode = self.official_requested_units >= OFFICIAL_CONTINUOUS_MAX_PACKAGES;

            ui.horizontal_wrapped(|ui| {
                if self.official_run_running {
                    Self::prime_badge_gui(ui, "RUNNING", "ok");
                } else {
                    Self::prime_badge_gui(ui, "READY", "blue");
                }

                let session_label =
                    format!("{} accepted this session", self.official_completed_units);

                Self::prime_badge_gui(ui, &session_label, "blue");

                if continuous_mode {
                    Self::prime_badge_gui(ui, "CONTINUOUS MODE", "blue");
                } else if self.official_requested_units > 0 {
                    let current_run_label = format!(
                        "Current run: {} package{}",
                        self.official_requested_units,
                        if self.official_requested_units == 1 {
                            ""
                        } else {
                            "s"
                        }
                    );

                    Self::prime_badge_gui(ui, &current_run_label, "blue");
                }
            });

            ui.add_space(6.0);

            if continuous_mode {
                ui.label(
                    "Accepted this session counts packages accepted by the server since this app was opened. Continuous mode requests one package at a time until stopped.",
                );
            } else {
                ui.label(
                    "Accepted this session is cumulative since this app was opened. Current run shows how many packages were requested by the latest command.",
                );
            }

            if self.official_run_running {
                ui.ctx().request_repaint_after(Duration::from_millis(350));

                let animation_step = ((ui.input(|input| input.time) * 2.5) as usize % 3) + 1;
                let dots = ".".repeat(animation_step);

                ui.add_space(8.0);
                ui.label(egui::RichText::new(format!("Testing current package{}", dots)).strong());
                ui.label(
                    "Large candidates can take longer. The application is still working normally.",
                );
            }

            ui.add_space(8.0);

            ui.add(
                egui::TextEdit::multiline(&mut self.official_current_work)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
        });

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Official result", "Clean view", |ui| {
            let has_hit = self.official_summary.contains("CONGRATULATIONS")
                || self.official_hit_details.contains("HIT FOUND")
                || self.official_hit_details.contains("Candidate type:")
                || self.official_hit_details.contains("sha256:");

            let challenge_done = self.official_summary.contains("completed")
                || self
                    .official_current_work
                    .contains("Challenge completed: true")
                || self
                    .official_server_status
                    .contains("COMPLETED_BY_AUTO_VERIFIED_HIT");

            if has_hit {
                Self::prime_badge_gui(ui, "MAX PRIME HIT FOUND", "ok");
                ui.add_space(8.0);

                let mut clean_result = String::new();

                if let Some(msg) = Self::read_last_official_outcome_message_gui() {
                    clean_result.push_str(&msg);
                } else if !self.official_hit_details.trim().is_empty() {
                    clean_result.push_str(&self.official_hit_details);
                } else {
                    clean_result.push_str(&self.official_summary);
                }

                ui.add(
                    egui::TextEdit::multiline(&mut clean_result)
                        .desired_rows(13)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );

                ui.add_space(8.0);

                if Self::prime_action_button_gui(ui, "Export winning hit data", "primary", true)
                    .clicked()
                {
                    self.export_official_winning_hit_data_gui();
                }

                ui.label("Save the official winning hit data as JSON for inspection and local reproducibility.");
                ui.add_space(8.0);

                ui.collapsing("Technical hit details", |ui| {
                    let mut details = self.official_hit_details.clone();

                    if details.trim().is_empty() {
                        details =
                            "No separate technical hit details are available yet.".to_string();
                    }

                    ui.add(
                        egui::TextEdit::multiline(&mut details)
                            .desired_rows(18)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
            } else if challenge_done {
                Self::prime_badge_gui(ui, "Challenge completed", "ok");
                ui.add_space(8.0);

                let mut clean_result = self.official_summary.clone();

                ui.add(
                    egui::TextEdit::multiline(&mut clean_result)
                        .desired_rows(10)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
            } else {
                Self::prime_badge_gui(ui, "Ready", "blue");
                ui.add_space(8.0);

                let mut clean_result = self.official_summary.clone();

                ui.add(
                    egui::TextEdit::multiline(&mut clean_result)
                        .desired_rows(6)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
            }
        });

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Live activity", "Compact", |ui| {
            let mut compact_activity = String::new();

            if self.official_work_stream.trim().is_empty() {
                compact_activity.push_str("No package activity yet.\n");
            } else {
                compact_activity.push_str(&self.official_work_stream);
            }

            ui.add(
                egui::TextEdit::multiline(&mut compact_activity)
                    .desired_rows(12)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );

            ui.collapsing("Full technical log", |ui| {
                let mut full_log = String::new();

                full_log.push_str("=== LIVE TERMINAL ===\n");
                full_log.push_str(&self.official_live_terminal);
                full_log.push_str("\n\n=== FULL RUN LOG ===\n");
                full_log.push_str(&self.official_run_log);

                ui.add(
                    egui::TextEdit::multiline(&mut full_log)
                        .desired_rows(24)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
            });
        });

        ui.add_space(10.0);

        Self::prime_card_gui(ui, "Official information", "Website", |ui| {
            ui.hyperlink("https://www.max-russo.com");
            ui.label("The app receives official packages, computes them locally, and submits the result to the official MAX Prime Challenge server.");
        });
    }

    fn self_check_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Diagnostics");
        ui.separator();

        ui.label("This page checks the local public client only.");
        ui.label("It does not contact the official server.");
        ui.label("It does not verify official Challenge submissions.");

        ui.add_space(8.0);

        ui.label("Local client:");
        ui.label("• Local tests: available");
        ui.label("• Result export: available");
        ui.label("• Official Challenge creation: not available in this public client");

        ui.add_space(8.0);

        ui.label("Security:");
        ui.label("• No admin tools included");
        ui.label("• No private MAX Login code included");
        ui.label("• No HF token included");
        ui.label("• No database credentials included");

        ui.add_space(8.0);

        ui.label("Status:");
        ui.monospace("Local public client ready.");
    }
}

impl eframe::App for MaxPrimeGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep the GUI live while background official work updates logs/progress.
        // Without this, some platforms redraw only after mouse/keyboard events.
        ctx.request_repaint_after(std::time::Duration::from_millis(250));

        // MAX_PRIME_FORCE_LIGHT_MODE_PATCH: default GUI in Light Mode.
        ctx.set_visuals(egui::Visuals::light());
        Self::prime_apply_visuals_gui(ctx, self.theme_dark);

        let panel_fill = if self.theme_dark {
            egui::Color32::from_rgb(18, 24, 34)
        } else {
            egui::Color32::from_rgb(238, 244, 252)
        };

        self.poll_official_server_run_gui();
        self.poll_registration_background_gui();

        egui::TopBottomPanel::top("top_panel")
            .frame(
                egui::Frame::new()
                    .fill(panel_fill)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new("MAX Prime Challenge")
                            .size(22.0)
                            .strong(),
                    );
                    Self::prime_badge_gui(ui, "Public Client", "blue");
                    Self::prime_badge_gui(ui, "Rust", "ok");

                    ui.separator();

                    let theme_label = if self.theme_dark {
                        "Switch to Light Mode"
                    } else {
                        "Switch to Dark Mode"
                    };

                    if ui
                        .add(egui::Button::new(theme_label).min_size(egui::vec2(150.0, 28.0)))
                        .clicked()
                    {
                        self.theme_dark = !self.theme_dark;
                    }
                });
                self.top_tabs(ui);
            });

        egui::TopBottomPanel::bottom("bottom_panel")
            .frame(
                egui::Frame::new()
                    .fill(panel_fill)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ctx, |ui| {
                ui.label("© MAX Prime Challenge — All rights reserved.");
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(panel_fill)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        Tab::Home => self.home_ui(ui),
                        Tab::AdvancedLocal => self.advanced_local_ui(ui),
                        Tab::OfficialMode => self.official_mode_ui(ui),
                        Tab::SelfCheck => self.self_check_ui(ui),
                    });
            });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MAX Prime Challenge",
        native_options,
        Box::new(|_cc| Ok(Box::new(MaxPrimeGuiApp::default()))),
    )
}
