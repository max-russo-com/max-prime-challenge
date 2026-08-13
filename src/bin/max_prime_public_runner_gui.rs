use eframe::egui;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;

struct RunnerApp {
    challenge_id: String,
    running: bool,
    log: String,
    rx: Option<Receiver<String>>,
}

impl Default for RunnerApp {
    fn default() -> Self {
        Self {
            challenge_id: "AUTO".to_string(),
            running: false,
            log: "MAX Prime Public Runner\n\nScegli quanti pacchetti eseguire.\n\n1 pacchetto  = test rapido\n5 pacchetti  = mini-run controllata\n50 pacchetti = run più seria, ma ancora controllata\n\n".to_string(),
            rx: None,
        }
    }
}

fn client_binary_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| {
        std::path::PathBuf::from("./target/release/max_prime_public_runner_gui")
    });
    let dir = exe
        .parent()
        .unwrap_or_else(|| std::path::Path::new("./target/release"));
    dir.join("max_prime_public_client")
}

fn start_batch(challenge_id: String, count: usize) -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || {
        let client = client_binary_path();

        let _ = tx.send(format!(
            "\n=== START: {} pacchetto/i su {} ===\nClient: {}\n",
            count,
            challenge_id,
            client.display()
        ));

        for n in 1..=count {
            let _ = tx.send(format!("\n--- RUN {} / {} ---\n", n, count));

            let output = Command::new(&client)
                .arg("official-run-once")
                .arg(&challenge_id)
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

                    if !stdout.trim().is_empty() {
                        let _ = tx.send(stdout.clone());
                    }

                    if !stderr.trim().is_empty() {
                        let _ = tx.send(format!("\n[stderr]\n{}\n", stderr));
                    }

                    if !out.status.success() {
                        let _ = tx.send(format!(
                            "\nSTOP: il client ha restituito errore. Exit status: {}\n",
                            out.status
                        ));
                        break;
                    }

                    let stop_text = format!("{}{}", stdout, stderr);

                    if stop_text.contains("Has hit: true")
                        || stop_text.contains("Challenge completed: true")
                        || stop_text.contains("CHALLENGE_COMPLETED")
                        || stop_text.contains("Server did not assign work")
                    {
                        let _ = tx.send(
                            "\nSTOP: hit trovato, challenge completata, oppure il server non assegna altro lavoro.\n"
                                .to_string(),
                        );
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("\nERRORE: impossibile avviare il client.\n{}\n", e));
                    break;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let _ = tx.send("\n=== FINE RUN ===\n".to_string());
        let _ = tx.send("__MAX_PRIME_DONE__".to_string());
    });

    rx
}

impl eframe::App for RunnerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                if msg == "__MAX_PRIME_DONE__" {
                    self.running = false;
                    self.rx = None;
                    break;
                } else {
                    self.log.push_str(&msg);
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("MAX Prime Public Runner");

            ui.label("Questo pannello usa il public client già testato. Ogni pulsante esegue pacchetti ufficiali assegnati dal server.");

            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Challenge ID:");
                ui.text_edit_singleline(&mut self.challenge_id);
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if ui.add_enabled(!self.running, egui::Button::new("Run 1 pacchetto")).clicked() {
                    self.running = true;
                    self.rx = Some(start_batch(self.challenge_id.trim().to_string(), 1));
                }

                if ui.add_enabled(!self.running, egui::Button::new("Run 5 pacchetti")).clicked() {
                    self.running = true;
                    self.rx = Some(start_batch(self.challenge_id.trim().to_string(), 5));
                }

                if ui.add_enabled(!self.running, egui::Button::new("Run 50 pacchetti")).clicked() {
                    self.running = true;
                    self.rx = Some(start_batch(self.challenge_id.trim().to_string(), 50));
                }
            });

            ui.add_space(8.0);

            if self.running {
                ui.label("Stato: in esecuzione...");
            } else {
                ui.label("Stato: pronto.");
            }

            ui.separator();

            ui.label("Spiegazione semplice:");
            ui.label("1 pacchetto = prova veloce. 5 pacchetti = piccolo test. 50 pacchetti = lavoro più serio ma controllato.");

            ui.separator();

            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.log)
                            .desired_rows(28)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(200));
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "MAX Prime Public Runner",
        options,
        Box::new(|_cc| Ok(Box::new(RunnerApp::default()))),
    )
}
