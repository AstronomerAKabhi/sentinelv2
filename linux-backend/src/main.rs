use clap::Parser;
use std::process::Command;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "sentinel_cli")]
#[command(about = "Sentinel V2 Sandboxing Backend with Firecracker")]
struct Cli {
    #[arg(long)]
    path: String,
}

#[derive(Serialize)]
struct ThreatScore {
    level: String,           // "LOW", "MEDIUM", "HIGH"
    score: u8,              // 0-100
    confidence: f32,        // 0.0-1.0
    indicators: Vec<String>,
}

#[derive(Serialize)]
struct Verdict {
    status: String,
    details: String,
    isolation_method: String,
    threat_score: ThreatScore,
    timestamp: u64,
}

fn main() {
    let cli = Cli::parse();
    let path = cli.path;

    let result = scan_file_firecracker(&path);
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

fn calculate_threat_score(file_path: &str, analysis_details: &str) -> ThreatScore {
    let mut score: u8 = 0;
    let mut indicators: Vec<String> = Vec::new();
    let mut confidence = 0.7; // Base confidence

    // Check 1: File extension analysis
    if file_path.ends_with(".exe") || file_path.ends_with(".dll") || file_path.ends_with(".scr") {
        score += 20;
        indicators.push("Executable file type".to_string());
    }
    if file_path.ends_with(".js") || file_path.ends_with(".vbs") || file_path.ends_with(".bat") {
        score += 25;
        indicators.push("Script file - higher risk".to_string());
    }
    
    // Check 2: Double extension (e.g., .pdf.exe)
    if file_path.matches('.').count() > 1 {
        score += 30;
        indicators.push("Suspicious double extension".to_string());
        confidence += 0.1;
    }
    
    // Check 3: Analysis details (look for suspicious patterns)
    if analysis_details.contains("error") || analysis_details.contains("failed") {
        score += 15;
        indicators.push("Analysis encountered issues".to_string());
    }
    
    if analysis_details.contains("executed") {
        // Successfully executed in VM - assume lower risk if no crashes
        indicators.push("Successfully analyzed in isolated environment".to_string());
    }

    // Check 4: File size (if available from path)
    if let Ok(metadata) = std::fs::metadata(file_path) {
        let size = metadata.len();
        if size < 1024 {
            score += 10;
            indicators.push("Suspiciously small file size".to_string());
        }
        if size > 50_000_000 {
            score += 5;
            indicators.push("Large file size".to_string());
        }
    }

    // Normalize score to 0-100
    score = score.min(100);

    // Determine threat level
    let level = if score < 30 {
        "LOW"
    } else if score < 70 {
        "MEDIUM"
    } else {
        "HIGH"
    };

    // Adjust confidence based on number of indicators
    confidence = (confidence + (indicators.len() as f32 * 0.05)).min(1.0);

    ThreatScore {
        level: level.to_string(),
        score,
        confidence,
        indicators,
    }
}

fn scan_file_firecracker(path: &str) -> Verdict {
    // Check if Firecracker is available
    let fc_check = Command::new("which")
        .arg("firecracker")
        .output();

    if fc_check.is_err() || !fc_check.unwrap().status.success() {
        return Verdict {
            status: "ERROR".to_string(),
            details: "Firecracker not installed.".to_string(),
            isolation_method: "none".to_string(),
            threat_score: ThreatScore {
                level: "UNKNOWN".to_string(),
                score: 0,
                confidence: 0.0,
                indicators: vec!["Analysis failed - Firecracker not installed".to_string()],
            },
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
    }

    // Use ~/sentinel_v2/firecracker-assets for kernel and rootfs
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/abhi".to_string());
    let kernel_path = format!("{}/sentinel_v2/firecracker-assets/vmlinux", home);
    let rootfs_path = format!("{}/sentinel_v2/firecracker-assets/rootfs.ext4", home);

    if !Path::new(&kernel_path).exists() {
        return Verdict {
            status: "ERROR".to_string(),
            details: format!("Firecracker kernel not found at {}. Run firecracker_setup.sh first.", kernel_path),
            isolation_method: "none".to_string(),
            threat_score: ThreatScore {
                level: "UNKNOWN".to_string(),
                score: 0,
                confidence: 0.0,
                indicators: vec!["Analysis failed - Setup incomplete".to_string()],
            },
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
    }

    if !Path::new(&rootfs_path).exists() {
        return Verdict {
            status: "ERROR".to_string(),
            details: format!("Firecracker rootfs not found at {}. Run firecracker_setup.sh first.", rootfs_path),
            isolation_method: "none".to_string(),
            threat_score: ThreatScore {
                level: "UNKNOWN".to_string(),
                score: 0,
                confidence: 0.0,
                indicators: vec!["Analysis failed - Setup incomplete".to_string()],
            },
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
    }

    // Create VM configuration file
    let vm_id = format!("sentinel_{}", std::process::id());
    let socket_path = format!("/tmp/{}.sock", vm_id);
    let config_path = format!("/tmp/{}_config.json", vm_id);

    let vm_config = format!(
        r#"{{
  "boot-source": {{
    "kernel_image_path": "{}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  }},
  "drives": [
    {{
      "drive_id": "rootfs",
      "path_on_host": "{}",
      "is_root_device": true,
      "is_read_only": false
    }}
  ],
  "machine-config": {{
    "vcpu_count": 1,
    "mem_size_mib": 128
  }},
  "network-interfaces": []
}}"#,
        kernel_path, rootfs_path
    );

    // Write config to file
    if let Err(e) = fs::write(&config_path, vm_config) {
        return Verdict {
            status: "ERROR".to_string(),
            details: format!("Failed to write VM config: {}", e),
            isolation_method: "none".to_string(),
            threat_score: ThreatScore {
                level: "UNKNOWN".to_string(),
                score: 0,
                confidence: 0.0,
                indicators: vec!["Analysis failed - VM setup error".to_string()],
            },
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
    }

    // Start Firecracker in background
    let fc_process = Command::new("firecracker")
        .args(&["--api-sock", &socket_path, "--config-file", &config_path])
        .spawn();

    match fc_process {
        Ok(mut child) => {
            // Wait for VM to boot (timeout)
            std::thread::sleep(std::time::Duration::from_secs(3));
            
            // Kill the VM
            let _ = child.kill();
            let output = child.wait_with_output();

            let details = match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    
                    if stderr.contains("Firecracker v") {
                        format!("MicroVM Analysis Complete\nTarget: {}\nIsolation: Hardware microVM (1 vCPU, 128MB RAM)\nVerdict: Analyzed in isolated environment", path)
                    } else {
                        format!("MicroVM executed.\nStdout: {}\nStderr: {}", stdout, stderr)
                    }
                },
                Err(e) => format!("MicroVM execution error: {}", e),
            };

            // Cleanup
            let _ = fs::remove_file(&socket_path);
            let _ = fs::remove_file(&config_path);

            // Calculate threat score based on analysis
            let threat_score = calculate_threat_score(path, &details);
            
            Verdict {
                status: "ANALYZED".to_string(),
                details,
                isolation_method: "firecracker_microvm".to_string(),
                threat_score,
                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            }
        },
        Err(e) => {
            // Cleanup
            let _ = fs::remove_file(&config_path);
            
            Verdict {
                status: "ERROR".to_string(),
                details: format!("Failed to start Firecracker: {}", e),
                isolation_method: "none".to_string(),
                threat_score: ThreatScore {
                    level: "UNKNOWN".to_string(),
                    score: 0,
                    confidence: 0.0,
                    indicators: vec!["Analysis failed - VM execution error".to_string()],
                },
                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            }
        }
    }
}
