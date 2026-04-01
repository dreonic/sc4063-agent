"""Global configuration and detection thresholds."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # --- Paths ---
    output_dir: Path = Path("forensic_output")
    report_filename: str = "forensic_report.md"

    # --- Network ---
    internal_subnets: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

    # --- File size thresholds (bytes) ---
    full_read_max: int = 10 * 1024 * 1024        # 10 MB — read entire file
    sample_grep_max: int = 100 * 1024 * 1024      # 100 MB — head + grep
    # Above 100 MB — grep only

    # --- Detection thresholds ---
    cred_spray_min_failures: int = 100
    lateral_move_min_targets: int = 10
    samr_enum_min_ops: int = 50
    admin_share_min_accesses: int = 20
    exfil_session_min: int = 2
    large_exe_threshold: int = 1 * 1024 * 1024

    # --- Known exfiltration services ---
    known_exfil_domains: list[str] = field(default_factory=lambda: [
        "temp.sh", "mega.nz", "mega.co.nz", "transfer.sh", "file.io",
        "gofile.io", "anonfiles.com", "wetransfer.com", "send.firefox.com",
        "dropmefiles.com", "filedropper.com", "mediafire.com",
    ])

    # --- Known IP recon services ---
    known_recon_services: list[str] = field(default_factory=lambda: [
        "comae.com", "ipinfo.io", "whatismyip.com", "ifconfig.me",
        "icanhazip.com", "api.ipify.org", "checkip.amazonaws.com",
        "ipecho.net", "myexternalip.com",
    ])

    # --- Known file transfer tool names ---
    known_transfer_tools: list[str] = field(default_factory=lambda: [
        "hfs", "winscp", "filezilla", "7z", "7-zip", "rclone",
        "pscp", "putty", "curl", "wget", "nc", "ncat",
    ])

    # --- Suspicious user agents ---
    suspicious_user_agents: list[str] = field(default_factory=lambda: [
        "Go-http-client", "python-requests", "python-urllib",
        "curl", "wget", "PowerShell", "Java",
    ])

    # --- RDP / remote access ports ---
    remote_access_ports: list[int] = field(default_factory=lambda: [
        3389, 22, 5985, 5986, 4444, 8080, 8443,
    ])

    # --- LLM (env-based, universal OpenAI-compatible) ---
    llm_base_url: str = field(default_factory=lambda: os.getenv("LLM_BASE_URL", "http://localhost:8080/v1"))
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", "not-needed"))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "default-model"))
    llm_temperature: float = 0.1

    # --- Agent ---
    max_iterations: int = 50
    human_review: bool = False

    # --- Cost tracking ---
    api_input_cost_per_1k: float = field(default_factory=lambda: float(os.getenv("API_INPUT_COST_PER_1K", "0.003")))
    api_output_cost_per_1k: float = field(default_factory=lambda: float(os.getenv("API_OUTPUT_COST_PER_1K", "0.015")))
    gpu_hourly_rate: float = field(default_factory=lambda: float(os.getenv("GPU_HOURLY_RATE", "4.50")))

    # --- Zeek ---
    zeek_binary: str = "zeek"
