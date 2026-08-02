"""RE-Nexus engine package.

Importing this package exposes every engine function so the Flask app can
import them from a single place (`from app.engines import ...`).
Each file lives in `app/engines/`, one analysis/dashboard engine per module.
"""
from .matryoshka import analyze_matryoshka
from .memory import hunt_keys
from .network import analyze_pcap, summarize_flows
from .author import attribute_author
from .anti_analysis import scan_anti_analysis, apply_bypass_patches
from .pe_graph import build_attack_graph
from .ghost_spectrum import ghost_spectrum
from .ant_colony import ant_colony
from .reverse_timestamp import reverse_timestamp
from .brain_link import brain_link
from .kamikaze import kamikaze_engine
from .sys_status import host_metrics
from .shattered_mind import shattered_mind
from .blackhole_engineer import blackhole_engineer
from .speculative_injector import speculative_injector
from .compiler_flipper import compiler_flipper
from .weighted_future import weighted_future
from .register_puzzle import register_puzzle
from .silent_plague import silent_plague

# ── Elite System modules ──
from .quantum_wiper import quantum_wipe, quantum_wipe_directory
from .dimensional_shield import shield_encrypt, shield_decrypt, shield_encrypt_file, shield_decrypt_file
from .neural_cleaner import neural_clean, neural_clean_recursive
from .blind_vault import vault_lock, vault_unlock
from .ghost_inlayer import ghost_hide, ghost_extract
from .elite_modules import (
    kamikaze_seal, kamikaze_unseal, kamikaze_refresh,
    spectral_scan, bio_entropy_analyze, forking_duplicate,
)
from .combi_scan import combi_scan
from .entrepreneurial_code import forge_code, verify_code, analyze_code
from .electoral_engine import electoral_route
from .elite_dashboard import (
    digital_fingerprint, scan_ports, process_monitor,
    encrypt_file, decrypt_file, stealth_tasks, event_log,
    log_event, speculative_brute, accelerate, secret_browser, kill_process,
)

__all__ = [
    "analyze_matryoshka",
    "hunt_keys",
    "analyze_pcap",
    "summarize_flows",
    "attribute_author",
    "scan_anti_analysis",
    "apply_bypass_patches",
    "build_attack_graph",
    "ghost_spectrum",
    "ant_colony",
    "reverse_timestamp",
    "brain_link",
    "kamikaze_engine",
    "host_metrics",
    "shattered_mind",
    "blackhole_engineer",
    "speculative_injector",
    "compiler_flipper",
    "weighted_future",
    "register_puzzle",
    "silent_plague",
    # Elite System
    "quantum_wipe",
    "quantum_wipe_directory",
    "shield_encrypt",
    "shield_decrypt",
    "shield_encrypt_file",
    "shield_decrypt_file",
    "neural_clean",
    "neural_clean_recursive",
    "vault_lock",
    "vault_unlock",
    "ghost_hide",
    "ghost_extract",
    "kamikaze_seal",
    "kamikaze_unseal",
    "kamikaze_refresh",
    "spectral_scan",
    "bio_entropy_analyze",
    "forking_duplicate",
    # New 9-module pack
    "combi_scan",
    "forge_code",
    "verify_code",
    "analyze_code",
    "electoral_route",
    "digital_fingerprint",
    "scan_ports",
    "process_monitor",
    "encrypt_file",
    "decrypt_file",
    "stealth_tasks",
    "event_log",
    "log_event",
    "speculative_brute",
    "accelerate",
    "secret_browser",
    "kill_process",
]
