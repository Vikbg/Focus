from pathlib import Path

path = Path("bins/focusd/src/lib.rs")
text = path.read_text()
needle = "mod linux_emergency;\n"
replacement = (
    "mod linux_emergency;\n"
    "mod service;\n\n"
    "pub use service::{DaemonService, DaemonSnapshot, ProtectionHealth};\n"
)
if needle not in text:
    raise SystemExit("focusd module anchor not found")
if "mod service;" not in text:
    text = text.replace(needle, replacement, 1)
path.write_text(text)
