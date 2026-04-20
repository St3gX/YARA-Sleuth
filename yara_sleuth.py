"""
YARA-Sleuth: Advanced File System Scanner for Digital Forensics
================================================================
A professional-grade forensics tool using YARA rules to detect malware,
suspicious files, data exfiltration artifacts, and security threats.

Author: StegX
Version: 1.0.0
"""

# ── AUTO DEPENDENCY CHECKER (must run before other imports) ───────────────────
import sys
import subprocess

def check_dependencies():
    missing = []
    try:
        import yara
    except ImportError:
        missing.append("yara-python")
    try:
        import colorama
    except ImportError:
        missing.append("colorama")
    try:
        import tabulate
    except ImportError:
        missing.append("tabulate")

    if missing:
        print(f"\n[!] Missing packages: {', '.join(missing)}")
        print("[*] Attempting auto-install...\n")
        for pkg in missing:
            print(f"    Installing {pkg}...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install",
                 pkg, "--only-binary=:all:", "-q"],
                capture_output=True
            )
            if result.returncode != 0:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "-q"]
                )
        print("\n[+] Dependencies installed! Restarting...\n")
        subprocess.run([sys.executable] + sys.argv)
        sys.exit(0)

check_dependencies()
# ── END DEPENDENCY CHECKER ────────────────────────────────────────────────────

import os
import yara
import hashlib
import json
import time
import threading
import argparse
import platform
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from colorama import init, Fore, Back, Style
from tabulate import tabulate

# Initialize colorama for cross-platform colored output
init(autoreset=True)


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
TOOL_NAME = "YARA-Sleuth"

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.GREEN,
    "INFO":     Fore.WHITE,
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# File extensions to skip (media files only — executables kept for malware scanning)
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2",
}

MAX_FILE_SIZE_MB = 100  # Skip files larger than this (in MB)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.CYAN + Style.BRIGHT}
██╗   ██╗ █████╗ ██████╗  █████╗        ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗       ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
 ╚████╔╝ ███████║██████╔╝███████║ █████╗███████╗██║     █████╗  ██║   ██║   ██║   ███████║
  ╚██╔╝  ██╔══██║██╔══██╗██╔══██║ ╚════╝╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
   ██║   ██║  ██║██║  ██║██║  ██║       ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝       ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │  {Fore.YELLOW}Advanced File System Scanner for Digital Forensics by StegX  {Fore.WHITE}│  {Fore.CYAN}v{VERSION}{Fore.WHITE}  │  {Fore.GREEN}YARA-Powered{Fore.WHITE}  │
  └─────────────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
    print(banner)


# ─────────────────────────────────────────────────────────────────────────────
# RULE LOADER
# ─────────────────────────────────────────────────────────────────────────────

class RuleLoader:
    """Loads and compiles YARA rules from .yar files."""

    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.compiled_rules = {}
        self.rule_count = 0
        self.load_errors = []

    def load_all(self) -> dict:
        """Load all .yar files from the rules directory."""
        yar_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))

        if not yar_files:
            print(f"{Fore.RED}[!] No YARA rule files found in: {self.rules_dir}{Style.RESET_ALL}")
            return {}

        print(f"\n{Fore.CYAN}[*] Loading YARA Rules from: {self.rules_dir}{Style.RESET_ALL}")
        for yar_file in yar_files:
            self._load_file(yar_file)

        print(f"{Fore.GREEN}[+] Loaded {len(self.compiled_rules)} rule sets | "
              f"{self.rule_count} total patterns compiled{Style.RESET_ALL}")

        if self.load_errors:
            print(f"{Fore.YELLOW}[!] {len(self.load_errors)} rule(s) failed to compile:{Style.RESET_ALL}")
            for err in self.load_errors:
                print(f"    {Fore.RED}→ {err}{Style.RESET_ALL}")

        return self.compiled_rules

    def _load_file(self, yar_file: Path):
        try:
            rules = yara.compile(str(yar_file))
            # Count rules by scanning a dummy string
            self.compiled_rules[yar_file.stem] = rules
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {yar_file.name}")
        except yara.SyntaxError as e:
            self.load_errors.append(f"{yar_file.name}: {e}")
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {yar_file.name} — {e}")


# ─────────────────────────────────────────────────────────────────────────────
# FILE METADATA EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

class FileMetadata:
    """Extracts and stores file metadata for forensic analysis."""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.metadata = {}

    def extract(self) -> dict:
        try:
            stat = self.filepath.stat()
            self.metadata = {
                "filename":       self.filepath.name,
                "full_path":      str(self.filepath.resolve()),
                "extension":      self.filepath.suffix.lower(),
                "size_bytes":     stat.st_size,
                "size_human":     self._human_size(stat.st_size),
                "created":        datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                "modified":       datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "accessed":       datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
                "md5":            self._compute_hash("md5"),
                "sha256":         self._compute_hash("sha256"),
                "is_hidden":      self.filepath.name.startswith("."),
                "permissions":    oct(stat.st_mode),
            }
        except (PermissionError, OSError) as e:
            self.metadata = {"error": str(e), "full_path": str(self.filepath)}
        return self.metadata

    def _human_size(self, size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _compute_hash(self, algo: str) -> str:
        try:
            h = hashlib.new(algo)
            with open(self.filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, OSError):
            return "N/A"


# ─────────────────────────────────────────────────────────────────────────────
# YARA SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class YARAScanner:
    """Core YARA scanning engine."""

    def __init__(self, compiled_rules: dict, max_file_size_mb: int = MAX_FILE_SIZE_MB):
        self.rules = compiled_rules
        self.max_bytes = max_file_size_mb * 1024 * 1024

    def scan_file(self, filepath: str) -> list:
        """Scan a single file and return list of match results."""
        fp = Path(filepath)
        matches = []

        # Size guard
        try:
            if fp.stat().st_size > self.max_bytes:
                return []
        except OSError:
            return []

        try:
            with open(fp, "rb") as f:
                data = f.read()
        except (PermissionError, OSError):
            return []

        for ruleset_name, rules in self.rules.items():
            try:
                rule_matches = rules.match(data=data)
                for match in rule_matches:
                    meta = match.meta if match.meta else {}
                    matches.append({
                        "ruleset":     ruleset_name,
                        "rule_name":   match.rule,
                        "tags":        list(match.tags),
                        "severity":    meta.get("severity", "MEDIUM"),
                        "category":    meta.get("category", "unknown"),
                        "description": meta.get("description", "No description"),
                        "strings":     self._extract_strings(match),
                    })
            except yara.Error:
                pass

        return matches

    def _extract_strings(self, match) -> list:
        """Extract matched string identifiers."""
        found = []
        for string_match in match.strings:
            # Handle both old and new YARA API
            try:
                identifier = string_match.identifier
                instances = [inst.plaintext().decode("utf-8", errors="replace")[:80]
                             for inst in string_match.instances[:3]]
                found.append({"id": identifier, "matches": instances})
            except AttributeError:
                # Fallback for older yara-python
                found.append({"id": str(string_match), "matches": []})
        return found


# ─────────────────────────────────────────────────────────────────────────────
# FILESYSTEM WALKER
# ─────────────────────────────────────────────────────────────────────────────

class FileSystemWalker:
    """Recursively walks the filesystem and feeds files to the scanner."""

    def __init__(self, scanner: YARAScanner, skip_extensions: set = None,
                 recursive: bool = True, follow_symlinks: bool = False):
        self.scanner = scanner
        self.skip_ext = skip_extensions or SKIP_EXTENSIONS
        self.recursive = recursive
        self.follow_symlinks = follow_symlinks

        # Stats
        self.files_scanned = 0
        self.files_skipped = 0
        self.files_errored = 0
        self.total_matches = 0

        # Results
        self.results = []          # All matches
        self.clean_files = []      # Files with no matches

        # Thread-safe spinner
        self._spinner_active = False
        self._spinner_thread = None
        self._current_file = ""
        self._lock = threading.Lock()

    def scan_directory(self, target_dir: str) -> list:
        target = Path(target_dir)
        if not target.exists():
            print(f"{Fore.RED}[!] Target directory not found: {target_dir}{Style.RESET_ALL}")
            return []

        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}  SCAN TARGET : {Fore.YELLOW}{target.resolve()}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}  RECURSIVE   : {Fore.YELLOW}{'Yes' if self.recursive else 'No'}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}\n")

        self._start_spinner()

        walker = os.walk(str(target), followlinks=self.follow_symlinks)
        if not self.recursive:
            walker = [next(walker)]

        for dirpath, dirnames, filenames in walker:
            # Skip hidden directories
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                ext = Path(filename).suffix.lower()

                if ext in self.skip_ext:
                    with self._lock:
                        self.files_skipped += 1
                    continue

                with self._lock:
                    self._current_file = filepath

                self._scan_single(filepath)

        self._stop_spinner()
        return self.results

    def _scan_single(self, filepath: str):
        meta = FileMetadata(filepath).extract()
        if "error" in meta:
            with self._lock:
                self.files_errored += 1
            return

        matches = self.scanner.scan_file(filepath)
        with self._lock:
            self.files_scanned += 1
            if matches:
                self.total_matches += len(matches)
                self.results.append({
                    "file": meta,
                    "matches": matches,
                    "max_severity": self._max_severity(matches),
                })
            else:
                self.clean_files.append(filepath)

    def _max_severity(self, matches: list) -> str:
        levels = [m.get("severity", "LOW") for m in matches]
        return max(levels, key=lambda s: SEVERITY_ORDER.get(s, 0))

    def _start_spinner(self):
        self._spinner_active = True
        self._spinner_thread = threading.Thread(target=self._spin, daemon=True)
        self._spinner_thread.start()

    def _stop_spinner(self):
        self._spinner_active = False
        if self._spinner_thread:
            self._spinner_thread.join()
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

    def _spin(self):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        while self._spinner_active:
            with self._lock:
                f = self._current_file[-60:] if len(self._current_file) > 60 else self._current_file
                scanned = self.files_scanned
                hits = self.total_matches
            sys.stdout.write(
                f"\r  {Fore.CYAN}{chars[i % len(chars)]}{Style.RESET_ALL} "
                f"Scanning: {Fore.WHITE}{f:<60}{Style.RESET_ALL} "
                f"| Files: {Fore.GREEN}{scanned}{Style.RESET_ALL} "
                f"| Hits: {Fore.RED}{hits}{Style.RESET_ALL}  "
            )
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generates forensic scan reports in multiple formats."""

    def __init__(self, results: list, walker_stats: dict, scan_meta: dict):
        self.results = results
        self.stats = walker_stats
        self.meta = scan_meta

    def print_summary(self):
        """Print a colorized summary to the terminal."""
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}  SCAN COMPLETE — SUMMARY REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")

        # Stats table
        duration = self.meta.get("duration_seconds", 0)
        stats_data = [
            ["Files Scanned",    f"{Fore.GREEN}{self.stats['scanned']}{Style.RESET_ALL}"],
            ["Files Skipped",    f"{Fore.YELLOW}{self.stats['skipped']}{Style.RESET_ALL}"],
            ["Files Errored",    f"{Fore.RED}{self.stats['errored']}{Style.RESET_ALL}"],
            ["Total Matches",    f"{Fore.RED + Style.BRIGHT}{self.stats['total_matches']}{Style.RESET_ALL}"],
            ["Infected Files",   f"{Fore.RED + Style.BRIGHT}{len(self.results)}{Style.RESET_ALL}"],
            ["Scan Duration",    f"{Fore.CYAN}{duration:.2f}s{Style.RESET_ALL}"],
            ["Scan Rate",        f"{Fore.CYAN}{self.stats['scanned']/max(duration,1):.1f} files/sec{Style.RESET_ALL}"],
        ]
        print(tabulate(stats_data, tablefmt="rounded_outline", colalign=("left", "left")))

        if not self.results:
            print(f"\n{Fore.GREEN + Style.BRIGHT}  ✓ No threats detected. System appears clean.{Style.RESET_ALL}\n")
            return

        # Severity breakdown
        severity_counts = defaultdict(int)
        category_counts  = defaultdict(int)
        for r in self.results:
            for m in r["matches"]:
                severity_counts[m["severity"]] += 1
                category_counts[m["category"]] += 1

        print(f"\n{Fore.WHITE + Style.BRIGHT}  SEVERITY BREAKDOWN:{Style.RESET_ALL}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(sev, 0)
            if count:
                color = SEVERITY_COLORS.get(sev, Fore.WHITE)
                bar = "█" * min(count * 2, 40)
                print(f"  {color}{sev:<12}{Style.RESET_ALL} {bar} {count}")

        print(f"\n{Fore.WHITE + Style.BRIGHT}  THREAT CATEGORIES:{Style.RESET_ALL}")
        for cat, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
            print(f"  {Fore.CYAN}•{Style.RESET_ALL} {cat:<30} {cnt} match(es)")

        # Detailed matches
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}  FLAGGED FILES DETAIL{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")

        # Sort by severity
        sorted_results = sorted(self.results,
                                key=lambda x: SEVERITY_ORDER.get(x["max_severity"], 0),
                                reverse=True)

        for idx, result in enumerate(sorted_results, 1):
            f = result["file"]
            sev_color = SEVERITY_COLORS.get(result["max_severity"], Fore.WHITE)

            print(f"\n  {Fore.WHITE + Style.BRIGHT}[{idx}]{Style.RESET_ALL} "
                  f"{Fore.YELLOW}{f['filename']}{Style.RESET_ALL}  "
                  f"{sev_color}[{result['max_severity']}]{Style.RESET_ALL}")
            print(f"      Path     : {f['full_path']}")
            print(f"      Size     : {f['size_human']}  |  Modified: {f['modified']}")
            print(f"      MD5      : {Fore.CYAN}{f['md5']}{Style.RESET_ALL}")
            print(f"      SHA-256  : {Fore.CYAN}{f['sha256']}{Style.RESET_ALL}")

            for match in result["matches"]:
                m_color = SEVERITY_COLORS.get(match["severity"], Fore.WHITE)
                print(f"\n      {m_color}▶ Rule: {match['rule_name']}{Style.RESET_ALL}  "
                      f"({match['severity']} | {match['category']})")
                print(f"        {Fore.WHITE}{match['description']}{Style.RESET_ALL}")
                if match["strings"]:
                    print(f"        {Fore.YELLOW}Matched strings:{Style.RESET_ALL}")
                    for s in match["strings"][:3]:
                        for inst in s["matches"][:2]:
                            cleaned = inst.strip().replace("\n", "\\n")
                            print(f"          {Fore.RED}→{Style.RESET_ALL} {cleaned[:80]}")

        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}\n")

    def save_json(self, output_path: str):
        """Save full scan results as JSON for further analysis."""
        report = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "scan_meta": self.meta,
            "statistics": self.stats,
            "findings": self.results,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"{Fore.GREEN}[+] JSON report saved: {output_path}{Style.RESET_ALL}")

    def save_text(self, output_path: str):
        """Save a plain-text forensic report."""
        lines = []
        lines.append("=" * 70)
        lines.append(f"  {TOOL_NAME} v{VERSION} — Forensic Scan Report")
        lines.append("=" * 70)
        lines.append(f"  Scan Time   : {self.meta.get('scan_time', 'N/A')}")
        lines.append(f"  Target      : {self.meta.get('target', 'N/A')}")
        lines.append(f"  Platform    : {self.meta.get('platform', 'N/A')}")
        lines.append(f"  Duration    : {self.meta.get('duration_seconds', 0):.2f}s")
        lines.append("")
        lines.append(f"  Files Scanned : {self.stats['scanned']}")
        lines.append(f"  Total Matches : {self.stats['total_matches']}")
        lines.append(f"  Infected Files: {len(self.results)}")
        lines.append("")
        lines.append("=" * 70)
        lines.append("  FINDINGS")
        lines.append("=" * 70)

        for idx, result in enumerate(self.results, 1):
            f = result["file"]
            lines.append(f"\n[{idx}] {f['filename']}  [{result['max_severity']}]")
            lines.append(f"    Path    : {f['full_path']}")
            lines.append(f"    Size    : {f['size_human']}")
            lines.append(f"    MD5     : {f['md5']}")
            lines.append(f"    SHA-256 : {f['sha256']}")
            for m in result["matches"]:
                lines.append(f"    ▶ {m['rule_name']} ({m['severity']}) — {m['description']}")

        lines.append("\n" + "=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"{Fore.GREEN}[+] Text report saved: {output_path}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class YARASleuth:
    """Main orchestrator class tying all components together."""

    def __init__(self, rules_dir: str = "yara_rules", reports_dir: str = "reports"):
        self.rules_dir = rules_dir
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)

    def run(self, target: str, recursive: bool = True,
            save_json: bool = True, save_text: bool = True,
            skip_ext: set = None):

        print_banner()

        # 1. Load YARA rules
        loader = RuleLoader(self.rules_dir)
        compiled_rules = loader.load_all()
        if not compiled_rules:
            print(f"{Fore.RED}[!] No rules loaded. Aborting scan.{Style.RESET_ALL}")
            return

        # 2. Setup scanner & walker
        scanner = YARAScanner(compiled_rules)
        walker = FileSystemWalker(
            scanner,
            skip_extensions=skip_ext or SKIP_EXTENSIONS,
            recursive=recursive,
        )

        # 3. Walk & scan
        start_time = time.time()
        results = walker.scan_directory(target)
        duration = time.time() - start_time

        # 4. Collect stats
        stats = {
            "scanned":      walker.files_scanned,
            "skipped":      walker.files_skipped,
            "errored":      walker.files_errored,
            "total_matches": walker.total_matches,
        }
        scan_meta = {
            "tool":             TOOL_NAME,
            "version":          VERSION,
            "scan_time":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target":           str(Path(target).resolve()),
            "platform":         platform.platform(),
            "python_version":   platform.python_version(),
            "yara_version":     yara.__version__,
            "recursive":        recursive,
            "duration_seconds": round(duration, 3),
            "rules_loaded":     len(compiled_rules),
        }

        # 5. Report
        reporter = ReportGenerator(results, stats, scan_meta)
        reporter.print_summary()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"yara_sleuth_{timestamp}"

        if save_json:
            reporter.save_json(str(self.reports_dir / f"{base_name}.json"))
        if save_text:
            reporter.save_text(str(self.reports_dir / f"{base_name}.txt"))

        return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="yara_sleuth",
        description=f"{TOOL_NAME} v{VERSION} — Advanced YARA-based File System Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python yara_sleuth.py --target ./sample_files
  python yara_sleuth.py --target /home/user --rules ./custom_rules --no-recursive
  python yara_sleuth.py --target ./suspicious_dir --no-json
        """
    )
    parser.add_argument("--target",     required=True, help="Directory to scan")
    parser.add_argument("--rules",      default="yara_rules", help="YARA rules directory")
    parser.add_argument("--reports",    default="reports", help="Output reports directory")
    parser.add_argument("--no-recursive", action="store_true", help="Non-recursive scan")
    parser.add_argument("--no-json",    action="store_true", help="Skip JSON report")
    parser.add_argument("--no-text",    action="store_true", help="Skip text report")
    parser.add_argument("--version",    action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    sleuth = YARASleuth(rules_dir=args.rules, reports_dir=args.reports)
    sleuth.run(
        target=args.target,
        recursive=not args.no_recursive,
        save_json=not args.no_json,
        save_text=not args.no_text,
    )


if __name__ == "__main__":
    main()
