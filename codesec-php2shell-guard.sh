#!/usr/bin/env bash
# CodeSec PHP2Shell Guard
# Defensive inventory and remediation helper.
# MIT License

set -uo pipefail

TOOL="CodeSec PHP2Shell Guard"
VERSION="2.0.0"
ADVISORY="https://www.php.net/security/"
PHP_URL="https://www.php.net/downloads.php"

JSON_OUT=""
CSV_OUT=""
VERSIONS_FILE=""
LOG_FILE=""
SYSTEM_MODE=0
SHOW_PATCH=0
CHECK_PROCESSES=1
EXIT_CODE=0

declare -a FOUND_VERSIONS=()
declare -a FOUND_SOURCES=()
declare -a RESULT_VERSIONS=()
declare -a RESULT_STATUSES=()
declare -a RESULT_REASONS=()
declare -a RESULT_FIXED=()
declare -a LOG_FINDINGS=()

usage() {
  cat <<'EOF'
CodeSec PHP2Shell Guard

Usage:
  ./codesec-php2shell-guard.sh --system
  ./codesec-php2shell-guard.sh --php-version 8.3.35
  ./codesec-php2shell-guard.sh --versions-file versions.txt
  ./codesec-php2shell-guard.sh --system --json-out report.json
  ./codesec-php2shell-guard.sh --system --csv-out report.csv
  ./codesec-php2shell-guard.sh --system --patch-guide
  ./codesec-php2shell-guard.sh --log-file /path/to/php-error.log

Options:
  --system               Inspect locally available PHP CLI and processes
  --php-version VERSION  Check a supplied version
  --versions-file FILE   Check one PHP version per line
  --json-out FILE        Write JSON results
  --csv-out FILE         Write CSV results
  --patch-guide          Show update guidance
  --log-file FILE        Search a supplied log for review indicators
  --no-process-check     Skip process inventory
  -h, --help             Show help

This tool does not exploit targets, prove exploitability, or guarantee
that a server is safe. Vendor backports require vendor-specific verification.
EOF
}

while (($#)); do
  case "$1" in
    --system) SYSTEM_MODE=1; shift ;;
    --php-version)
      [[ $# -ge 2 ]] || { echo "Missing PHP version"; exit 2; }
      FOUND_VERSIONS+=("$2")
      FOUND_SOURCES+=("user input")
      shift 2 ;;
    --versions-file)
      [[ $# -ge 2 ]] || { echo "Missing filename"; exit 2; }
      VERSIONS_FILE="$2"; shift 2 ;;
    --json-out)
      [[ $# -ge 2 ]] || { echo "Missing JSON filename"; exit 2; }
      JSON_OUT="$2"; shift 2 ;;
    --csv-out)
      [[ $# -ge 2 ]] || { echo "Missing CSV filename"; exit 2; }
      CSV_OUT="$2"; shift 2 ;;
    --log-file)
      [[ $# -ge 2 ]] || { echo "Missing log filename"; exit 2; }
      LOG_FILE="$2"; shift 2 ;;
    --patch-guide) SHOW_PATCH=1; shift ;;
    --no-process-check) CHECK_PROCESSES=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 2 ;;
  esac
done

# Compare numeric dotted versions using Bash arithmetic.
version_lt() {
  local a="$1" b="$2"
  local a1 a2 a3 b1 b2 b3

  [[ "$a" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
  a1="${BASH_REMATCH[1]}"; a2="${BASH_REMATCH[2]}"; a3="${BASH_REMATCH[3]}"
  [[ "$b" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
  b1="${BASH_REMATCH[1]}"; b2="${BASH_REMATCH[2]}"; b3="${BASH_REMATCH[3]}"

  # Strip leading zeroes to avoid octal arithmetic.
  a1=$((10#$a1)); a2=$((10#$a2)); a3=$((10#$a3))
  b1=$((10#$b1)); b2=$((10#$b2)); b3=$((10#$b3))

  (( a1 < b1 )) && return 0
  (( a1 > b1 )) && return 1
  (( a2 < b2 )) && return 0
  (( a2 > b2 )) && return 1
  (( a3 < b3 )) && return 0
  return 1
}

assess_version() {
  local v="$1" source="$2" fixed=""
  local major minor patch status reason

  if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    status="unknown"
    reason="Could not parse version; verify manually."
    fixed=""
  else
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"
    major=$((10#$major)); minor=$((10#$minor)); patch=$((10#$patch))
    v="${major}.${minor}.${patch}"

    case "${major}.${minor}" in
      8.5) fixed="8.5.12" ;;
      8.4) fixed="8.4.27" ;;
      8.3) fixed="8.3.36" ;;
      8.2) fixed="8.2.35" ;;
      *)
        fixed=""
        ;;
    esac

    if [[ -n "$fixed" ]]; then
      if version_lt "$v" "$fixed"; then
        status="potentially_vulnerable"
        reason="Below upstream fix threshold; patch and verify vendor advisory."
      else
        status="likely_fixed"
        reason="At or above upstream threshold; verify package origin and running service."
      fi
    elif (( major < 8 || (major == 8 && minor < 2) )); then
      status="unknown_or_legacy"
      reason="Older branch or vendor backport; check vendor security status immediately."
    else
      status="unknown"
      reason="No configured threshold for this branch; consult official advisory."
    fi
  fi

  RESULT_VERSIONS+=("$v")
  RESULT_STATUSES+=("$status")
  RESULT_REASONS+=("$reason")
  RESULT_FIXED+=("$fixed")

  printf '\nPHP version: %s\nSource: %s\nStatus: %s\nReason: %s\n' \
    "$v" "$source" "$status" "$reason"
  [[ -n "$fixed" ]] && printf 'Upstream threshold: %s\n' "$fixed"

  case "$status" in
    potentially_vulnerable|unknown_or_legacy) EXIT_CODE=1 ;;
  esac
}

if [[ -n "$VERSIONS_FILE" ]]; then
  [[ -r "$VERSIONS_FILE" ]] || { echo "Cannot read $VERSIONS_FILE"; exit 2; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -z "$line" ]] && continue
    FOUND_VERSIONS+=("$line")
    FOUND_SOURCES+=("versions file")
  done < "$VERSIONS_FILE"
fi

if (( SYSTEM_MODE )); then
  if command -v php >/dev/null 2>&1; then
    local_php="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    if [[ -n "$local_php" ]]; then
      FOUND_VERSIONS+=("$local_php")
      FOUND_SOURCES+=("local PHP CLI")
    fi
  else
    echo "PHP CLI not found in PATH."
  fi

  if (( CHECK_PROCESSES )); then
    echo
    echo "PHP/web-server process inventory (not proof of exposure):"
    if command -v pgrep >/dev/null 2>&1; then
      pgrep -afil 'php-fpm|php-cgi|apache2|httpd|frankenphp|lsphp' 2>/dev/null \
        || echo "No matching process found or process listing restricted."
    else
      echo "pgrep unavailable; skipping process inventory."
    fi
  fi

  echo
  echo "Detected package managers:"
  command -v apt-get >/dev/null 2>&1 && echo " - apt-get (Debian/Ubuntu family)"
  command -v dnf >/dev/null 2>&1 && echo " - dnf (Fedora/RHEL family)"
  command -v yum >/dev/null 2>&1 && echo " - yum (older RHEL family)"
  command -v apk >/dev/null 2>&1 && echo " - apk (Alpine)"
  command -v brew >/dev/null 2>&1 && echo " - brew (macOS)"
fi

if ((${#FOUND_VERSIONS[@]} == 0)); then
  echo "No PHP versions supplied or detected."
  usage
  exit 2
fi

echo
echo "=== $TOOL v$VERSION ==="
echo "Advisory: $ADVISORY"

for i in "${!FOUND_VERSIONS[@]}"; do
  assess_version "${FOUND_VERSIONS[$i]}" "${FOUND_SOURCES[$i]}"
done

if [[ -n "$LOG_FILE" ]]; then
  [[ -r "$LOG_FILE" ]] || { echo "Cannot read log file: $LOG_FILE"; exit 2; }
  echo
  echo "=== Log review indicators ==="
  echo "These patterns are leads for human review, not proof of compromise."

  if grep -Ein \
    'Allowed memory size exhausted|PHP Fatal error|child exited|segfault|multipart|unexpected EOF' \
    "$LOG_FILE" | head -n 50; then
    LOG_FINDINGS+=("Matched one or more PHP error/crash indicators; investigate context and timestamps.")
  else
    echo "No configured indicators matched."
  fi
fi

if (( SHOW_PATCH )); then
  echo
  echo "=== Patch guidance ==="
  echo "1. Back up the system and confirm your supported package source."
  echo "2. Update PHP from the official OS/vendor repository or PHP release."
  echo "3. Restart the actual PHP runtime and web-server workers."
  echo "4. Recheck the runtime version and vendor package changelog."
  echo "5. Review logs and investigate suspected compromise separately."
  echo
  echo "Debian/Ubuntu: sudo apt update && sudo apt upgrade"
  echo "Fedora/RHEL:   sudo dnf update"
  echo "Alpine:        sudo apk update && sudo apk upgrade"
  echo "macOS/Homebrew: brew update && brew upgrade php"
  echo
  echo "Commands above update packages broadly; review proposed changes first."
  echo "Do not assume these commands update every custom PHP installation."
  echo "PHP release information: $PHP_URL"
fi

if [[ -n "$CSV_OUT" ]]; then
  {
    echo 'php_version,status,reason,upstream_fix_threshold'
    for i in "${!RESULT_VERSIONS[@]}"; do
      printf '"%s","%s","%s","%s"\n' \
        "${RESULT_VERSIONS[$i]}" "${RESULT_STATUSES[$i]}" \
        "${RESULT_REASONS[$i]//\"/\"\"}" "${RESULT_FIXED[$i]}"
    done
  } > "$CSV_OUT" || { echo "Could not write CSV"; exit 2; }
  echo "CSV report written: $CSV_OUT"
fi

if [[ -n "$JSON_OUT" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required to create valid JSON output."
    exit 2
  fi

  export JSON_OUT
  export RESULT_VERSIONS RESULT_STATUSES RESULT_REASONS RESULT_FIXED
  export ADVISORY TOOL VERSION

  # Bash arrays are serialized safely using a temporary tab-delimited stream.
  tmp="${TMPDIR:-/tmp}/codesec-report-$$.txt"
  for i in "${!RESULT_VERSIONS[@]}"; do
    printf '%s\t%s\t%s\t%s\n' \
      "${RESULT_VERSIONS[$i]}" "${RESULT_STATUSES[$i]}" \
      "${RESULT_REASONS[$i]}" "${RESULT_FIXED[$i]}"
  done > "$tmp"

  REPORT_TMP="$tmp" python3 - <<'PY'
import csv, json, os

items = []
with open(os.environ["REPORT_TMP"], encoding="utf-8") as f:
    for row in csv.reader(f, delimiter="\t"):
        if len(row) == 4:
            items.append({
                "php_version": row[0],
                "status": row[1],
                "reason": row[2],
                "upstream_fix_threshold": row[3] or None,
            })

report = {
    "tool": os.environ["TOOL"],
    "tool_version": os.environ["VERSION"],
    "advisory": os.environ["ADVISORY"],
    "results": items,
    "limitations": [
        "Version-only upstream threshold check",
        "Vendor backports are not detected",
        "CLI version may differ from web runtime",
        "No remote scanning or exploitation",
        "Log indicators are not proof of compromise"
    ]
}
with open(os.environ["JSON_OUT"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
    f.write("\n")
print("JSON report written:", os.environ["JSON_OUT"])
PY
  rm -f "$tmp"
fi

echo
echo "Reminder: patching fixes the vulnerability; log review alone cannot."
echo "Review official PHP and operating-system vendor advisories."
exit "$EXIT_CODE"
