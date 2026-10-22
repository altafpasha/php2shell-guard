#!/usr/bin/env bash
# CodeSec PHP2Shell Guard
# Defensive inventory and remediation helper.
# MIT License
# Author: Altaf Pasha | https://altafpasha.in | X: @altafpasha_h

set -uo pipefail

# ─── Tool Info ────────────────────────────────────────────────────────────────
TOOL="CodeSec PHP2Shell Guard"
VERSION="2.1.0"
AUTHOR="Altaf Pasha"
WEBSITE="https://altafpasha.in"
TWITTER="@altafpasha_h"
GITHUB="https://github.com/altafpasha/php2shell-guard"
ADVISORY="https://www.php.net/security/"
PHP_URL="https://www.php.net/downloads.php"

# ─── Color Codes ──────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[1;31m'
  GREEN='\033[1;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[1;34m'
  MAGENTA='\033[1;35m'
  CYAN='\033[1;36m'
  WHITE='\033[1;37m'
  DIM='\033[2m'
  BOLD='\033[1m'
  RESET='\033[0m'
  BG_RED='\033[41m'
  BG_GREEN='\033[42m'
  BG_BLUE='\033[44m'
  BG_YELLOW='\033[43m'
else
  RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE=''
  DIM='' BOLD='' RESET='' BG_RED='' BG_GREEN='' BG_BLUE='' BG_YELLOW=''
fi

# ─── State Variables ──────────────────────────────────────────────────────────
JSON_OUT=""
CSV_OUT=""
VERSIONS_FILE=""
LOG_FILE=""
SYSTEM_MODE=0
SHOW_PATCH=0
CHECK_PROCESSES=1
EXIT_CODE=0
INTERACTIVE=0

declare -a FOUND_VERSIONS=()
declare -a FOUND_SOURCES=()
declare -a RESULT_VERSIONS=()
declare -a RESULT_STATUSES=()
declare -a RESULT_REASONS=()
declare -a RESULT_FIXED=()
declare -a LOG_FINDINGS=()

# ─── Banner ───────────────────────────────────────────────────────────────────
show_banner() {
  echo -e "${CYAN}"
  cat <<'BANNER'

   ██████╗ ██████╗ ██████╗ ███████╗███████╗███████╗ ██████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝
  ██║     ██║   ██║██║  ██║█████╗  ███████╗█████╗  ██║
  ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══╝  ██║
  ╚██████╗╚██████╔╝██████╔╝███████╗███████║███████╗╚██████╗
   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝

BANNER
  echo -e "${RED}"
  cat <<'BANNER'
  ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
  ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
  ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
  ██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
  ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

BANNER
  echo -e "${GREEN}"
  cat <<'BANNER'
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

BANNER
  echo -e "${RESET}"
  echo -e "${DIM}  ─────────────────────────────────────────────────────────────${RESET}"
  echo -e "  ${BOLD}${WHITE}PHP2Shell Guard${RESET} ${DIM}v${VERSION}${RESET}  ${DIM}│${RESET}  ${CYAN}CVE-2026-109618${RESET} ${DIM}&${RESET} ${CYAN}CVE-2026-109619${RESET}"
  echo -e "  ${DIM}CVSS v4.0: ${RESET}${RED}${BOLD}9.2 CRITICAL${RESET}  ${DIM}│${RESET}  ${GREEN}Defensive Security Tool${RESET}"
  echo -e "${DIM}  ─────────────────────────────────────────────────────────────${RESET}"
  echo -e "  ${DIM}Author :${RESET} ${BOLD}${WHITE}${AUTHOR}${RESET}"
  echo -e "  ${DIM}Web    :${RESET} ${CYAN}${WEBSITE}${RESET}"
  echo -e "  ${DIM}X      :${RESET} ${BLUE}${TWITTER}${RESET}"
  echo -e "  ${DIM}GitHub :${RESET} ${MAGENTA}${GITHUB}${RESET}"
  echo -e "${DIM}  ─────────────────────────────────────────────────────────────${RESET}"
  echo
}

# ─── Separator ────────────────────────────────────────────────────────────────
separator() {
  echo -e "${DIM}  ─────────────────────────────────────────────────────────────${RESET}"
}

# ─── Status Badges ────────────────────────────────────────────────────────────
status_badge() {
  case "$1" in
    potentially_vulnerable)
      echo -e "${BG_RED}${WHITE}${BOLD} ✘ VULNERABLE ${RESET}" ;;
    likely_fixed)
      echo -e "${BG_GREEN}${WHITE}${BOLD} ✔ LIKELY FIXED ${RESET}" ;;
    unknown_or_legacy)
      echo -e "${BG_YELLOW}${WHITE}${BOLD} ⚠ LEGACY/EOL ${RESET}" ;;
    *)
      echo -e "${BG_BLUE}${WHITE}${BOLD} ? UNKNOWN ${RESET}" ;;
  esac
}

# ─── Interactive Menu ─────────────────────────────────────────────────────────
show_menu() {
  echo -e "  ${BOLD}${WHITE}Select an option:${RESET}"
  echo
  echo -e "  ${CYAN}${BOLD}[1]${RESET}  🖥️   ${WHITE}Scan Local System${RESET}          ${DIM}— Auto-detect & check installed PHP${RESET}"
  echo -e "  ${CYAN}${BOLD}[2]${RESET}  🔢  ${WHITE}Check Specific Version${RESET}      ${DIM}— Enter a PHP version manually${RESET}"
  echo -e "  ${CYAN}${BOLD}[3]${RESET}  📁  ${WHITE}Batch Check (File)${RESET}          ${DIM}— Check multiple versions from file${RESET}"
  echo -e "  ${CYAN}${BOLD}[4]${RESET}  📊  ${WHITE}Generate Reports${RESET}            ${DIM}— Export results to JSON / CSV${RESET}"
  echo -e "  ${CYAN}${BOLD}[5]${RESET}  📜  ${WHITE}Review PHP Error Log${RESET}        ${DIM}— Scan logs for crash indicators${RESET}"
  echo -e "  ${CYAN}${BOLD}[6]${RESET}  🩹  ${WHITE}Patch Guidance${RESET}              ${DIM}— Step-by-step update instructions${RESET}"
  echo -e "  ${CYAN}${BOLD}[7]${RESET}  🔒  ${WHITE}Full Defensive Audit${RESET}        ${DIM}— System + Logs + Reports + Patch${RESET}"
  echo -e "  ${CYAN}${BOLD}[8]${RESET}  📋  ${WHITE}Patched Versions Reference${RESET}  ${DIM}— View safe version numbers${RESET}"
  echo -e "  ${CYAN}${BOLD}[9]${RESET}  ❓  ${WHITE}Help & Usage Info${RESET}           ${DIM}— Show all CLI options${RESET}"
  echo -e "  ${CYAN}${BOLD}[0]${RESET}  🚪  ${WHITE}Exit${RESET}"
  echo
  separator
}

read_choice() {
  echo -ne "  ${YELLOW}${BOLD}⮞  Enter your choice [0-9]: ${RESET}"
  read -r choice
  echo
}

prompt_enter() {
  echo
  echo -ne "  ${DIM}Press Enter to return to menu...${RESET}"
  read -r
}

# ─── Patched Versions Table ──────────────────────────────────────────────────
show_patched_table() {
  echo
  echo -e "  ${BOLD}${WHITE}┌──────────────┬────────────────────┬──────────┐${RESET}"
  echo -e "  ${BOLD}${WHITE}│ PHP Branch   │ Min Safe Version   │ Status   │${RESET}"
  echo -e "  ${BOLD}${WHITE}├──────────────┼────────────────────┼──────────┤${RESET}"
  echo -e "  ${WHITE}│${RESET} PHP 8.5      ${WHITE}│${RESET} ${GREEN}${BOLD}8.5.12${RESET}             ${WHITE}│${RESET} ${GREEN}Patched${RESET}  ${WHITE}│${RESET}"
  echo -e "  ${WHITE}│${RESET} PHP 8.4      ${WHITE}│${RESET} ${GREEN}${BOLD}8.4.27${RESET}             ${WHITE}│${RESET} ${GREEN}Patched${RESET}  ${WHITE}│${RESET}"
  echo -e "  ${WHITE}│${RESET} PHP 8.3      ${WHITE}│${RESET} ${GREEN}${BOLD}8.3.36${RESET}             ${WHITE}│${RESET} ${GREEN}Patched${RESET}  ${WHITE}│${RESET}"
  echo -e "  ${WHITE}│${RESET} PHP 8.2      ${WHITE}│${RESET} ${GREEN}${BOLD}8.2.35${RESET}             ${WHITE}│${RESET} ${GREEN}Patched${RESET}  ${WHITE}│${RESET}"
  echo -e "  ${WHITE}│${RESET} PHP 8.1 & ↓  ${WHITE}│${RESET} ${RED}${BOLD}— EOL —${RESET}            ${WHITE}│${RESET} ${RED}Upgrade${RESET}  ${WHITE}│${RESET}"
  echo -e "  ${BOLD}${WHITE}└──────────────┴────────────────────┴──────────┘${RESET}"
  echo
  echo -e "  ${YELLOW}⚠  PHP 8.1 and below are End-of-Life. Upgrade to a supported branch!${RESET}"
}

# ─── Usage/Help (CLI) ────────────────────────────────────────────────────────
usage() {
  show_banner
  cat <<'EOF'
  Usage:
    ./codesec-php2shell-guard.sh                         Launch interactive menu
    ./codesec-php2shell-guard.sh --system                Scan local system
    ./codesec-php2shell-guard.sh --php-version 8.3.35    Check a specific version
    ./codesec-php2shell-guard.sh --versions-file FILE    Check multiple versions
    ./codesec-php2shell-guard.sh --system --json-out F   Export JSON report
    ./codesec-php2shell-guard.sh --system --csv-out F    Export CSV report
    ./codesec-php2shell-guard.sh --system --patch-guide  Show update guidance
    ./codesec-php2shell-guard.sh --log-file /path/to/log Review PHP error log

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

  Run without arguments to launch the interactive menu.

  This tool does not exploit targets, prove exploitability, or guarantee
  that a server is safe. Vendor backports require vendor-specific verification.
EOF
}

# ─── Compare numeric dotted versions using Bash arithmetic ────────────────────
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

# ─── Assess a PHP version ────────────────────────────────────────────────────
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

  local badge
  badge=$(status_badge "$status")

  echo
  separator
  echo -e "  ${BOLD}${WHITE}PHP Version :${RESET}  ${CYAN}${BOLD}$v${RESET}"
  echo -e "  ${BOLD}${WHITE}Source      :${RESET}  ${DIM}$source${RESET}"
  echo -e "  ${BOLD}${WHITE}Status      :${RESET}  $badge"
  echo -e "  ${BOLD}${WHITE}Reason      :${RESET}  $reason"
  [[ -n "$fixed" ]] && echo -e "  ${BOLD}${WHITE}Fix Version :${RESET}  ${GREEN}${BOLD}$fixed${RESET}"
  separator

  case "$status" in
    potentially_vulnerable|unknown_or_legacy) EXIT_CODE=1 ;;
  esac
}

# ─── Process file of versions ────────────────────────────────────────────────
load_versions_file() {
  local file="$1"
  [[ -r "$file" ]] || { echo -e "  ${RED}Cannot read $file${RESET}"; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -z "$line" ]] && continue
    FOUND_VERSIONS+=("$line")
    FOUND_SOURCES+=("versions file")
  done < "$file"
}

# ─── Detect system PHP ───────────────────────────────────────────────────────
detect_system_php() {
  echo -e "\n  ${BOLD}${CYAN}🔍 Scanning local system...${RESET}\n"

  if command -v php >/dev/null 2>&1; then
    local_php="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    if [[ -n "$local_php" ]]; then
      echo -e "  ${GREEN}✔${RESET} PHP CLI detected: ${BOLD}${WHITE}$local_php${RESET}"
      FOUND_VERSIONS+=("$local_php")
      FOUND_SOURCES+=("local PHP CLI")
    fi
  else
    echo -e "  ${YELLOW}⚠${RESET} PHP CLI not found in PATH."
  fi

  if (( CHECK_PROCESSES )); then
    echo
    echo -e "  ${BOLD}${WHITE}📋 PHP/Web-Server Process Inventory:${RESET}"
    echo -e "  ${DIM}(This is an inventory, not proof of exposure)${RESET}"
    echo
    if command -v pgrep >/dev/null 2>&1; then
      local procs
      procs=$(pgrep -afil 'php-fpm|php-cgi|apache2|httpd|frankenphp|lsphp' 2>/dev/null || true)
      if [[ -n "$procs" ]]; then
        while IFS= read -r proc; do
          echo -e "    ${DIM}├─${RESET} $proc"
        done <<< "$procs"
      else
        echo -e "    ${DIM}└─${RESET} No matching processes found."
      fi
    else
      echo -e "    ${DIM}└─${RESET} pgrep unavailable; skipping."
    fi
  fi

  echo
  echo -e "  ${BOLD}${WHITE}📦 Detected Package Managers:${RESET}"
  local found_pm=0
  command -v apt-get >/dev/null 2>&1 && { echo -e "    ${DIM}├─${RESET} ${GREEN}apt-get${RESET} (Debian/Ubuntu)"; found_pm=1; }
  command -v dnf >/dev/null 2>&1     && { echo -e "    ${DIM}├─${RESET} ${GREEN}dnf${RESET} (Fedora/RHEL)"; found_pm=1; }
  command -v yum >/dev/null 2>&1     && { echo -e "    ${DIM}├─${RESET} ${GREEN}yum${RESET} (older RHEL)"; found_pm=1; }
  command -v apk >/dev/null 2>&1     && { echo -e "    ${DIM}├─${RESET} ${GREEN}apk${RESET} (Alpine)"; found_pm=1; }
  command -v brew >/dev/null 2>&1    && { echo -e "    ${DIM}├─${RESET} ${GREEN}brew${RESET} (macOS Homebrew)"; found_pm=1; }
  (( found_pm == 0 )) && echo -e "    ${DIM}└─${RESET} ${YELLOW}None detected${RESET}"
}

# ─── Log review ──────────────────────────────────────────────────────────────
review_log() {
  local logfile="$1"
  [[ -r "$logfile" ]] || { echo -e "  ${RED}✘ Cannot read log file: $logfile${RESET}"; return 1; }
  echo
  echo -e "  ${BOLD}${WHITE}📜 Log Review Indicators${RESET}"
  echo -e "  ${DIM}These patterns are leads for human review, not proof of compromise.${RESET}"
  echo

  if grep -Ein \
    'Allowed memory size exhausted|PHP Fatal error|child exited|segfault|multipart|unexpected EOF' \
    "$logfile" | head -n 50 | while IFS= read -r match; do
      echo -e "    ${RED}▸${RESET} $match"
    done; then
    LOG_FINDINGS+=("Matched one or more PHP error/crash indicators; investigate context and timestamps.")
  else
    echo -e "    ${GREEN}✔${RESET} No configured indicators matched."
  fi
}

# ─── Patch guidance ──────────────────────────────────────────────────────────
show_patch_guide() {
  echo
  echo -e "  ${BOLD}${WHITE}🩹 Patch Guidance${RESET}"
  separator
  echo -e "  ${CYAN}${BOLD}Step 1:${RESET} Back up the system and confirm your supported package source."
  echo -e "  ${CYAN}${BOLD}Step 2:${RESET} Update PHP from the official OS/vendor repository or PHP release."
  echo -e "  ${CYAN}${BOLD}Step 3:${RESET} Restart the actual PHP runtime and web-server workers."
  echo -e "  ${CYAN}${BOLD}Step 4:${RESET} Recheck the runtime version and vendor package changelog."
  echo -e "  ${CYAN}${BOLD}Step 5:${RESET} Review logs and investigate suspected compromise separately."
  separator
  echo
  echo -e "  ${BOLD}${WHITE}OS-Specific Update Commands:${RESET}"
  echo
  echo -e "  ${GREEN}Debian/Ubuntu :${RESET}  sudo apt update && sudo apt upgrade"
  echo -e "  ${GREEN}Fedora/RHEL   :${RESET}  sudo dnf update"
  echo -e "  ${GREEN}Alpine        :${RESET}  sudo apk update && sudo apk upgrade"
  echo -e "  ${GREEN}macOS/Homebrew:${RESET}  brew update && brew upgrade php"
  echo
  echo -e "  ${YELLOW}⚠  Commands above update packages broadly; review proposed changes first.${RESET}"
  echo -e "  ${YELLOW}⚠  Do not assume these commands update every custom PHP installation.${RESET}"
  echo -e "  ${DIM}PHP release information: ${PHP_URL}${RESET}"
}

# ─── CSV export ──────────────────────────────────────────────────────────────
write_csv() {
  local outfile="$1"
  {
    echo 'php_version,status,reason,upstream_fix_threshold'
    for i in "${!RESULT_VERSIONS[@]}"; do
      printf '"%s","%s","%s","%s"\n' \
        "${RESULT_VERSIONS[$i]}" "${RESULT_STATUSES[$i]}" \
        "${RESULT_REASONS[$i]//\"/\"\"}" "${RESULT_FIXED[$i]}"
    done
  } > "$outfile" || { echo -e "  ${RED}✘ Could not write CSV${RESET}"; return 1; }
  echo -e "  ${GREEN}✔${RESET} CSV report written: ${BOLD}${outfile}${RESET}"
}

# ─── JSON export ─────────────────────────────────────────────────────────────
write_json() {
  local outfile="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    echo -e "  ${RED}✘ Python 3 is required for JSON output.${RESET}"
    return 1
  fi

  export JSON_OUT="$outfile"
  export RESULT_VERSIONS RESULT_STATUSES RESULT_REASONS RESULT_FIXED
  export ADVISORY TOOL VERSION

  # Bash arrays are serialized safely using a temporary tab-delimited stream.
  local tmp="${TMPDIR:-/tmp}/codesec-report-$$.txt"
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
PY
  rm -f "$tmp"
  echo -e "  ${GREEN}✔${RESET} JSON report written: ${BOLD}${outfile}${RESET}"
}

# ─── Run assessment on all collected versions ─────────────────────────────────
run_assessment() {
  if ((${#FOUND_VERSIONS[@]} == 0)); then
    echo -e "  ${YELLOW}⚠  No PHP versions supplied or detected.${RESET}"
    return 1
  fi

  echo
  echo -e "  ${BOLD}${WHITE}=== $TOOL v$VERSION ===${RESET}"
  echo -e "  ${DIM}Advisory: ${ADVISORY}${RESET}"

  for i in "${!FOUND_VERSIONS[@]}"; do
    assess_version "${FOUND_VERSIONS[$i]}" "${FOUND_SOURCES[$i]}"
  done

  echo
  echo -e "  ${YELLOW}${BOLD}⚠  Reminder:${RESET} ${WHITE}Patching fixes the vulnerability; log review alone cannot.${RESET}"
  echo -e "  ${DIM}Review official PHP and operating-system vendor advisories.${RESET}"
}

# ─── Footer ──────────────────────────────────────────────────────────────────
show_footer() {
  echo
  separator
  echo -e "  ${DIM}${TOOL} v${VERSION} — ${AUTHOR}${RESET}"
  echo -e "  ${DIM}Web: ${WEBSITE}  |  X: ${TWITTER}  |  GitHub: ${GITHUB}${RESET}"
  separator
}

# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU MODE
# ═══════════════════════════════════════════════════════════════════════════════
run_interactive() {
  while true; do
    clear
    show_banner
    show_menu
    read_choice

    case "$choice" in
      1) # Scan Local System
        FOUND_VERSIONS=(); FOUND_SOURCES=()
        RESULT_VERSIONS=(); RESULT_STATUSES=(); RESULT_REASONS=(); RESULT_FIXED=()
        SYSTEM_MODE=1
        detect_system_php
        run_assessment
        show_footer
        prompt_enter
        ;;

      2) # Check Specific Version
        FOUND_VERSIONS=(); FOUND_SOURCES=()
        RESULT_VERSIONS=(); RESULT_STATUSES=(); RESULT_REASONS=(); RESULT_FIXED=()
        echo -ne "  ${YELLOW}Enter PHP version (e.g. 8.3.35): ${RESET}"
        read -r user_version
        if [[ -n "$user_version" ]]; then
          FOUND_VERSIONS+=("$user_version")
          FOUND_SOURCES+=("user input")
          run_assessment
        else
          echo -e "  ${RED}✘ No version entered.${RESET}"
        fi
        show_footer
        prompt_enter
        ;;

      3) # Batch Check from File
        FOUND_VERSIONS=(); FOUND_SOURCES=()
        RESULT_VERSIONS=(); RESULT_STATUSES=(); RESULT_REASONS=(); RESULT_FIXED=()
        echo -ne "  ${YELLOW}Enter path to versions file: ${RESET}"
        read -r user_file
        if [[ -n "$user_file" ]]; then
          load_versions_file "$user_file"
          run_assessment
        else
          echo -e "  ${RED}✘ No file path entered.${RESET}"
        fi
        show_footer
        prompt_enter
        ;;

      4) # Generate Reports
        if ((${#RESULT_VERSIONS[@]} == 0)); then
          echo -e "  ${YELLOW}⚠  No results available yet. Run a scan first (option 1, 2, or 3).${RESET}"
        else
          echo -e "  ${BOLD}${WHITE}Export Options:${RESET}"
          echo -e "  ${CYAN}[a]${RESET}  JSON report"
          echo -e "  ${CYAN}[b]${RESET}  CSV report"
          echo -e "  ${CYAN}[c]${RESET}  Both JSON & CSV"
          echo -ne "\n  ${YELLOW}Choose [a/b/c]: ${RESET}"
          read -r export_choice
          case "$export_choice" in
            a|A)
              echo -ne "  ${YELLOW}JSON filename (default: report.json): ${RESET}"
              read -r jf; jf="${jf:-report.json}"
              write_json "$jf"
              ;;
            b|B)
              echo -ne "  ${YELLOW}CSV filename (default: report.csv): ${RESET}"
              read -r cf; cf="${cf:-report.csv}"
              write_csv "$cf"
              ;;
            c|C)
              echo -ne "  ${YELLOW}JSON filename (default: report.json): ${RESET}"
              read -r jf; jf="${jf:-report.json}"
              echo -ne "  ${YELLOW}CSV filename (default: report.csv): ${RESET}"
              read -r cf; cf="${cf:-report.csv}"
              write_json "$jf"
              write_csv "$cf"
              ;;
            *) echo -e "  ${RED}✘ Invalid choice.${RESET}" ;;
          esac
        fi
        show_footer
        prompt_enter
        ;;

      5) # Review PHP Error Log
        echo -ne "  ${YELLOW}Enter PHP version for context (e.g. 8.3.35): ${RESET}"
        read -r log_ver
        echo -ne "  ${YELLOW}Enter log file path: ${RESET}"
        read -r log_path
        if [[ -n "$log_ver" ]]; then
          FOUND_VERSIONS=(); FOUND_SOURCES=()
          RESULT_VERSIONS=(); RESULT_STATUSES=(); RESULT_REASONS=(); RESULT_FIXED=()
          FOUND_VERSIONS+=("$log_ver")
          FOUND_SOURCES+=("user input")
          run_assessment
        fi
        if [[ -n "$log_path" ]]; then
          review_log "$log_path"
        else
          echo -e "  ${RED}✘ No log file path entered.${RESET}"
        fi
        show_footer
        prompt_enter
        ;;

      6) # Patch Guidance
        show_patch_guide
        show_patched_table
        show_footer
        prompt_enter
        ;;

      7) # Full Defensive Audit
        FOUND_VERSIONS=(); FOUND_SOURCES=()
        RESULT_VERSIONS=(); RESULT_STATUSES=(); RESULT_REASONS=(); RESULT_FIXED=()
        SYSTEM_MODE=1
        detect_system_php
        run_assessment
        echo -ne "\n  ${YELLOW}Enter log file path (or press Enter to skip): ${RESET}"
        read -r audit_log
        [[ -n "$audit_log" ]] && review_log "$audit_log"
        show_patch_guide
        echo
        echo -ne "  ${YELLOW}Export JSON report? (y/N): ${RESET}"
        read -r do_json
        if [[ "$do_json" =~ ^[Yy] ]]; then
          echo -ne "  ${YELLOW}JSON filename (default: audit-report.json): ${RESET}"
          read -r jf; jf="${jf:-audit-report.json}"
          write_json "$jf"
        fi
        echo -ne "  ${YELLOW}Export CSV report? (y/N): ${RESET}"
        read -r do_csv
        if [[ "$do_csv" =~ ^[Yy] ]]; then
          echo -ne "  ${YELLOW}CSV filename (default: audit-report.csv): ${RESET}"
          read -r cf; cf="${cf:-audit-report.csv}"
          write_csv "$cf"
        fi
        show_footer
        prompt_enter
        ;;

      8) # Patched Versions Reference
        show_patched_table
        show_footer
        prompt_enter
        ;;

      9) # Help
        usage
        show_footer
        prompt_enter
        ;;

      0) # Exit
        echo -e "  ${GREEN}${BOLD}Thank you for using $TOOL!${RESET}"
        echo -e "  ${DIM}Stay patched. Stay protected. Stay vigilant.${RESET}"
        show_footer
        exit "$EXIT_CODE"
        ;;

      *)
        echo -e "  ${RED}✘ Invalid option. Please enter a number between 0-9.${RESET}"
        sleep 1
        ;;
    esac
  done
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSING (CLI MODE)
# ═══════════════════════════════════════════════════════════════════════════════

# If no arguments, launch interactive menu.
if (( $# == 0 )); then
  run_interactive
  exit 0
fi

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

# ─── CLI execution flow ──────────────────────────────────────────────────────
show_banner

if [[ -n "$VERSIONS_FILE" ]]; then
  load_versions_file "$VERSIONS_FILE"
fi

if (( SYSTEM_MODE )); then
  detect_system_php
fi

if ((${#FOUND_VERSIONS[@]} == 0)); then
  echo -e "  ${YELLOW}No PHP versions supplied or detected.${RESET}"
  usage
  exit 2
fi

run_assessment

if [[ -n "$LOG_FILE" ]]; then
  review_log "$LOG_FILE"
fi

if (( SHOW_PATCH )); then
  show_patch_guide
fi

if [[ -n "$CSV_OUT" ]]; then
  write_csv "$CSV_OUT"
fi

if [[ -n "$JSON_OUT" ]]; then
  write_json "$JSON_OUT"
fi

show_footer
exit "$EXIT_CODE"
