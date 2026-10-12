#!/usr/bin/env bash
# =============================================================================
#  enable-security-for-arch-linux.sh  —  FINAL v3.0.3
# =============================================================================
#  A production-grade security baseline for Arch-based systems.
#  Supported: Arch Linux, Manjaro, Omarchy, EndeavourOS, Garuda Linux.
#
#  CachyOS IS NOT SUPPORTED. Do not run this script on CachyOS.
#  Artix Linux is NOT SUPPORTED (no systemd).
#
#  v3.0.3 changes:
#    - FIX: patch_quoted_var writes the original operator back (+= stays +=).
#      v3.0.2 turned Omarchy's second KERNEL_CMDLINE[default]+= into =, which
#      wiped cryptdevice=/root= from the boot line.
#    - FIX: rollback is offered whenever the boot settings may be broken,
#      not only when the overall verdict is "fail".
#    - FIX: SSH started through sshd.socket is detected, and its listen ports
#      are kept open, so ufw cannot lock you out of a remote session.
#    - FIX: with -y, an active firewalld is kept (it was replaced silently);
#      use --force-ufw to replace it.
#    - FIX: a refused boot edit (e.g. SELinux) no longer triggers a rollback
#      of the whole setup; only a changed boot file counts as "may be broken".
#    - FIX: complain mode chosen before the first reboot is applied on the
#      next run instead of being recorded as done.
#    - NEW: Omarchy 4 Limine drop-ins (/etc/limine-entry-tool.d/*.conf) are
#      used when the main Limine files hold no KERNEL_CMDLINE line.
#
#  v3.0.2 changes (all from external review):
#    - FIX: Limine KERNEL_CMDLINE lines are now written correctly.
#      patch_quoted_var builds the left-hand side from the real line in the
#      file (${line%%=*}) instead of from the regex, so no backslashes leak
#      into the output and the leading space is preserved for += entries.
#    - FIX: removed the duplicate lsm= substitution that produced
#      "lsm=...,apparmor,apparmor" when lsm= already existed.
#    - FIX: --disable / --rollback no longer forces every profile to enforce.
#      aa_undo only stops the service; it does not touch profile modes.
#    - FIX: 'integrity' restored to LSM_VALUE (Arch Wiki canonical value).
#      KERNEL_PARAM_MODE is now tracked so cmdline_remove_lsm can strip the
#      old value on systems that had an earlier version installed.
#    - FIX: bootloader_sanity skips systemd-boot entries with no linux line
#      (memtest86+, EFI shell, etc.) instead of reporting a false failure.
#    - FIX: full file restored (previous reply was truncated mid-function).
#
#  v3.0.1 changes:
#    - systemd-boot: always prefer persistent /etc/kernel/cmdline and
#      /etc/cmdline.d/*.conf over regenerable entry files.
#    - Limine: handle per-kernel KERNEL_CMDLINE["..."]+= entries.
#    - apparmor.d is no longer auto-installed from the AUR (boot-loop risk).
#    - Rollback is idempotent (IN_ROLLBACK flag prevents stale manifest entries).
#    - CachyOS explicitly blocked in detect_distro.
#
#  v3.0.0 changes:
#    - Removed CachyOS support entirely (boot-loop risk).
#    - Removed ArcoLinux (discontinued), Artix (no systemd).
#    - Fixed rollback-on-unsupported-AppArmor bug.
#    - Fixed restore_entry deleting restored files.
#    - Fixed undo_files conflicting with bootloader_apply.
#    - Fixed do_uninstall not removing apparmor.d.
#    - Fixed progress counter showing [11/10].
#    - Improved cmdline_add_lsm robustness.
#    - Improved aa_set_mode profile filtering.
#    - Added aura AUR helper detection.
# =============================================================================

set -u
set -o pipefail
umask 022

# =============================================================================
# SECTION 1: SETTINGS AND FILE LOCATIONS
# =============================================================================
SCRIPT_VERSION="3.0.3"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"
SCRIPT_FILE="${SCRIPT_PATH##*/}"
[[ -n $SCRIPT_FILE ]] || SCRIPT_FILE="enable-security-for-arch-linux.sh"

# FIX v3.0.2: restored 'integrity' — this is the canonical value from the
# Arch Wiki AppArmor page. Removing it broke --disable on systems where an
# earlier version had already written the old value to the bootloader.
LSM_VALUE="landlock,lockdown,yama,integrity,apparmor,bpf"
SECURITY_VALUE="apparmor"
APPARMOR_BOOTPARAM="1"

OS_RELEASE_FILE="/etc/os-release"
STATE_DIR="/var/lib/arch-security"
STATE_FILE="$STATE_DIR/state"
MANIFEST_FILE="$STATE_DIR/manifest"
LOG_FILE="/var/log/arch-security.log"
LOCK_FILE="/run/arch-security.lock"
SYSCTL_FILE="/etc/sysctl.d/99-arch-security.conf"
GRUB_DEFAULT_FILE="/etc/default/grub"
GRUB_CFG_FILE="/boot/grub/grub.cfg"
LIMINE_DEFAULT_FILE="/etc/default/limine"
LIMINE_ENTRY_TOOL_CONF="/etc/limine-entry-tool.conf"
LIMINE_DROPIN_DIR="/etc/limine-entry-tool.d"
KERNEL_CMDLINE_FILE="/etc/kernel/cmdline"
CMDLINE_D="/etc/cmdline.d"
SDBOOT_MANAGE_CONF="/etc/sdboot-manage.conf"
UKI_CONF="/etc/kernel/uki.conf"
APPARMOR_DIR="/etc/apparmor.d"
APPARMOR_PARSER_CONF="/etc/apparmor/parser.conf"
LSM_SYSFS="/sys/kernel/security/lsm"
APPARMOR_SYSFS="/sys/kernel/security/apparmor"
PROC_CMDLINE="/proc/cmdline"
PACMAN_LOCK="/var/lib/pacman/db.lck"
MODULE_DIR="/usr/lib/modules"

if [[ "${ARCH_SEC_TESTING:-0}" == "1" ]]; then
  OS_RELEASE_FILE="${T_OS_RELEASE_FILE:-$OS_RELEASE_FILE}"
  STATE_DIR="${T_STATE_DIR:-$STATE_DIR}"
  STATE_FILE="$STATE_DIR/state"
  MANIFEST_FILE="$STATE_DIR/manifest"
  LOG_FILE="${T_LOG_FILE:-$LOG_FILE}"
  LOCK_FILE="${T_LOCK_FILE:-$LOCK_FILE}"
  SYSCTL_FILE="${T_SYSCTL_FILE:-$SYSCTL_FILE}"
  GRUB_DEFAULT_FILE="${T_GRUB_DEFAULT_FILE:-$GRUB_DEFAULT_FILE}"
  GRUB_CFG_FILE="${T_GRUB_CFG_FILE:-$GRUB_CFG_FILE}"
  LIMINE_DEFAULT_FILE="${T_LIMINE_DEFAULT_FILE:-$LIMINE_DEFAULT_FILE}"
  LIMINE_ENTRY_TOOL_CONF="${T_LIMINE_ENTRY_TOOL_CONF:-$LIMINE_ENTRY_TOOL_CONF}"
  LIMINE_DROPIN_DIR="${T_LIMINE_DROPIN_DIR:-$LIMINE_DROPIN_DIR}"
  KERNEL_CMDLINE_FILE="${T_KERNEL_CMDLINE_FILE:-$KERNEL_CMDLINE_FILE}"
  CMDLINE_D="${T_CMDLINE_D:-$CMDLINE_D}"
  SDBOOT_MANAGE_CONF="${T_SDBOOT_MANAGE_CONF:-$SDBOOT_MANAGE_CONF}"
  UKI_CONF="${T_UKI_CONF:-$UKI_CONF}"
  APPARMOR_DIR="${T_APPARMOR_DIR:-$APPARMOR_DIR}"
  LSM_SYSFS="${T_LSM_SYSFS:-$LSM_SYSFS}"
  APPARMOR_SYSFS="${T_APPARMOR_SYSFS:-$APPARMOR_SYSFS}"
  PROC_CMDLINE="${T_PROC_CMDLINE:-$PROC_CMDLINE}"
fi

ACTION=""
AI_MODE=""
ASSUME_YES=0
DRY_RUN=0
FORCE_UFW=0
OPT_NO_COLOR=0
SHOW_HELP=0
SHOW_VERSION=0
ORIG_ARGS=()

STEP_N=0
STEP_TOTAL=1
STEP_FAILS=0
CURRENT_PID=""
RUN_TMP=""
DISTRO_KEY=""
DISTRO_LABEL=""
DISTRO_SUPPORT=""
OS_ID=""; OS_LIKE=""; OS_NAME=""; OS_PRETTY=""
BOOTLOADER="unknown"
FW_MODE="ufw"
UPGRADE_OK=0
FW_STATUS="skipped"; AA_STATUS="skipped"; SYS_STATUS="skipped"
NEED_REBOOT=0
BOOT_BROKEN=0
NOTES=()
AA_KERNEL_SUPPORTED=1
AUR_HELPER=""

# FIX v3.0.1: during rollback, track_file() becomes a no-op so the
# bootloader regeneration step does not re-add stale manifest entries.
IN_ROLLBACK=0

# =============================================================================
# SECTION 2: TERMINAL LOOK AND FEEL
# =============================================================================
UI_TTY=0; UI_UTF8=0; UI_COLOR=0; UI_WIDTH=72
C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
C_BLUE=""; C_CYAN=""; C_MAGENTA=""
SYM_OK="[ok]"; SYM_FAIL="[x]"; SYM_WARN="[!]"; SYM_INFO="*"; SYM_ARROW=">"; SYM_SKIP="-"
BAR_ON="#"; BAR_OFF="."
BX_TL="+"; BX_TR="+"; BX_BL="+"; BX_BR="+"; BX_H="-"; BX_V="|"; BX_ML="+"; BX_MR="+"
SPIN_FRAMES=('|' '/' '-' '\')

setup_ui() {
  local cols
  [[ -t 1 ]] && UI_TTY=1
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) UI_UTF8=1 ;;
  esac
  [[ "${TERM:-}" == "linux" ]] && UI_UTF8=0
  if (( UI_TTY )) && [[ -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]] && (( ! OPT_NO_COLOR )); then
    UI_COLOR=1
  fi
  if (( UI_COLOR )); then
    C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
    C_RED=$'\e[38;5;203m'; C_GREEN=$'\e[38;5;78m'; C_YELLOW=$'\e[38;5;221m'
    C_BLUE=$'\e[38;5;75m'; C_CYAN=$'\e[38;5;87m'; C_MAGENTA=$'\e[38;5;177m'
  fi
  if (( UI_UTF8 )); then
    SYM_OK="✔"; SYM_FAIL="✘"; SYM_WARN="▲"; SYM_INFO="●"; SYM_ARROW="➜"; SYM_SKIP="○"
    BAR_ON="▰"; BAR_OFF="▱"
    BX_TL="╭"; BX_TR="╮"; BX_BL="╰"; BX_BR="╯"; BX_H="─"; BX_V="│"; BX_ML="├"; BX_MR="┤"
    SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  fi
  cols=$(tput cols 2>/dev/null || echo 80)
  [[ $cols =~ ^[0-9]+$ ]] || cols=80
  (( cols > 78 )) && cols=78
  (( cols < 56 )) && cols=56
  UI_WIDTH=$cols
}

cursor_hide() { (( UI_TTY )) && printf '\033[?25l'; return 0; }
cursor_show() { (( UI_TTY )) && printf '\033[?25h'; return 0; }

repeat_char() {
  local n=$1 c=$2 s=""
  (( n > 0 )) || return 0
  printf -v s '%*s' "$n" ''
  printf '%s' "${s// /$c}"
}

strip_ansi() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' <<<"$1"; }

box_top() { printf '%s%s%s%s%s\n' "$1" "$BX_TL" "$(repeat_char $((UI_WIDTH - 2)) "$BX_H")" "$BX_TR" "$C_RESET"; }
box_sep() { printf '%s%s%s%s%s\n' "$1" "$BX_ML" "$(repeat_char $((UI_WIDTH - 2)) "$BX_H")" "$BX_MR" "$C_RESET"; }
box_bot() { printf '%s%s%s%s%s\n' "$1" "$BX_BL" "$(repeat_char $((UI_WIDTH - 2)) "$BX_H")" "$BX_BR" "$C_RESET"; }

box_row() {
  local bc=$1 text=$2 plain pad
  plain="$(strip_ansi "$text")"
  pad=$(( UI_WIDTH - 4 - ${#plain} ))
  (( pad < 0 )) && pad=0
  printf '%s%s%s %s%*s %s%s%s\n' "$bc" "$BX_V" "$C_RESET" "$text" "$pad" "" "$bc" "$BX_V" "$C_RESET"
}

box_text() {
  local bc=$1 tc=$2 line
  shift 2
  while IFS= read -r line; do
    box_row "$bc" "${tc}${line}${C_RESET}"
  done < <(printf '%s\n' "$*" | fold -s -w $((UI_WIDTH - 4)))
}

banner() {
  printf '\n'
  box_top "$C_CYAN"
  box_row "$C_CYAN" "${C_BOLD}ARCH LINUX SECURITY SETUP${C_RESET}   ${C_DIM}v${SCRIPT_VERSION}${C_RESET}"
  box_row "$C_CYAN" "${C_DIM}Production-grade protection for Arch-based systems${C_RESET}"
  box_row "$C_CYAN" "${C_DIM}Supported: Arch, Manjaro, Omarchy, EndeavourOS, Garuda${C_RESET}"
  box_bot "$C_CYAN"
}

section() {
  printf '\n  %s%s%s\n  %s%s%s\n' "$C_BOLD$C_CYAN" "$1" "$C_RESET" "$C_DIM" "$(repeat_char "${#1}" "$BX_H")" "$C_RESET"
}

step_prefix() {
  local n=$STEP_N t=$STEP_TOTAL on off
  (( t < 1 )) && t=1
  (( n > t )) && n=$t
  on=$(( n * 10 / t )); (( on > 10 )) && on=10
  off=$(( 10 - on ))
  printf '%s[%2d/%d]%s %s%s%s%s%s' "$C_DIM" "$n" "$t" "$C_RESET" \
    "$C_BLUE" "$(repeat_char "$on" "$BAR_ON")" "$C_DIM" "$(repeat_char "$off" "$BAR_OFF")" "$C_RESET"
}

step_live() { printf '\r\033[K  %s %s%s%s %s' "$(step_prefix)" "$C_CYAN" "$1" "$C_RESET" "$2"; }

step_final() {
  local st=$1 desc=$2 note=${3:-} sym col
  case $st in
    ok)   sym=$SYM_OK;    col=$C_GREEN ;;
    fail) sym=$SYM_FAIL;  col=$C_RED ;;
    warn) sym=$SYM_WARN;  col=$C_YELLOW ;;
    skip) sym=$SYM_SKIP;  col=$C_DIM ;;
    *)    sym=$SYM_ARROW; col=$C_MAGENTA ;;
  esac
  (( UI_TTY )) && printf '\r\033[K'
  printf '  %s %s%s%s %s' "$(step_prefix)" "$col" "$sym" "$C_RESET" "$desc"
  [[ -n $note ]] && printf '  %s%s%s' "$C_DIM" "$note" "$C_RESET"
  printf '\n'
}

spin_until_done() {
  local pid=$1 desc=$2 i=0
  (( UI_TTY )) || return 0
  while kill -0 "$pid" 2>/dev/null; do
    step_live "${SPIN_FRAMES[i % ${#SPIN_FRAMES[@]}]}" "$desc"
    i=$(( i + 1 ))
    sleep 0.1
  done
}

show_log_tail() {
  local mark=$1 l
  tail -c +"$(( mark + 1 ))" "$LOG_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' | tail -n 6 | while IFS= read -r l; do
    printf '        %s%s%s\n' "$C_DIM" "${l:0:$(( UI_WIDTH + 4 ))}" "$C_RESET"
  done
  return 0
}

# =============================================================================
# SECTION 3: MESSAGES, LOGGING AND SMALL HELPERS
# =============================================================================
log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null || true; }
info()   { printf '  %s%s%s %s\n' "$C_CYAN" "$SYM_INFO" "$C_RESET" "$*"; }
good()   { printf '  %s%s%s %s\n' "$C_GREEN" "$SYM_OK" "$C_RESET" "$*"; }
warn()   { printf '  %s%s%s %s\n' "$C_YELLOW" "$SYM_WARN" "$C_RESET" "$*"; log "WARN: $*"; }
err()    { printf '  %s%s%s %s\n' "$C_RED" "$SYM_FAIL" "$C_RESET" "$*" >&2; log "ERROR: $*"; }
add_note() { NOTES+=("$*"); }

have() { command -v "$1" >/dev/null 2>&1; }

die_box() {
  local title=$1; shift
  printf '\n'
  box_top "$C_RED"
  box_row "$C_RED" "${C_BOLD}${C_RED}${SYM_FAIL}  ${title}${C_RESET}"
  box_sep "$C_RED"
  box_text "$C_RED" "" "$*"
  box_bot "$C_RED"
  printf '\n'
  log "FATAL: $title - $*"
  exit 1
}

hard_fail() {
  if (( DRY_RUN )); then warn "$2 (ignored because of --dry-run)"; else die_box "$1" "$2"; fi
}

ask_yes_no() {
  local q=$1 def=${2:-Y} ans prompt
  (( ASSUME_YES )) && return 0
  if [[ ! -t 0 ]]; then [[ $def == Y ]]; return; fi
  [[ $def == Y ]] && prompt="[Y/n]" || prompt="[y/N]"
  printf '\n'
  read -r -p "  ${q} ${prompt} " ans || return 1
  ans=${ans:-$def}
  [[ $ans == [Yy]* ]]
}

mark_set()   { [[ -n ${RUN_TMP:-} && -d $RUN_TMP ]] && : >"$RUN_TMP/$1"; }
mark_clear() { [[ -n ${RUN_TMP:-} && -d $RUN_TMP ]] && rm -f "$RUN_TMP/$1"; }
mark_has()   { [[ -n ${RUN_TMP:-} && -e $RUN_TMP/$1 ]]; }

run_step() {
  local desc=$1; shift
  local start=$SECONDS rc=0 mark=0
  STEP_N=$(( STEP_N + 1 ))
  if (( DRY_RUN )); then
    log "[dry-run] $desc :: $*"
    step_final dry "$desc" "(dry-run: not executed)"
    return 0
  fi
  mark=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
  log ">>> STEP $STEP_N: $desc"
  "$@" </dev/null >>"$LOG_FILE" 2>&1 &
  CURRENT_PID=$!
  spin_until_done "$CURRENT_PID" "$desc"
  wait "$CURRENT_PID"; rc=$?
  CURRENT_PID=""
  log "<<< exit code $rc"
  if (( rc == 0 )); then
    step_final ok "$desc" "$(( SECONDS - start ))s"
  else
    STEP_FAILS=$(( STEP_FAILS + 1 ))
    step_final fail "$desc" "failed"
    show_log_tail "$mark"
  fi
  return "$rc"
}

fg_step() {
  local desc=$1; shift
  local rc=0
  STEP_N=$(( STEP_N + 1 ))
  if (( DRY_RUN )); then step_final dry "$desc" "(dry-run: not executed)"; return 0; fi
  "$@" >>"$LOG_FILE" 2>&1; rc=$?
  if (( rc == 0 )); then step_final ok "$desc"; else STEP_FAILS=$(( STEP_FAILS + 1 )); step_final fail "$desc" "failed"; fi
  return "$rc"
}

skip_step() {
  STEP_N=$(( STEP_N + 1 ))
  step_final skip "$1" "(${2})"
  log "SKIPPED: $1 - $2"
}

cleanup() {
  cursor_show
  if [[ -n ${RUN_TMP:-} && -d $RUN_TMP ]]; then rm -rf "$RUN_TMP"; fi
}

on_interrupt() {
  trap - INT TERM
  cursor_show
  if [[ -n $CURRENT_PID ]]; then
    pkill -TERM -P "$CURRENT_PID" 2>/dev/null || true
    kill -TERM "$CURRENT_PID" 2>/dev/null || true
    wait "$CURRENT_PID" 2>/dev/null || true
  fi
  printf '\n'
  warn "Stopped before the script finished."
  if [[ -t 0 ]] && manifest_nonempty && (( ! DRY_RUN )); then
    offer_rollback Y "You stopped the script while it was changing files."
  fi
  exit 130
}

# =============================================================================
# SECTION 4: MEMORY - STATE FILE AND BACKUP SYSTEM
# =============================================================================
state_get() {
  [[ -r $STATE_FILE ]] || return 1
  local v
  v=$(grep -E "^$1=" "$STATE_FILE" | tail -n1) || return 1
  printf '%s' "${v#*=}"
}

state_set() {
  (( DRY_RUN )) && return 0
  local tmp
  mkdir -p "$STATE_DIR" && touch "$STATE_FILE" || return 1
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-st.XXXXXX") || return 1
  grep -vE "^$1=" "$STATE_FILE" >"$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$1" "$2" >>"$tmp"
  cat "$tmp" >"$STATE_FILE"
  rm -f "$tmp"
}

state_set_default() { state_get "$1" >/dev/null 2>&1 || state_set "$1" "$2"; }

state_del() {
  (( DRY_RUN )) && return 0
  [[ -f $STATE_FILE ]] || return 0
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-st.XXXXXX") || return 1
  grep -vE "^$1=" "$STATE_FILE" >"$tmp" 2>/dev/null || true
  cat "$tmp" >"$STATE_FILE"
  rm -f "$tmp"
}

file_sha() { [[ -f $1 ]] && sha256sum -- "$1" 2>/dev/null | awk '{print $1}'; }

make_backup() {
  local f=$1 b="$1.backup" n=1
  while [[ -e $b ]]; do n=$(( n + 1 )); b="$f.backup.$n"; done
  if cp -p -- "$f" "$b" 2>/dev/null || cp -- "$f" "$b" 2>/dev/null; then
    if cmp -s -- "$f" "$b"; then printf '%s' "$b"; return 0; fi
  fi
  rm -f -- "$b"
  return 1
}

manifest_cat()      { [[ -r $MANIFEST_FILE ]] && cat "$MANIFEST_FILE"; return 0; }
manifest_nonempty() { [[ -s $MANIFEST_FILE ]]; }

manifest_find() {
  [[ -r $MANIFEST_FILE ]] || return 1
  P="$1" awk -F'|' '$2==ENVIRON["P"] {print; f=1} END{exit f?0:1}' "$MANIFEST_FILE"
}

manifest_put() {
  (( DRY_RUN )) && return 0
  local tmp
  mkdir -p "$STATE_DIR" && touch "$MANIFEST_FILE" || return 1
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-mf.XXXXXX") || return 1
  P="$2" awk -F'|' '$2!=ENVIRON["P"]' "$MANIFEST_FILE" >"$tmp"
  printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$tmp"
  cat "$tmp" >"$MANIFEST_FILE"
  rm -f "$tmp"
}

manifest_drop() {
  (( DRY_RUN )) && return 0
  [[ -f $MANIFEST_FILE ]] || return 0
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-mf.XXXXXX") || return 1
  P="$1" awk -F'|' '$2!=ENVIRON["P"]' "$MANIFEST_FILE" >"$tmp"
  cat "$tmp" >"$MANIFEST_FILE"
  rm -f "$tmp"
}

track_file() {
  local f=$1 kind=${2:-edited} b
  (( DRY_RUN )) && return 0
  # FIX v3.0.1: during rollback, we are restoring files, not editing them.
  (( IN_ROLLBACK )) && return 0
  manifest_find "$f" >/dev/null 2>&1 && return 0
  if [[ -e $f ]]; then
    b=$(make_backup "$f") || { echo "Could not make a backup of $f - refusing to edit it."; return 1; }
    manifest_put "$kind" "$f" "$b" "-" || return 1
    echo "Backup saved: $b"
  else
    manifest_put created "$f" "-" "-" || return 1
  fi
  return 0
}

seal_file() {
  local f=$1 line kind backup
  (( DRY_RUN )) && return 0
  line=$(manifest_find "$f") || return 0
  IFS='|' read -r kind _ backup _ <<<"$line"
  manifest_put "$kind" "$f" "$backup" "$(file_sha "$f")"
}

file_set_line() {
  local f=$1 re=$2 new=$3 tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-ln.XXXXXX") || return 1
  NEWLINE="$new" RE="$re" awk '
    { a[NR]=$0; if ($0 ~ ENVIRON["RE"]) last=NR }
    END { for (i=1;i<=NR;i++) print (i==last ? ENVIRON["NEWLINE"] : a[i]);
          if (!last) print ENVIRON["NEWLINE"] }
  ' "$f" >"$tmp" || { rm -f "$tmp"; return 1; }
  cat "$tmp" >"$f"
  rm -f "$tmp"
}

# =============================================================================
# SECTION 5: COMMAND-LINE OPTIONS AND HELP
# =============================================================================
usage_error() {
  printf 'Error: %s\nTry:   %s --help\n' "$1" "$SCRIPT_FILE" >&2
  exit 64
}

set_action() {
  if [[ -n $ACTION && $ACTION != "$1" ]]; then
    usage_error "please choose only ONE of --enable, --disable, --uninstall, --rollback, --status."
  fi
  ACTION=$1
}

set_ai() {
  if [[ -n $AI_MODE && $AI_MODE != "$1" ]]; then
    usage_error "--allow-ai-agent and --disable-ai-agent cannot be used together."
  fi
  AI_MODE=$1
}

parse_args() {
  while (( $# )); do
    case $1 in
      --enable)             set_action enable ;;
      --disable)            set_action disable ;;
      --uninstall)          set_action uninstall ;;
      --rollback)           set_action rollback ;;
      --status)             set_action status ;;
      --allow-ai-agent)     set_ai allowed ;;
      --disable-ai-agent)   set_ai blocked ;;
      -y|--yes)             ASSUME_YES=1 ;;
      --dry-run)            DRY_RUN=1 ;;
      --force-ufw)          FORCE_UFW=1 ;;
      --no-color)           OPT_NO_COLOR=1 ;;
      -h|--help)            SHOW_HELP=1 ;;
      -V|--version)         SHOW_VERSION=1 ;;
      *)                    usage_error "unknown option '$1'" ;;
    esac
    shift
  done
  if [[ -z $ACTION ]]; then
    if [[ -n $AI_MODE ]]; then ACTION=ai; else ACTION=enable; fi
  fi
  if [[ -n $AI_MODE && $ACTION != enable && $ACTION != ai ]]; then
    usage_error "the AI-agent options only work together with the normal install, or on their own."
  fi
}

show_help() {
  cat <<EOF

${C_BOLD}${C_CYAN}ARCH LINUX SECURITY SETUP${C_RESET}  v${SCRIPT_VERSION}
Gives Arch-based systems a production-grade security baseline:
firewall + AppArmor + safe kernel settings. Permanent after reboot.

${C_BOLD}USAGE${C_RESET}
  ./${SCRIPT_FILE} [OPTION...]
  (needs administrator rights; the script asks sudo by itself)

${C_BOLD}MAIN COMMANDS${C_RESET}  (choose one; no option = install and enable)
  --enable             Install and enable the security system.
  --disable            Turn the security system OFF. Nothing is uninstalled.
  --uninstall          Turn it off, restore ORIGINAL files, remove packages.
  --rollback           Undo only my file edits and switch off what I enabled.
  --status             Show what is installed and active right now.

${C_BOLD}AI-AGENT SWITCH${C_RESET}  (for Omarchy and other systems with AI agents)
  --allow-ai-agent     AppArmor profiles go from "enforce" to "complain" (log only).
                       NOTE: This only affects programs that HAVE a profile.
                       Unprofiled programs are not confined either way.
                       On pure Arch, apparmor.d (AUR) installs in complain mode
                       by default. This switch is mainly for enforcing setups.
  --disable-ai-agent   Back to the most secure mode (AppArmor enforcing).

${C_BOLD}EXTRA OPTIONS${C_RESET}
  -y, --yes            Do not ask questions.
  --dry-run            Show what would happen; change nothing.
  --force-ufw          Replace firewalld by ufw (firewalld config is backed up).
  --no-color           Plain text, no colours.
  -h, --help           Show this help.
  -V, --version        Show the version.

${C_BOLD}SAFETY NET${C_RESET}
  Before editing a file the script saves a copy named <file>.backup right
  next to it. If something breaks, it asks: "Shall I undo my changes?"

${C_BOLD}SUPPORTED${C_RESET}
  Arch Linux, Manjaro, Omarchy, EndeavourOS, Garuda Linux

${C_BOLD}NOT SUPPORTED${C_RESET}
  CachyOS   — AppArmor has caused boot loops there. Do NOT run this script on CachyOS.
  Artix     — No systemd. This script requires systemd.
  ArcoLinux — Discontinued in 2025.

Log file: ${LOG_FILE}

EOF
}

# =============================================================================
# SECTION 6: SAFETY CHECKS
# =============================================================================
require_root() {
  (( EUID == 0 )) && return 0
  if (( DRY_RUN )); then warn "Not running as root: this is only a preview (--dry-run)."; return 0; fi
  if [[ -f $SCRIPT_PATH ]] && have sudo; then
    info "Administrator rights are needed - asking sudo for permission..."
    exec sudo bash "$SCRIPT_PATH" "${ORIG_ARGS[@]}"
  fi
  die_box "Administrator rights needed" "Please run this script as root, for example:  sudo ./${SCRIPT_FILE}"
}

init_workdirs() {
  RUN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/arch-security.XXXXXX") || { echo "Cannot create a temp folder." >&2; exit 1; }
  if ! { : >>"$LOG_FILE"; } 2>/dev/null; then LOG_FILE="/tmp/arch-security-$(id -u).log"; : >>"$LOG_FILE"; fi
  log "================ $SCRIPT_FILE v$SCRIPT_VERSION  action=$ACTION dry_run=$DRY_RUN ================"
  if (( ! DRY_RUN )); then
    exec 9>"$LOCK_FILE" 2>/dev/null || return 0
    flock -n 9 || die_box "Already running" "Another copy of this script is running. Wait for it to finish."
  fi
}

kernel_modules_present() { [[ -d "$MODULE_DIR/$(uname -r)" ]]; }

detect_apparmor_kernel_support() {
  if [[ -d /sys/module/apparmor ]] || [[ -d $APPARMOR_SYSFS ]]; then
    AA_KERNEL_SUPPORTED=1
    return 0
  fi
  if [[ -r /proc/config.gz ]]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_SECURITY_APPARMOR=y'; then
      AA_KERNEL_SUPPORTED=1
      return 0
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_SECURITY_APPARMOR=m'; then
      modprobe apparmor 2>/dev/null && { AA_KERNEL_SUPPORTED=1; return 0; }
    fi
  fi
  if compgen -G "$MODULE_DIR/$(uname -r)/kernel/security/apparmor/apparmor.ko*" >/dev/null 2>&1; then
    modprobe apparmor 2>/dev/null && { AA_KERNEL_SUPPORTED=1; return 0; }
  fi
  AA_KERNEL_SUPPORTED=0
  return 1
}

preflight() {
  section "System check"
  detect_distro
  case $DISTRO_SUPPORT in
    none)
      die_box "This is not an Arch-based system" \
        "I found '${OS_PRETTY:-unknown}'. This script is only for Arch Linux and systems based on it. Nothing was changed." ;;
    unsupported)
      if [[ $DISTRO_KEY == cachyos ]]; then
        die_box "CachyOS is not supported" \
          "This script refuses to run on CachyOS: AppArmor has caused boot loops there, and the project ships its own post-install guide. Nothing was changed."
      else
        die_box "This system is not supported" \
          "'${OS_PRETTY}' is not one of the supported Arch-based systems (Arch, Manjaro, Omarchy, EndeavourOS, Garuda). Nothing was changed."
      fi ;;
    generic)
      warn "'${OS_PRETTY}' says it is Arch-based, but it is not one of the specifically supported systems."
      ask_yes_no "Do you want to continue anyway?" N || { info "Okay, nothing was changed."; exit 0; } ;;
  esac
  info "System         : ${DISTRO_LABEL}"
  have pacman || hard_fail "Package manager missing" "The 'pacman' command was not found."
  [[ -d /run/systemd/system ]] || hard_fail "systemd is required" "This system is not running systemd."
  if have systemd-detect-virt && systemd-detect-virt --container -q 2>/dev/null; then
    hard_fail "Containers are not supported" "AppArmor and kernel settings belong to the real computer, not to a container."
  fi
  if ! kernel_modules_present; then
    hard_fail "Please reboot first" "Your kernel was updated since the last start. Reboot, then run this script again."
  fi
  BOOTLOADER=$(detect_bootloader)
  info "Boot loader    : ${BOOTLOADER}"

  if ! detect_apparmor_kernel_support; then
    info "AppArmor       : NOT available in this kernel"
    warn "This kernel was built without AppArmor. AppArmor will be SKIPPED completely."
    warn "Firewall and kernel hardening will still be applied."
    add_note "Your kernel was built without AppArmor. Use the standard 'linux' or 'linux-lts' kernel to get AppArmor."
  else
    info "AppArmor       : supported by this kernel"
  fi

  if is_omarchy; then
    info "Omarchy found  : AI agents are ${AI_MODE:-allowed (default)}."
  fi
}

# =============================================================================
# SECTION 7: DETECTING THE ARCH-BASED SYSTEM
# =============================================================================
is_omarchy() {
  [[ $OS_ID == omarchy ]] && return 0
  [[ $OS_ID == arch ]] || return 1
  have omarchy-version && return 0
  local d
  for d in /usr/share/omarchy /opt/omarchy /home/*/.local/share/omarchy /root/.local/share/omarchy; do
    [[ -d $d ]] && return 0
  done
  return 1
}

detect_distro() {
  DISTRO_KEY=""; DISTRO_LABEL=""; DISTRO_SUPPORT="none"
  [[ -r $OS_RELEASE_FILE ]] || return 0
  eval "$( ( . "$OS_RELEASE_FILE" 2>/dev/null
            printf 'OS_ID=%q OS_LIKE=%q OS_NAME=%q OS_PRETTY=%q\n' \
              "${ID:-}" "${ID_LIKE:-}" "${NAME:-}" "${PRETTY_NAME:-}" ) )"
  OS_ID=${OS_ID,,}
  if is_omarchy; then
    DISTRO_KEY=omarchy; DISTRO_LABEL="Omarchy (Arch-based)"; DISTRO_SUPPORT=tested
    return 0
  fi
  case $OS_ID in
    arch)         DISTRO_KEY=arch;        DISTRO_LABEL="Arch Linux";   DISTRO_SUPPORT=tested ;;
    endeavouros)  DISTRO_KEY=endeavouros; DISTRO_LABEL="EndeavourOS";  DISTRO_SUPPORT=tested ;;
    garuda)       DISTRO_KEY=garuda;      DISTRO_LABEL="Garuda Linux"; DISTRO_SUPPORT=tested ;;
    manjaro*)     DISTRO_KEY=manjaro;     DISTRO_LABEL="Manjaro";      DISTRO_SUPPORT=tested ;;
    artix)        DISTRO_KEY=artix;       DISTRO_LABEL="Artix Linux";  DISTRO_SUPPORT=unsupported ;;
    cachyos*)     DISTRO_KEY=cachyos;     DISTRO_LABEL="CachyOS";      DISTRO_SUPPORT=unsupported ;;
    *)
      if [[ " ${OS_LIKE,,} " == *" arch "* ]]; then
        DISTRO_KEY=generic; DISTRO_LABEL="${OS_PRETTY:-$OS_NAME} (Arch-based)"; DISTRO_SUPPORT=generic
      fi ;;
  esac
}

efi_boot_hint() {
  have efibootmgr || return 0
  local cur line
  cur=$(efibootmgr 2>/dev/null | sed -n 's/^BootCurrent: *//p')
  [[ -n $cur ]] || return 0
  line=$(efibootmgr -v 2>/dev/null | grep -i "^Boot${cur}" | head -n1)
  case "${line,,}" in
    *limine*)                          echo limine ;;
    *grub*)                            echo grub ;;
    *systemd*|*"linux boot manager"*)  echo systemd-boot ;;
  esac
}

detect_bootloader() {
  local hint
  hint=$(efi_boot_hint)
  if [[ -n $hint ]]; then echo "$hint"; return 0; fi
  if compgen -G '/sys/firmware/efi/efivars/LoaderInfo-*' >/dev/null; then echo systemd-boot; return 0; fi
  if [[ -f $LIMINE_DEFAULT_FILE ]] || have limine-update; then echo limine; return 0; fi
  if [[ -f $GRUB_DEFAULT_FILE && -f $GRUB_CFG_FILE ]]; then echo grub; return 0; fi
  if [[ -d /boot/loader/entries || -d /efi/loader/entries || -d /boot/efi/loader/entries ]]; then echo systemd-boot; return 0; fi
  echo unknown
}

# =============================================================================
# SECTION 8: PACKAGE MANAGER HELPERS
# =============================================================================
pkg_installed() { pacman -Qq "$1" >/dev/null 2>&1; }

pacman_lock_wait() {
  local waited=0
  while [[ -e $PACMAN_LOCK ]]; do
    if pgrep -x 'pacman|pamac|pamac-daemon|yay|paru|packagekitd|octopi' >/dev/null 2>&1; then
      (( waited >= 120 )) && { echo "Another package manager has kept pacman locked for 2 minutes. Close it and run this script again."; return 1; }
      sleep 3; waited=$(( waited + 3 ))
    else
      echo "Removing a leftover pacman lock ($PACMAN_LOCK): no package manager is running."
      rm -f "$PACMAN_LOCK" || return 1
    fi
  done
  return 0
}

pm_prepare() {
  local avail
  pacman_lock_wait || return 1
  avail=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ $avail =~ ^[0-9]+$ ]] && (( avail < 300000 )); then
    echo "Not enough free disk space on / (need about 300 MB, only $(( avail / 1024 )) MB free)."
    return 1
  fi
  return 0
}

repair_keyring() {
  local k pkgs=()
  pacman-key --init || true
  pacman-key --populate || true
  local keyring_pkgs=()
  case $DISTRO_KEY in
    arch)        keyring_pkgs=(archlinux-keyring) ;;
    endeavouros) keyring_pkgs=(archlinux-keyring endeavouros-keyring) ;;
    manjaro)     keyring_pkgs=(manjaro-keyring) ;;
    garuda)      keyring_pkgs=(garuda-keyring) ;;
    *)           keyring_pkgs=(archlinux-keyring) ;;
  esac
  for k in "${keyring_pkgs[@]}"; do
    pacman -Si "$k" >/dev/null 2>&1 && pkgs+=("$k")
  done
  if (( ${#pkgs[@]} )); then
    pacman -S --needed --noconfirm "${pkgs[@]}" || true
  fi
  return 0
}

pkg_install() {
  local attempt out rc did_sync=0 did_keys=0
  out=$(mktemp "${TMPDIR:-/tmp}/asec-pkg.XXXXXX") || return 1
  for attempt in 1 2 3; do
    pacman_lock_wait || { rm -f "$out"; return 1; }
    echo ">> pacman -S --needed --noconfirm $*   (attempt $attempt)"
    pacman -S --needed --noconfirm "$@" >"$out" 2>&1; rc=$?
    cat "$out"
    if (( rc == 0 )); then rm -f "$out"; return 0; fi
    if grep -qiE 'Could not resolve host|Failed to connect|Connection timed out|Network is unreachable|Temporary failure in name resolution' "$out"; then
      echo "PROBLEM: no working internet connection. Check your network, then run the script again."
      rm -f "$out"; return 1
    elif (( ! did_keys )) && grep -qiE 'signature|keyring|PGP|invalid or corrupted package|not trusted' "$out"; then
      did_keys=1
      echo ">> Package signing keys look broken. Repairing them..."
      repair_keyring
    elif (( ! did_sync )) && grep -qiE 'The requested URL returned error: 404|failed retrieving file|target not found|invalid or corrupted database|could not satisfy dependencies' "$out"; then
      did_sync=1
      if (( UPGRADE_OK )); then
        echo ">> The package list looks outdated. Running a full system update (pacman -Syu)..."
        if ! pacman -Syu --noconfirm; then
          echo "PROBLEM: the full system update failed. Fix that first, then run this script again."
          rm -f "$out"; return 1
        fi
      else
        echo "PROBLEM: the package list looks outdated. Run 'sudo pacman -Syu' and then run this script again."
        rm -f "$out"; return 1
      fi
    else
      echo "PROBLEM: pacman could not install: $*  (conflicting files or a broken dependency must be fixed by hand - see above)."
      rm -f "$out"; return 1
    fi
  done
  rm -f "$out"
  return 1
}

pkg_remove() {
  pacman_lock_wait || return 1
  pacman -Rns --noconfirm "$1"
}

ask_upgrade_policy() {
  if ask_yes_no "If your package list is out of date, may I run a full system update (pacman -Syu) first?" Y; then
    UPGRADE_OK=1
  else
    UPGRADE_OK=0
  fi
}

# =============================================================================
# SECTION 9: FIREWALL (ufw)
# =============================================================================
firewalld_in_use() {
  systemctl is-active --quiet firewalld.service 2>/dev/null || systemctl is-enabled --quiet firewalld.service 2>/dev/null
}

decide_firewall() {
  FW_MODE=ufw
  if firewalld_in_use && (( ! FORCE_UFW )); then
    section "Firewall conflict detected"
    info "firewalld is currently active and protecting your system."
    info "This script can either leave firewalld alone or replace it with ufw."
    info "Replacing it will disable firewalld and its rules."
    if (( ASSUME_YES )); then
      FW_MODE=keep
      info "Running with -y: keeping firewalld. Use --force-ufw to replace it."
    elif ask_yes_no "Do you want to replace firewalld with ufw?" N; then
      FW_MODE=ufw
      FORCE_UFW=1
    else
      FW_MODE=keep
      info "Keeping firewalld. The script will skip firewall configuration."
    fi
  fi
}

ufw_is_on() {
  systemctl is-enabled --quiet ufw.service 2>/dev/null || { have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; }
}

sshd_ports() {
  local p=""
  if have sshd; then p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un); fi
  # Socket-activated SSH listens on the socket's ports, not sshd_config's.
  local u l
  for u in sshd.socket ssh.socket; do
    systemctl is-active --quiet "$u" 2>/dev/null || continue
    while IFS= read -r l; do
      l=${l##*:}; l=${l%% *}
      [[ $l =~ ^[0-9]+$ ]] && p+=$'\n'"$l"
    done < <(systemctl show -p Listen --value "$u" 2>/dev/null | tr ' ' '\n' | grep -E '[0-9]+(\(Stream\))?$' | sed 's/(Stream)//')
  done
  p=$(printf '%s\n' "$p" | grep -E '^[0-9]+$' | sort -un)
  [[ -n $p ]] || p=22
  printf '%s\n' "$p"
}
sshd_running() {
  systemctl is-active --quiet sshd.service 2>/dev/null || systemctl is-active --quiet ssh.service 2>/dev/null ||
  systemctl is-active --quiet sshd.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null
}

UFW_FILES=(/etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules)
FIREWALLD_FILES=(/etc/firewalld/firewalld.conf /etc/firewalld/zones/public.xml)

fw_configure_rules() {
  local f p
  for f in "${UFW_FILES[@]}"; do
    [[ -e $f ]] && { track_file "$f" || return 1; }
  done
  if firewalld_in_use && (( FORCE_UFW )); then
    echo "Switching off firewalld (because of --force-ufw)."
    for f in "${FIREWALLD_FILES[@]}"; do
      [[ -e $f ]] && { track_file "$f" || return 1; }
    done
    state_set FIREWALLD_DISABLED_BY_US 1
    systemctl disable --now firewalld.service || return 1
  fi
  ufw default deny incoming || return 1
  ufw default allow outgoing || return 1
  if sshd_running; then
    for p in $(sshd_ports); do
      echo "An SSH server is running: keeping port $p/tcp reachable (rate-limited)."
      ufw limit "${p}/tcp" || return 1
    done
  fi
  return 0
}

fw_turn_on() {
  local f
  if ! kernel_modules_present; then
    echo "The running kernel's modules are missing (a kernel update happened). Reboot, then run this script again."
    return 1
  fi
  ufw --force enable || return 1
  systemctl enable --now ufw.service || return 1
  ufw status 2>/dev/null | grep -q '^Status: active' || { echo "ufw says it is not active."; return 1; }
  for f in "${UFW_FILES[@]}"; do seal_file "$f"; done
  return 0
}

fw_disable() {
  have ufw && { ufw --force disable || true; }
  systemctl disable --now ufw.service 2>/dev/null || true
  return 0
}

fw_undo() {
  if [[ $(state_get ENABLED_UFW_SVC 2>/dev/null) == 1 ]]; then
    have ufw && { ufw --force disable || true; }
    systemctl disable --now ufw.service 2>/dev/null || true
    state_del ENABLED_UFW_SVC
  fi
  if [[ $(state_get FIREWALLD_DISABLED_BY_US 2>/dev/null) == 1 ]]; then
    echo "Re-enabling firewalld, which I had switched off."
    systemctl enable --now firewalld.service || true
    state_del FIREWALLD_DISABLED_BY_US
  fi
  return 0
}

# =============================================================================
# SECTION 10: APPARMOR, PART 1 - KERNEL BOOT SETTING
# =============================================================================
cmdline_trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  while [[ $s == *"  "* ]]; do s="${s//  / }"; done
  printf '%s' "$s"
}

# FIX v3.0.2: removed the redundant second substitution
#   cmd="${cmd/ lsm=$cur/ lsm=$new }"
# that ran unconditionally and produced "...,apparmor,apparmor" when the
# first substitution had already matched.
cmdline_add_lsm() {
  local cmd=" $1 " cur new
  if [[ $cmd =~ [[:space:]]lsm=([^[:space:]]*) ]]; then
    cur="${BASH_REMATCH[1]}"
    if [[ ",$cur," == *",apparmor,"* ]]; then
      : # already present
    elif [[ ",$cur," == *",selinux,"* ]]; then
      return 2
    else
      new="${cur},apparmor"
      cmd="${cmd/ lsm=$cur / lsm=$new }"
      mark_set lsm_appended
    fi
  else
    cmd="${cmd} lsm=${LSM_VALUE} "
  fi
  if ! [[ $cmd =~ [[:space:]]security=([^[:space:]]*) ]]; then
    cmd="${cmd} security=${SECURITY_VALUE} "
  fi
  if ! [[ $cmd =~ [[:space:]]apparmor=([^[:space:]]*) ]]; then
    cmd="${cmd} apparmor=${APPARMOR_BOOTPARAM} "
  fi
  cmdline_trim "$cmd"
}

cmdline_remove_lsm() {
  local cmd=" $1 " cur new mode
  mode=$(state_get KERNEL_PARAM_MODE 2>/dev/null || true)
  cmd="${cmd// lsm=$LSM_VALUE / }"
  cmd="${cmd// security=$SECURITY_VALUE / }"
  cmd="${cmd// apparmor=$APPARMOR_BOOTPARAM / }"
  if [[ $mode == appended && $cmd =~ [[:space:]]lsm=([^[:space:]]*) ]]; then
    cur="${BASH_REMATCH[1]}"
    if [[ $cur == *,apparmor ]]; then
      new="${cur%,apparmor}"
      cmd="${cmd/ lsm=$cur / lsm=$new }"
    fi
  fi
  cmdline_trim "$cmd"
}

# FIX v3.0.2: this function is completely rewritten.
#
# The old version passed the *regex pattern* as the variable name, so when
# the pattern contained escaped brackets like KERNEL_CMDLINE\[default\],
# those backslashes were written into the configuration file verbatim,
# producing an invalid Limine line. It also dropped the leading space for
# "+=" entries, turning "rw quiet" into "rwquiet".
#
# The new version extracts the real left-hand side from the line found in
# the file (${line%%=*} → e.g. KERNEL_CMDLINE[default]+), so:
#   - no backslashes ever leak into the output,
#   - the original operator (= or +=) is preserved,
#   - for += entries a leading space is re-added to the value,
#   - for new lines (no $line) a clean, unescaped $var is used.
patch_quoted_var() {
  local f=$1 var=$2 mode=$3 need=${4:-0} line val q='"' new rc op lhs=''
  [[ -f $f ]] || { echo "File not found: $f"; return 1; }

  # Find the line with = or += and the actual variable name (unescaped).
  line=$(grep -E "^[[:space:]]*${var}\+?=" "$f" | tail -n1)

  if [[ -n $line ]]; then
    # Extract the real left-hand side from the file, e.g.:
    #   KERNEL_CMDLINE[default]+   (with the +)
    # or KERNEL_CMDLINE[default]
    lhs=${line%%=*}
    lhs="${lhs#"${lhs%%[![:space:]]*}"}"   # ltrim
    lhs="${lhs%"${lhs##*[![:space:]]}"}"   # rtrim
    if [[ $lhs == *+ ]]; then op="+="; else op="="; fi
    # Strip the trailing + so we can rebuild the line cleanly.
    lhs=${lhs%+}
    lhs="${lhs%"${lhs##*[![:space:]]}"}"

    # Pull the current value out of the quotes.
    val=${line#*=}
    case ${val:0:1} in
      '"'|"'") q=${val:0:1}; val=${val:1}; val=${val%"$q"*} ;;
    esac
    val=$(cmdline_trim "$val")
  else
    [[ $mode == remove ]] && return 0
    if (( need )); then echo "No active $var line in $f - skipping this file."; return 0; fi
    # New line: build the LHS from $var, stripping any backslashes that the
    # caller may have used to make the grep pattern safe.
    lhs="${var//\\/}"
    op="="
    val=""
  fi

  if [[ $mode == add ]]; then new=$(cmdline_add_lsm "$val"); rc=$?; else new=$(cmdline_remove_lsm "$val"); rc=$?; fi
  if (( rc == 2 )); then echo "SELinux is configured in $f. AppArmor and SELinux cannot be mixed; I did not change anything."; return 3; fi
  if [[ $new == "$val" ]]; then echo "${lhs:-$var} in $f is already up to date."; return 0; fi

  # For += entries, ensure a leading space so "rw quiet" does not become
  # "rwquiet". For plain = entries, use the value as-is.
  if [[ $op == "+=" ]]; then
    new=" ${new# }"
  fi

  track_file "$f" || return 1
  file_set_line "$f" "^[[:space:]]*${var}\+?=" "${lhs}${op}${q}${new}${q}" || return 1
  seal_file "$f"
  mark_set bl_changed
  echo "Updated ${lhs:-$var} in $f"
  return 0
}

patch_oneline_file() {
  local f=$1 mode=$2 val new rc
  val=$(cmdline_trim "$(tr '\n' ' ' <"$f")")
  if [[ -z $val ]]; then echo "$f is empty - leaving it alone."; return 0; fi
  if [[ $mode == add ]]; then new=$(cmdline_add_lsm "$val"); rc=$?; else new=$(cmdline_remove_lsm "$val"); rc=$?; fi
  if (( rc == 2 )); then echo "SELinux is configured in $f; not changed."; return 3; fi
  [[ $new == "$val" ]] && { echo "$f is already up to date."; return 0; }
  track_file "$f" || return 1
  printf '%s\n' "$new" >"$f" || return 1
  seal_file "$f"
  mark_set bl_changed
  echo "Updated $f"
  return 0
}

# --- GRUB ---
bl_grub() { patch_quoted_var "$GRUB_DEFAULT_FILE" GRUB_CMDLINE_LINUX_DEFAULT "$1"; }

# --- systemd-boot ---
sdboot_entry_files() {
  local d p f
  local -A seen=()
  local dirs=()
  if have bootctl; then
    p=$(bootctl --print-esp-path 2>/dev/null) && dirs+=("${p%/}")
    p=$(bootctl --print-boot-path 2>/dev/null) && dirs+=("${p%/}")
  fi
  dirs+=(/boot /efi /boot/efi)
  for d in "${dirs[@]}"; do
    for f in "$d"/loader/entries/*.conf; do
      [[ -f $f ]] || continue
      [[ -n ${seen[$f]:-} ]] && continue
      seen[$f]=1
      printf '%s\n' "$f"
    done
  done
}

sdboot_uses_uki() {
  if grep -qsE '^[a-z0-9_]*_uki=' /etc/mkinitcpio.d/*.preset 2>/dev/null; then
    return 0
  fi
  if grep -qsE '^[[:space:]]*uki' /etc/kernel/install.conf 2>/dev/null; then
    return 0
  fi
  if [[ -f $UKI_CONF ]]; then
    return 0
  fi
  return 1
}

sdboot_cmdline_sources() {
  local f
  if [[ -f $KERNEL_CMDLINE_FILE ]]; then
    printf '%s\n' "$KERNEL_CMDLINE_FILE"
  fi
  if [[ -d $CMDLINE_D ]]; then
    for f in "$CMDLINE_D"/*.conf; do
      [[ -f $f ]] && printf '%s\n' "$f"
    done
  fi
}

bl_sdboot() {
  local mode=$1 f line val new rc found=0 persistent=0

  # PERSISTENT SOURCES FIRST: these survive kernel updates / mkinitcpio runs.
  while IFS= read -r f; do
    found=1; persistent=1
    patch_oneline_file "$f" "$mode" || return $?
  done < <(sdboot_cmdline_sources)
  if [[ -f $SDBOOT_MANAGE_CONF ]]; then
    found=1; persistent=1
    patch_quoted_var "$SDBOOT_MANAGE_CONF" LINUX_OPTIONS "$mode" 1 || return $?
  fi

  if sdboot_uses_uki; then
    if (( ! persistent )); then
      echo "No systemd-boot UKI cmdline source found (looked for $KERNEL_CMDLINE_FILE and $CMDLINE_D/*.conf)."
      return 1
    fi
    return 0
  fi

  # NON-UKI: also edit the live entry files so the change takes effect now.
  while IFS= read -r f; do
    grep -qE '^options[[:space:]]' "$f" || continue
    found=1
    line=$(grep -E '^options[[:space:]]' "$f" | tail -n1)
    val=$(cmdline_trim "${line#options}")
    if [[ $mode == add ]]; then new=$(cmdline_add_lsm "$val"); rc=$?; else new=$(cmdline_remove_lsm "$val"); rc=$?; fi
    if (( rc == 2 )); then echo "SELinux is configured in $f; not changed."; return 3; fi
    [[ $new == "$val" ]] && continue
    track_file "$f" || return 1
    file_set_line "$f" '^options[[:space:]]' "options  $new" || return 1
    seal_file "$f"
    mark_set bl_changed
    echo "Updated $f"
  done < <(sdboot_entry_files)

  if (( ! found )); then echo "No systemd-boot configuration found."; return 1; fi
  return 0
}

# --- Limine ---
# FIX v3.0.2: simplified — relies entirely on the rewritten
# patch_quoted_var, which now correctly handles both = and += entries
# and preserves the leading space for +=.
bl_limine() {
  local mode=$1 f found=0 entry
  local candidates=()
  [[ -f $LIMINE_DEFAULT_FILE ]] && candidates+=("$LIMINE_DEFAULT_FILE")
  [[ -f $LIMINE_ENTRY_TOOL_CONF ]] && candidates+=("$LIMINE_ENTRY_TOOL_CONF")
  # Omarchy 4 keeps the cmdline in drop-ins. Use them only when the main files
  # hold no KERNEL_CMDLINE line, and then only the last one (it is read last),
  # so the setting is never added twice.
  if ! grep -qsE '^[[:space:]]*KERNEL_CMDLINE' "${candidates[@]}" /dev/null && [[ -d $LIMINE_DROPIN_DIR ]]; then
    local d last=""
    for d in "$LIMINE_DROPIN_DIR"/*.conf; do
      [[ -f $d ]] && grep -qsE '^[[:space:]]*KERNEL_CMDLINE' "$d" && last=$d
    done
    [[ -n $last ]] && candidates+=("$last")
  fi

  if (( ${#candidates[@]} == 0 )); then
    echo "Could not find Limine configuration ($LIMINE_DEFAULT_FILE or $LIMINE_ENTRY_TOOL_CONF)."
    return 1
  fi

  for f in "${candidates[@]}"; do
    found=1
    # Per-kernel entries (e.g., KERNEL_CMDLINE["linux-cachyos"]) with = or +=.
    while IFS= read -r entry; do
      [[ -n $entry ]] || continue
      patch_quoted_var "$f" "KERNEL_CMDLINE\[\"${entry}\"\]" "$mode" || return $?
    done < <(grep -oE '^[[:space:]]*KERNEL_CMDLINE\["[^"]+"\]' "$f" 2>/dev/null | sed -E 's/.*\["([^"]+)"\].*/\1/' | sort -u)

    # [default] entry, with = or +=
    if grep -qsE '^[[:space:]]*KERNEL_CMDLINE\[default\]\+?=' "$f"; then
      patch_quoted_var "$f" 'KERNEL_CMDLINE\[default\]' "$mode" || return $?
    fi

    # Bare KERNEL_CMDLINE, with = or +=
    if grep -qsE '^[[:space:]]*KERNEL_CMDLINE\+?=' "$f"; then
      patch_quoted_var "$f" 'KERNEL_CMDLINE' "$mode" || return $?
    fi
  done

  (( found )) || { echo "No Limine cmdline variables found in configuration files."; return 1; }
  return 0
}

limine_conf_candidates() {
  local c
  for c in /boot/limine.conf /boot/limine/limine.conf /boot/EFI/limine/limine.conf /efi/limine.conf /boot/efi/limine.conf /boot/efi/EFI/limine/limine.conf; do
    [[ -f $c ]] && printf '%s\n' "$c"
  done
  return 0
}

# --- common part ---
bootloader_regen() {
  local c
  case $BOOTLOADER in
    grub)
      have grub-mkconfig || { echo "grub-mkconfig was not found."; return 1; }
      track_file "$GRUB_CFG_FILE" generated || return 1
      grub-mkconfig -o "$GRUB_CFG_FILE" || return 1
      seal_file "$GRUB_CFG_FILE" ;;
    systemd-boot)
      if sdboot_uses_uki && have mkinitcpio; then mkinitcpio -P || return 1; fi
      if [[ -f $SDBOOT_MANAGE_CONF ]] && have sdboot-manage; then sdboot-manage gen || return 1; fi ;;
    limine)
      while IFS= read -r c; do track_file "$c" generated || return 1; done < <(limine_conf_candidates)
      if have limine-update; then limine-update || return 1
      elif have limine-mkinitcpio; then limine-mkinitcpio || return 1
      else echo "Neither limine-update nor limine-mkinitcpio was found; please run your Limine update command by hand."; return 1; fi
      while IFS= read -r c; do seal_file "$c"; done < <(limine_conf_candidates) ;;
  esac
  return 0
}

tracked_files_sane() {
  local line kind path bad=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    IFS='|' read -r kind path _ _ <<<"$line"
    [[ -s $path ]] || { echo "File is empty or missing after the edit: $path"; bad=1; }
  done < <(manifest_cat)
  return "$bad"
}

# FIX v3.0.2: skip systemd-boot entries that have no 'linux' line.
# memtest86+ and similar EFI-application entries legitimately have no
# kernel command line; the old code flagged them as CHECK FAILED.
bootloader_sanity() {
  local c found=0 missing=0 skipped=0
  case $BOOTLOADER in
    grub)
      if ! { [[ -s $GRUB_CFG_FILE ]] && grep -q 'menuentry' "$GRUB_CFG_FILE"; }; then echo "CHECK FAILED: $GRUB_CFG_FILE looks empty or damaged."; return 1; fi
      grep -Eq 'lsm=[^[:space:]]*apparmor' "$GRUB_CFG_FILE" || { echo "CHECK FAILED: the new setting did not reach $GRUB_CFG_FILE."; return 1; } ;;
    systemd-boot)
      if sdboot_uses_uki; then
        while IFS= read -r c; do
          found=1
          grep -Eq 'lsm=[^[:space:]]*apparmor' "$c" || missing=1
        done < <(sdboot_cmdline_sources)
        if (( found && missing )); then echo "CHECK FAILED: the new setting did not reach the UKI cmdline sources."; return 1; fi
        (( found )) || echo "Note: could not locate UKI cmdline sources to double-check."
      else
        while IFS= read -r c; do
          # Skip entries that have no 'linux' line (memtest86+, EFI shell, …).
          if ! grep -qE '^[[:space:]]*linux[[:space:]]' "$c"; then
            skipped=$(( skipped + 1 ))
            continue
          fi
          found=1
          grep -Eq 'lsm=[^[:space:]]*apparmor' "$c" || missing=1
        done < <(sdboot_entry_files)
        if (( found && missing )); then echo "CHECK FAILED: the new setting did not reach the systemd-boot entries."; return 1; fi
        if (( ! found && skipped )); then
          echo "Note: only non-kernel systemd-boot entries found ($skipped skipped); nothing to check."
        elif (( ! found )); then
          echo "Note: could not locate systemd-boot entries to double-check."
        fi
      fi ;;
    limine)
      while IFS= read -r c; do
        found=1
        grep -Eq 'lsm=[^[:space:]]*apparmor' "$c" || missing=1
      done < <(limine_conf_candidates)
      if (( found && missing )); then echo "CHECK FAILED: the new setting did not reach the Limine menu."; return 1; fi
      (( found )) || echo "Note: could not locate limine.conf to double-check it." ;;
  esac
  tracked_files_sane
}

print_manual_kernel_param() {
  cat <<EOF
Please add this to your kernel command line by hand:
    lsm=${LSM_VALUE} security=${SECURITY_VALUE} apparmor=${APPARMOR_BOOTPARAM}
  GRUB          edit GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then:
                sudo grub-mkconfig -o /boot/grub/grub.cfg
  systemd-boot  add it to the 'options' line of /boot/loader/entries/*.conf
                (or to /etc/kernel/cmdline and /etc/cmdline.d/*.conf for UKI)
  Limine        add  KERNEL_CMDLINE[default]+=" lsm=${LSM_VALUE} security=${SECURITY_VALUE} apparmor=${APPARMOR_BOOTPARAM}"  to
                /etc/default/limine, then run: sudo limine-update
EOF
}

bootloader_apply() {
  local mode=$1 rc=0
  mark_clear bl_changed
  case $BOOTLOADER in
    grub)          bl_grub "$mode";   rc=$? ;;
    systemd-boot)  bl_sdboot "$mode"; rc=$? ;;
    limine)        bl_limine "$mode"; rc=$? ;;
    *)             echo "Unknown boot loader."; print_manual_kernel_param; return 1 ;;
  esac
  (( rc == 0 )) || return "$rc"
  if mark_has bl_changed; then
    bootloader_regen || { echo "The boot menu could not be refreshed."; return 1; }
    if [[ $mode == add ]]; then bootloader_sanity || return 1; fi
  fi
  return 0
}

# =============================================================================
# SECTION 11: APPARMOR, PART 2 - SERVICE AND AI-AGENT SWITCH
# =============================================================================
aa_supported() {
  (( AA_KERNEL_SUPPORTED )) && return 0
  [[ -d /sys/module/apparmor ]] && return 0
  [[ -r /proc/config.gz ]] && zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_SECURITY_APPARMOR=y' && return 0
  [[ -d $APPARMOR_SYSFS ]]
}

aa_active() { grep -qw apparmor "$LSM_SYSFS" 2>/dev/null && [[ -d $APPARMOR_SYSFS ]]; }

aa_service_enabled() { systemctl is-enabled --quiet apparmor.service 2>/dev/null; }

aa_service_enable() {
  systemctl enable apparmor.service || return 1
  if aa_active; then systemctl restart apparmor.service || return 1; fi
  return 0
}

aa_disable() {
  systemctl disable --now apparmor.service 2>/dev/null || true
  have aa-teardown && { aa-teardown || true; }
  return 0
}

# FIX v3.0.2: no longer forces every profile into enforce mode.
# --disable and --rollback should stop the service; they should NOT change
# the mode of any profile. The old aa_set_mode blocked line is gone.
aa_undo() {
  if [[ $(state_get ENABLED_APPARMOR_SVC 2>/dev/null) == 1 ]]; then
    aa_disable
    state_del ENABLED_APPARMOR_SVC
  fi
  return 0
}

aa_set_mode() {
  local mode=$1 files=()
  have aa-complain && have aa-enforce || { echo "The AppArmor tools (aa-complain / aa-enforce) are missing."; return 1; }
  mapfile -t files < <(
    find "$APPARMOR_DIR" -maxdepth 1 -type f ! -name '.*' ! -name '*.pacnew' ! -name '*.pacsave' ! -name '*.pacorig' ! -name '*~' -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
      if grep -qE '^\s*profile\s' "$f" 2>/dev/null; then
        printf '%s\n' "$(basename "$f")"
      fi
    done
  )
  if (( ${#files[@]} == 0 )); then echo "No actual profiles in $APPARMOR_DIR yet - nothing to switch."; return 0; fi
  if [[ $mode == allowed ]]; then aa-complain "${files[@]}"; else aa-enforce "${files[@]}"; fi
}

resolve_ai_mode() {
  [[ -n $AI_MODE ]] && return 0
  AI_MODE=$(state_get AI_AGENT 2>/dev/null || true)
  [[ $AI_MODE == allowed || $AI_MODE == blocked ]] || AI_MODE=allowed
}

# =============================================================================
# SECTION 12: KERNEL HARDENING (sysctl)
# =============================================================================
sysctl_apply() {
  local sd
  track_file "$SYSCTL_FILE" || return 1
  cat >"$SYSCTL_FILE" <<'EOF'
# Written by enable-security-for-arch-linux.sh  - safe to delete (or run the script with --disable).

kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
  chmod 644 "$SYSCTL_FILE" || return 1
  seal_file "$SYSCTL_FILE"
  sd=$(command -v systemd-sysctl || true)
  [[ -n $sd ]] || sd=/usr/lib/systemd/systemd-sysctl
  "$sd" "$SYSCTL_FILE"
}

# =============================================================================
# SECTION 13: UNDO LOGIC
# =============================================================================
restore_entry() {
  local line=$1 force=$2 kind path backup sha cur
  IFS='|' read -r kind path backup sha <<<"$line"
  case $kind in
    created)
      rm -f -- "$path" && echo "Removed the file I had created: $path"
      manifest_drop "$path"
      return 0 ;;
    edited|generated)
      if [[ ! -f $backup ]]; then echo "The backup is missing: $backup (cannot restore $path)"; return 1; fi
      cur=$(file_sha "$path")
      if [[ $force == 1 || $sha == "-" || -z $cur || $cur == "$sha" ]]; then
        if mv -f -- "$backup" "$path"; then
          echo "Restored the original: $path"
          manifest_drop "$path"
          return 0
        fi
        return 1
      fi
      echo "Left as it is (it was changed after my edit): $path   [original copy kept as $backup]"
      return 2 ;;
  esac
  return 0
}

is_boot_path() {
  case $1 in
    "$GRUB_DEFAULT_FILE"|"$KERNEL_CMDLINE_FILE"|"$LIMINE_DEFAULT_FILE"|"$LIMINE_ENTRY_TOOL_CONF"|"$LIMINE_DROPIN_DIR"/*.conf|"$SDBOOT_MANAGE_CONF"|"$UKI_CONF"|*/loader/entries/*.conf|"$CMDLINE_D"/*.conf) return 0 ;;
  esac
  return 1
}

undo_files() {
  local force=0 line kind path backup rc errors=0 boot_touched=0 boot_left=0 pass
  local lines=()
  [[ ${1:-safe} == force ]] && force=1
  if ! manifest_nonempty; then echo "No tracked files - nothing to restore."; return 0; fi
  mapfile -t lines < <(manifest_cat)
  # FIX v3.0.1: suppress track_file during the post-restore regen step.
  IN_ROLLBACK=1
  for pass in generated other; do
    for line in "${lines[@]}"; do
      [[ -n $line ]] || continue
      IFS='|' read -r kind path backup _ <<<"$line"
      if [[ $pass == generated && $kind != generated ]]; then continue; fi
      if [[ $pass == other && $kind == generated ]]; then continue; fi
      restore_entry "$line" "$force"; rc=$?
      is_boot_path "$path" && boot_touched=1
      case $rc in
        1) errors=$(( errors + 1 )) ;;
        2) if [[ $kind == generated ]]; then rm -f -- "$backup"; manifest_drop "$path"
           else is_boot_path "$path" && boot_left=1; fi ;;
      esac
    done
  done
  if (( boot_touched && ! boot_left )); then
    bootloader_regen || echo "Note: the boot menu could not be refreshed automatically; please run your boot loader update command."
  fi
  IN_ROLLBACK=0
  # Clean up any remaining backups for generated files
  while IFS='|' read -r kind path backup _; do
    [[ $kind == generated && -n $backup && -f $backup ]] && rm -f -- "$backup"
  done < <(manifest_cat)
  (( errors == 0 ))
}

rollback_changes() {
  local mode=${1:-safe}
  fw_undo
  aa_undo
  undo_files "$mode" || return 1
  state_del KERNEL_PARAM_ADDED; state_del KERNEL_PARAM_MODE; state_del KERNEL_PARAM_BOOTLOADER
  return 0
}

offer_rollback() {
  local def=$1 why=$2
  manifest_nonempty || return 0
  printf '\n'
  box_top "$C_YELLOW"
  box_row "$C_YELLOW" "${C_BOLD}${C_YELLOW}${SYM_WARN}  Sorry - something did not go as planned${C_RESET}"
  box_sep "$C_YELLOW"
  box_text "$C_YELLOW" "" "$why"
  box_text "$C_YELLOW" "" "Before editing, I saved a copy of every file I touched."
  box_text "$C_YELLOW" "" "If you answer Y, I will delete my edited versions and put the .backup copies back."
  box_bot "$C_YELLOW"
  if ask_yes_no "Do you want me to undo my changes now?" "$def"; then
    run_rollback force
  else
    info "Okay. Your backups stay next to the original files (named *.backup)."
    info "To undo later, run:  sudo ./${SCRIPT_FILE} --rollback"
  fi
}

run_rollback() {
  local mode=$1 ok=1
  STEP_N=0; STEP_TOTAL=2
  section "Going back to how things were"
  run_step "Switching off what I turned on" bash -c 'true' >/dev/null 2>&1
  STEP_N=0
  if run_step "Restoring your original files from the .backup copies" rollback_changes "$mode"; then ok=1; else ok=0; fi
  STEP_N=1
  step_final ok "Switching off what I turned on" "(done together with the step below)"
  printf '\n'
  if (( ok )); then
    box_top "$C_GREEN"
    box_row "$C_GREEN" "${C_BOLD}${C_GREEN}${SYM_OK}  Everything was put back the way it was${C_RESET}"
    box_sep "$C_GREEN"
    box_text "$C_GREEN" "" "The edited files are gone and your original files are back."
    box_bot "$C_GREEN"
  else
    box_top "$C_RED"
    box_row "$C_RED" "${C_BOLD}${C_RED}${SYM_FAIL}  The undo was only partly possible${C_RESET}"
    box_sep "$C_RED"
    box_text "$C_RED" "" "Some files could not be restored automatically. Look for files named *.backup next to the originals."
    box_bot "$C_RED"
  fi
}

# =============================================================================
# SECTION 14: THE ACTIONS
# =============================================================================
show_enable_plan() {
  section "What I am about to do"
  if [[ $FW_MODE == keep ]]; then
    info "Firewall: firewalld is already protecting this PC, so I keep it."
  else
    info "Firewall: install ufw, block unrequested incoming connections, allow outgoing."
  fi
  if (( AA_KERNEL_SUPPORTED )); then
    info "AppArmor: install it and switch it on at boot (one reboot needed)."
    if [[ $DISTRO_KEY == omarchy ]]; then
      info "Omarchy detected: profiles will start in 'complain' (log-only) mode for safety."
    fi
  else
    warn "AppArmor: SKIPPED — this kernel was built without AppArmor."
    warn "Firewall and kernel hardening will still be applied."
  fi
  info "Kernel hardening: apply safe network and kernel settings."
  if (( ! AA_KERNEL_SUPPORTED )); then
    :
  elif [[ $AI_MODE == allowed ]]; then
    warn "AppArmor profiles: COMPLAIN mode (log only). Unprofiled programs are unaffected."
  else
    info "AppArmor profiles: ENFORCE mode (most secure)."
  fi
  if (( ! AA_KERNEL_SUPPORTED )); then
    :
  elif pkg_installed apparmor.d || [[ $(state_get INSTALLED_APPARMOR_D 2>/dev/null) == 1 ]]; then
    info "apparmor.d is installed; it ships with all profiles in COMPLAIN mode by default."
    info "This means AppArmor will only log violations, not block them, until you enforce manually."
  else
    info "On pure Arch, only the stock AppArmor profiles are installed."
    info "For full coverage, install apparmor.d-git from the AUR after setup."
  fi
  info "Backups: before editing a file I save a copy next to it, named <file>.backup."
  info "Everything is permanent and survives a reboot."
}

do_enable() {
  STEP_TOTAL=10
  local fw_ok=1 aa_ok=1 kp_ok=1 sys_ok=1 prev

  decide_firewall
  resolve_ai_mode
  show_enable_plan
  ask_yes_no "Continue?" Y || { info "Okay, nothing was changed."; exit 0; }
  ask_upgrade_policy
  section "Setting up your security system"

  # Step 1
  if ! run_step "Checking the package manager" pm_prepare; then
    finish_failed "The package manager is not ready" "pacman is locked, the disk is nearly full, or something else blocks installing packages."
    exit 1
  fi

  # Steps 2-4: firewall
  if [[ $FW_MODE == keep ]]; then
    skip_step "Installing the firewall (ufw)" "firewalld is already active"
    skip_step "Setting the firewall rules" "firewalld keeps its own rules"
    skip_step "Turning the firewall on" "firewalld is already on"
    FW_STATUS=kept
  else
    if pkg_installed ufw; then state_set_default INSTALLED_UFW 0; else state_set INSTALLED_UFW 1; fi
    run_step "Installing the firewall (ufw)" pkg_install ufw || fw_ok=0
    if (( fw_ok )); then
      run_step "Setting the firewall rules (block incoming, allow outgoing)" fw_configure_rules || fw_ok=0
    else
      skip_step "Setting the firewall rules" "ufw is not installed"
    fi
    if (( fw_ok )); then
      ufw_is_on || state_set ENABLED_UFW_SVC 1
      run_step "Turning the firewall on, also after every reboot" fw_turn_on || fw_ok=0
    else
      skip_step "Turning the firewall on" "earlier firewall step failed"
    fi
    if (( fw_ok )); then FW_STATUS=ok; else FW_STATUS=fail; fi
  fi

  # Steps 5-8: AppArmor
  if (( ! AA_KERNEL_SUPPORTED )) || ! aa_supported; then
    skip_step "Installing AppArmor" "this kernel has no AppArmor (compiled out)"
    skip_step "Installing AppArmor profiles (apparmor.d)" "this kernel has no AppArmor"
    skip_step "Enabling AppArmor in the boot settings" "this kernel has no AppArmor"
    skip_step "Turning AppArmor on, also after every reboot" "this kernel has no AppArmor"
    AA_STATUS=unsupported
    add_note "Your kernel was built without AppArmor. Use the standard 'linux' or 'linux-lts' kernel to get AppArmor."
  else
    if pkg_installed apparmor; then state_set_default INSTALLED_APPARMOR 0; else state_set INSTALLED_APPARMOR 1; fi
    run_step "Installing AppArmor" pkg_install apparmor || aa_ok=0

    if (( aa_ok )); then
      if pkg_installed apparmor.d; then
        skip_step "Installing AppArmor profiles (apparmor.d)" "already installed"
      elif pacman -Si apparmor.d >/dev/null 2>&1; then
        state_set INSTALLED_APPARMOR_D 1
        run_step "Installing AppArmor profiles (apparmor.d)" pkg_install apparmor.d || add_note "apparmor.d could not be installed; AppArmor will have very few profiles."
      else
        AUR_HELPER=$(detect_aur_helper)
        skip_step "Installing AppArmor profiles (apparmor.d)" "not in official repo"
        if [[ -n $AUR_HELPER ]]; then
          add_note "For full AppArmor protection, install 'apparmor.d-git' from the AUR:  ${AUR_HELPER} -S apparmor.d-git  (then reboot)."
        else
          add_note "For full AppArmor protection, install 'apparmor.d-git' from the AUR. First install an AUR helper like 'yay' or 'paru'."
        fi
      fi
    else
      skip_step "Installing AppArmor profiles (apparmor.d)" "the AppArmor package is missing"
    fi

    if (( ! aa_ok )); then
      skip_step "Enabling AppArmor in the boot settings" "the AppArmor package is missing"; kp_ok=0
    elif aa_active; then
      skip_step "Enabling AppArmor in the boot settings" "already active in the running kernel"
    elif run_step "Enabling AppArmor in the boot settings (backup first)" bootloader_apply add; then
      if (( ! DRY_RUN )) && mark_has bl_changed; then
        state_set KERNEL_PARAM_ADDED 1
        state_set KERNEL_PARAM_BOOTLOADER "$BOOTLOADER"
        if mark_has lsm_appended; then state_set KERNEL_PARAM_MODE appended; else state_set KERNEL_PARAM_MODE added; fi
      fi
    else
      kp_ok=0
      # Only a boot file that was actually changed can leave the boot broken
      # (a refusal such as SELinux changes nothing and needs no rollback).
      mark_has bl_changed && BOOT_BROKEN=1
    fi

    if (( aa_ok && kp_ok )); then
      aa_service_enabled || state_set ENABLED_APPARMOR_SVC 1
      run_step "Turning AppArmor on, also after every reboot" aa_service_enable || aa_ok=0
    else
      skip_step "Turning AppArmor on, also after every reboot" "an earlier AppArmor step failed"
    fi

    prev=$(state_get AI_AGENT 2>/dev/null || echo allowed)
    if (( ! aa_ok || ! kp_ok )); then
      skip_step "Applying the AppArmor profile mode" "AppArmor is not set up"
    elif ! aa_active; then
      skip_step "Applying the AppArmor profile mode" "saved; applies once AppArmor runs after the reboot"
      if [[ $AI_MODE == allowed ]]; then
        state_set AI_AGENT_PENDING 1
        add_note "After the reboot, run './${SCRIPT_FILE}' once more to put the AppArmor profiles in complain (log-only) mode."
      fi
    elif [[ $AI_MODE == allowed && ( $prev != allowed || $(state_get AI_AGENT_PENDING 2>/dev/null) == 1 ) ]]; then
      if run_step "Applying the AppArmor profile mode (${AI_MODE})" aa_set_mode "$AI_MODE"; then
        state_del AI_AGENT_PENDING
      else
        add_note "The AppArmor profile mode could not be applied to all profiles."
      fi
    else
      skip_step "Applying the AppArmor profile mode" "already in the desired mode"
    fi
    state_set AI_AGENT "$AI_MODE"

    if (( aa_ok && kp_ok )); then AA_STATUS=ok; else AA_STATUS=fail; fi
    if [[ $AA_STATUS == ok ]] && ! aa_active; then NEED_REBOOT=1; AA_STATUS=pending; fi
  fi

  # Step 9: kernel hardening
  run_step "Applying safe kernel hardening settings" sysctl_apply || sys_ok=0
  if (( sys_ok )); then SYS_STATUS=ok; else SYS_STATUS=fail; fi

  # Step 10: verify
  fg_step "Double-checking everything" verify_all

  state_set ENABLED 1
  finish_enable
}

detect_aur_helper() {
  local h
  for h in yay paru trizen pikaur aura aura-bin; do
    if have "$h"; then
      echo "$h"
      return 0
    fi
  done
  return 1
}

verify_all() {
  local rc=0
  if [[ $FW_STATUS == ok ]]; then
    ufw status 2>/dev/null | grep -q '^Status: active' || { echo "ufw is not active."; FW_STATUS=fail; rc=1; }
    systemctl is-enabled --quiet ufw.service 2>/dev/null || { echo "ufw will not start at boot."; FW_STATUS=fail; rc=1; }
  fi
  if [[ $AA_STATUS == ok || $AA_STATUS == pending ]]; then
    aa_service_enabled || { echo "apparmor.service will not start at boot."; AA_STATUS=fail; rc=1; }
  fi
  if [[ $SYS_STATUS == ok && ! -s $SYSCTL_FILE ]]; then echo "The sysctl file is missing."; SYS_STATUS=fail; rc=1; fi
  tracked_files_sane || { BOOT_BROKEN=1; rc=1; }
  return "$rc"
}

do_disable() {
  STEP_TOTAL=4
  section "Turning the security system off (nothing is uninstalled)"
  if pkg_installed ufw; then run_step "Turning the firewall off" fw_disable
  else skip_step "Turning the firewall off" "ufw is not installed"; fi
  if pkg_installed apparmor; then run_step "Turning AppArmor off" aa_disable
  else skip_step "Turning AppArmor off" "AppArmor is not installed"; fi
  if [[ -e $SYSCTL_FILE ]]; then run_step "Removing the kernel hardening file" restore_sysctl
  else skip_step "Removing the kernel hardening file" "it is not there"; fi
  state_set ENABLED 0
  step_final ok "Done - turn everything back on any time with: ./${SCRIPT_FILE}"; STEP_N=$(( STEP_N + 1 ))
  finish_simple "Security system turned OFF" "The firewall and AppArmor are switched off. Nothing was uninstalled."
}

restore_sysctl() {
  local line
  if line=$(manifest_find "$SYSCTL_FILE"); then restore_entry "$line" 1
  else rm -f "$SYSCTL_FILE"; fi
}

do_uninstall() {
  STEP_TOTAL=8
  local inst
  section "Uninstall"
  info "This will turn off the security system, put your ORIGINAL files back from their .backup copies, and remove the packages this script installed."
  ask_yes_no "Do you really want to uninstall?" N || { info "Okay, nothing was changed."; exit 0; }
  section "Removing the security system"

  run_step "Turning off the firewall I enabled" fw_undo
  run_step "Turning off AppArmor, which I enabled" aa_undo
  if [[ -n $(state_get KERNEL_PARAM_BOOTLOADER 2>/dev/null) ]]; then BOOTLOADER=$(state_get KERNEL_PARAM_BOOTLOADER); fi
  run_step "Putting your original files back (from the .backup copies)" undo_files safe

  inst=$(state_get INSTALLED_APPARMOR_D 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed apparmor.d; then
    run_step "Removing the apparmor.d package I installed" pkg_remove apparmor.d
  else
    skip_step "Removing the apparmor.d package" "it was on your system before, or not installed"
  fi

  inst=$(state_get INSTALLED_UFW 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed ufw; then run_step "Removing the ufw package I installed" pkg_remove ufw
  else skip_step "Removing the ufw package" "it was on your system before, or not installed"; fi
  inst=$(state_get INSTALLED_APPARMOR 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed apparmor; then run_step "Removing the AppArmor package I installed" pkg_remove apparmor
  else skip_step "Removing the AppArmor package" "it was on your system before, or not installed"; fi

  run_step "Cleaning up my notes" cleanup_state
  NEED_REBOOT=1
  finish_simple "Security system UNINSTALLED" "Your original files are back, and what I installed is removed. Please reboot."
}

cleanup_state() {
  rm -f "$STATE_FILE"
  [[ -s $MANIFEST_FILE ]] || rm -f "$MANIFEST_FILE"
  rmdir "$STATE_DIR" 2>/dev/null || true
  return 0
}

do_rollback() {
  if ! manifest_nonempty; then
    info "There is nothing to undo: I have no record of edited files."
    exit 0
  fi
  section "Rollback"
  info "I will restore the original files from their .backup copies, delete files I created, and switch off what I enabled."
  ask_yes_no "Go ahead?" N || { info "Okay, nothing was changed."; exit 0; }
  run_rollback safe
}

do_ai() {
  STEP_TOTAL=2
  section "AppArmor profile mode: ${AI_MODE}"
  if [[ $AI_MODE == allowed ]]; then
    warn "Complain mode: AppArmor will only LOG violations, not block them."
    warn "This only affects programs that HAVE an AppArmor profile. Unprofiled programs are unaffected."
  else
    info "Enforce mode: AppArmor blocks policy violations (most secure)."
  fi
  if ! pkg_installed apparmor; then
    state_set AI_AGENT "$AI_MODE"
    step_final warn "AppArmor is not installed yet" "(setting saved; run ./${SCRIPT_FILE} to install)"
    return 0
  fi
  fg_step "Saving the setting" state_set AI_AGENT "$AI_MODE"
  if aa_active; then
    run_step "Switching the AppArmor profiles" aa_set_mode "$AI_MODE"
  else
    skip_step "Switching the AppArmor profiles" "AppArmor is not running yet; reboot, then run this again"
  fi
  if (( STEP_FAILS )); then finish_simple_fail "The profile mode could not be applied" "See ${LOG_FILE}."
  else finish_simple "AppArmor profile mode is now: ${AI_MODE}" "$([[ $AI_MODE == allowed ]] && echo 'AppArmor only logs. The firewall is unchanged.' || echo 'AppArmor is blocking again (most secure).')"; fi
}

status_row() {
  local sym col
  case $2 in
    ok)   sym=$SYM_OK;   col=$C_GREEN ;;
    warn) sym=$SYM_WARN; col=$C_YELLOW ;;
    fail) sym=$SYM_FAIL; col=$C_RED ;;
    *)    sym=$SYM_SKIP; col=$C_DIM ;;
  esac
  printf '  %s%s%s  %-18s %s\n' "$col" "$sym" "$C_RESET" "$1" "$3"
}

do_status() {
  local e c f
  section "Security status"
  status_row "System" ok "${DISTRO_LABEL} (boot loader: ${BOOTLOADER})"
  if firewalld_in_use && ! ufw_is_on; then
    status_row "Firewall" ok "firewalld is active"
  elif pkg_installed ufw; then
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
      if systemctl is-enabled --quiet ufw.service 2>/dev/null; then status_row "Firewall (ufw)" ok "active now and at every boot"
      else status_row "Firewall (ufw)" warn "active now, but will NOT start at boot"; fi
    else status_row "Firewall (ufw)" fail "installed but OFF"; fi
  else status_row "Firewall (ufw)" fail "not installed"; fi

  if pkg_installed apparmor; then
    if aa_active; then
      e=$(aa-status --enforced 2>/dev/null || true); c=$(aa-status --complaining 2>/dev/null || true)
      [[ $e =~ ^[0-9]+$ ]] || e="?"; [[ $c =~ ^[0-9]+$ ]] || c="?"
      status_row "AppArmor" ok "running ($e profiles blocking, $c log-only)"
    elif aa_service_enabled; then status_row "AppArmor" warn "enabled, but not running yet (reboot needed)"
    else status_row "AppArmor" fail "installed but OFF"; fi
  else status_row "AppArmor" fail "not installed"; fi

  if [[ -s $SYSCTL_FILE ]]; then status_row "Kernel hardening" ok "applied ($SYSCTL_FILE)"
  else status_row "Kernel hardening" off "not applied"; fi

  case $(state_get AI_AGENT 2>/dev/null || echo allowed) in
    allowed) status_row "AppArmor profiles" warn "COMPLAIN (log only)" ;;
    *)       status_row "AppArmor profiles" ok "ENFORCE (most secure)" ;;
  esac

  if manifest_nonempty; then
    printf '\n  %sFiles I edited (a .backup copy sits next to each):%s\n' "$C_DIM" "$C_RESET"
    while IFS='|' read -r c f _ _; do
      [[ -n $f ]] && printf '    %s - %s\n' "$c" "$f"
    done < <(manifest_cat)
  fi
  printf '\n'
}

# =============================================================================
# SECTION 15: FINAL REPORT SCREENS
# =============================================================================
result_row() {
  local bc=$1 label=$2 st=$3 text=$4 sym col line
  case $st in
    ok)   sym=$SYM_OK;   col=$C_GREEN ;;
    warn) sym=$SYM_WARN; col=$C_YELLOW ;;
    fail) sym=$SYM_FAIL; col=$C_RED ;;
    *)    sym=$SYM_SKIP; col=$C_DIM ;;
  esac
  printf -v line '%s%s%s  %-17s %s' "$col" "$sym" "$C_RESET" "$label" "$text"
  box_row "$bc" "$line"
}

manual_steps_text() {
  if [[ $FW_STATUS == fail ]]; then
    cat <<'EOF'
FIREWALL (by hand):
  sudo pacman -S ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw enable
  sudo systemctl enable --now ufw.service
EOF
  fi
  if [[ $AA_STATUS == fail ]]; then
    printf 'APPARMOR (by hand):\n  sudo pacman -S apparmor\n  sudo pacman -S apparmor.d   # or: yay -S apparmor.d-git\n'
    print_manual_kernel_param | sed 's/^/  /'
    printf '  sudo systemctl enable --now apparmor.service\n  sudo reboot\n  aa-enabled   # verify after reboot\n'
  fi
  if [[ $SYS_STATUS == fail ]]; then
    printf 'KERNEL SETTINGS: copy the settings from the script (SECTION 12) into\n  /etc/sysctl.d/99-arch-security.conf and run: sudo sysctl --system\n'
  fi
}

finish_enable() {
  local verdict=ok bc n
  if [[ $FW_STATUS == fail || $SYS_STATUS == fail ]]; then
    verdict=fail
  elif [[ $AA_STATUS == fail ]]; then
    verdict=warn
  elif [[ $AA_STATUS == unsupported ]]; then
    verdict=partial
  fi
  if [[ $verdict == ok && $STEP_FAILS -gt 0 ]]; then
    verdict=warn
  fi
  (( DRY_RUN )) && verdict=dry

  printf '\n'
  case $verdict in
    ok)      bc=$C_GREEN ;;
    partial) bc=$C_CYAN ;;
    warn)    bc=$C_YELLOW ;;
    fail)    bc=$C_RED ;;
    *)       bc=$C_MAGENTA ;;
  esac
  box_top "$bc"
  case $verdict in
    ok)      box_row "$bc" "${C_BOLD}${C_GREEN}${SYM_OK}  SUCCESS - firewall and kernel hardening are active${C_RESET}" ;;
    partial) box_row "$bc" "${C_BOLD}${C_CYAN}${SYM_INFO}  PARTIAL SUCCESS - firewall and kernel hardening applied${C_RESET}" ;;
    warn)    box_row "$bc" "${C_BOLD}${C_YELLOW}${SYM_WARN}  DONE, BUT PLEASE READ THE NOTES BELOW${C_RESET}" ;;
    fail)    box_row "$bc" "${C_BOLD}${C_RED}${SYM_FAIL}  FAILED - the security system could not be set up${C_RESET}" ;;
    *)       box_row "$bc" "${C_BOLD}${C_MAGENTA}${SYM_ARROW}  DRY-RUN FINISHED - nothing was changed${C_RESET}" ;;
  esac
  box_sep "$bc"
  if [[ $verdict != dry ]]; then
    case $FW_STATUS in
      ok)   result_row "$bc" "Firewall" ok "ufw active, starts at every boot" ;;
      kept) result_row "$bc" "Firewall" ok "firewalld is protecting this PC" ;;
      fail) result_row "$bc" "Firewall" fail "could not be set up" ;;
    esac
    case $AA_STATUS in
      ok)          result_row "$bc" "AppArmor" ok "active" ;;
      pending)     result_row "$bc" "AppArmor" ok "enabled - starts after the reboot" ;;
      unsupported) result_row "$bc" "AppArmor" skip "not available in this kernel (skipped)" ;;
      fail)        result_row "$bc" "AppArmor" fail "could not be set up" ;;
    esac
    case $SYS_STATUS in
      ok)   result_row "$bc" "Kernel hardening" ok "applied and permanent" ;;
      fail) result_row "$bc" "Kernel hardening" fail "could not be applied" ;;
    esac
    if [[ $AI_MODE == allowed ]]; then result_row "$bc" "AppArmor profiles" warn "complain (log only)"
    else result_row "$bc" "AppArmor profiles" ok "enforce (most secure)"; fi
  else
    box_text "$bc" "" "This was a preview. Run the script again without --dry-run to apply it."
  fi
  if (( NEED_REBOOT )) && [[ $verdict != dry ]]; then
    box_sep "$bc"
    box_text "$bc" "$C_BOLD" "Please REBOOT once to switch AppArmor on:  sudo reboot"
    box_text "$bc" "$C_DIM" "After rebooting, verify with:  aa-enabled"
  fi
  if manifest_nonempty && [[ $verdict != dry ]]; then
    box_sep "$bc"
    box_text "$bc" "$C_DIM" "Backups: every file I edited has a copy named <file>.backup next to it. Undo any time with: ./${SCRIPT_FILE} --rollback"
  fi
  if (( ${#NOTES[@]} )); then
    box_sep "$bc"
    for n in "${NOTES[@]}"; do box_text "$bc" "$C_YELLOW" "${SYM_WARN} ${n}"; done
  fi
  if [[ $verdict == warn || $verdict == fail ]]; then
    box_sep "$bc"
    box_text "$bc" "$C_BOLD" "Please do these steps by hand:"
    box_text "$bc" "" "$(manual_steps_text)"
    box_text "$bc" "$C_DIM" "Full details: ${LOG_FILE}"
  fi
  box_bot "$bc"
  printf '\n'

  if { [[ $verdict == fail ]] || (( BOOT_BROKEN )); } && (( ! DRY_RUN )); then
    if (( BOOT_BROKEN )); then
      offer_rollback Y "Something failed while changing your system, and the boot settings may be affected."
    else
      offer_rollback N "Part of the setup did not work."
    fi
  fi

  case $verdict in
    ok|partial|dry) exit 0 ;;
    warn)           exit 2 ;;
    *)              exit 1 ;;
  esac
}

finish_failed() {
  local title=$1 text=$2
  printf '\n'
  box_top "$C_RED"
  box_row "$C_RED" "${C_BOLD}${C_RED}${SYM_FAIL}  FAILED - ${title}${C_RESET}"
  box_sep "$C_RED"
  box_text "$C_RED" "" "$text"
  box_text "$C_RED" "" "Nothing was changed on your system. Please do it by hand:  sudo pacman -Syu  (fix any error it shows), then run this script again."
  box_text "$C_RED" "$C_DIM" "Full details: ${LOG_FILE}"
  box_bot "$C_RED"
  printf '\n'
}

finish_simple() {
  printf '\n'
  box_top "$C_GREEN"
  box_row "$C_GREEN" "${C_BOLD}${C_GREEN}${SYM_OK}  $1${C_RESET}"
  box_sep "$C_GREEN"
  box_text "$C_GREEN" "" "$2"
  (( NEED_REBOOT )) && box_text "$C_GREEN" "$C_BOLD" "Please reboot:  sudo reboot"
  box_bot "$C_GREEN"
  printf '\n'
  exit 0
}

finish_simple_fail() {
  printf '\n'
  box_top "$C_RED"
  box_row "$C_RED" "${C_BOLD}${C_RED}${SYM_FAIL}  $1${C_RESET}"
  box_sep "$C_RED"
  box_text "$C_RED" "" "$2"
  box_bot "$C_RED"
  printf '\n'
  exit 1
}

# =============================================================================
# SECTION 16: main()
# =============================================================================
main() {
  ORIG_ARGS=("$@")
  parse_args "$@"
  setup_ui
  if (( SHOW_HELP ));    then show_help; exit 0; fi
  if (( SHOW_VERSION )); then echo "${SCRIPT_FILE} ${SCRIPT_VERSION}"; exit 0; fi

  require_root
  init_workdirs
  trap cleanup EXIT
  trap on_interrupt INT TERM
  cursor_hide
  banner
  (( DRY_RUN )) && warn "DRY-RUN: I will only show what would happen. Nothing is changed."
  preflight

  case $ACTION in
    enable)    do_enable ;;
    disable)   do_disable ;;
    uninstall) do_uninstall ;;
    rollback)  do_rollback ;;
    status)    do_status ;;
    ai)        resolve_ai_mode; do_ai ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
