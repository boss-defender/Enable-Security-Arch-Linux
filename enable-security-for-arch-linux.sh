#!/usr/bin/env bash
# =============================================================================
#  enable-security-for-arch-linux.sh  —  v3.3.0
# =============================================================================
#  A production-grade security baseline for Arch-based systems.
#  Supported: Arch Linux, Manjaro, Omarchy, EndeavourOS, Garuda Linux.
#
#  CachyOS IS NOT SUPPORTED. Do not run this script on CachyOS.
#  Artix Linux is NOT SUPPORTED (no systemd).
#
#  v3.3.0 changes:
#    - NEW: setup asks "apparmor.d on or off?" first. On -> it asks complain
#      or enforce. Off -> apparmor.d is skipped (same as --no-aur).
#    - NEW: --apparmor-d-on / --apparmor-d-off turn apparmor.d on or off later
#      (AppArmor, firewall and kernel hardening stay as they are).
#    - NEW: --complain / --enforce as clearer names for --allow-ai-agent /
#      --disable-ai-agent (the old names still work).
#    - NEW: --status shows apparmor.d on/off, the mode and for how many days;
#      after 7 days in complain mode it gives the week-2 tip.
#    - FIX: apparmor.d from the repos is no longer installed when the user
#      chose off or gave --no-aur.
#
#  v3.2.2 changes:
#    - NEW: a normal run asks whether AI agents are allowed (AppArmor
#      complain / log-only, the default) or blocked (enforce). It shows the
#      detected desktop and warns on Hyprland/Sway/i3/niri, where apparmor.d
#      is not supported. Not asked with -y, without a terminal, or when
#      --allow-ai-agent / --disable-ai-agent is given.
#    - FIX: choosing "block" during setup now really switches the profiles to
#      enforce (before, enforce was applied only by --disable-ai-agent alone).
#
#  v3.2.0 changes:
#    - NEW: apparmor.d is built from the AUR automatically (as the normal
#      user who ran the script, installed with pacman -U; no AUR helper).
#      Upstream key is checked; go/just are removed after the build.
#      parser.conf gets the cache settings upstream asks for. --no-aur skips it.
#    - NEW: Ctrl+C and Ctrl+Z stop the script safely: the running step
#      finishes first (the AUR build is cancelled at once), then undo is offered.
#    - CHANGE: the AI-agent switch is shown and works the same on every
#      supported system, not only Omarchy.
#    - FIX (3.2.1): profile mode switch no longer uses aa-enforce/aa-complain
#      with apparmor.d ("Conflicting profiles for brave"); uses apparmor.d's
#      /etc/apparmor/modes + aa-install, never touches unconfined placeholders,
#      and repairs placeholders older versions switched by mistake.
#    - NEW: if the setup fails (or the script crashes), everything is undone
#      automatically and the user is told: "Sorry, I failed - but your system
#      is safe". Original files come back; installed packages are removed.
#    - FIX: question prompts were invisible ("exec 9>lock 2>/dev/null"
#      silenced stderr for the whole script).
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
SCRIPT_VERSION="3.3.0"
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
AAD_MODES_FILE="/etc/apparmor/modes"          # apparmor.d (aa-install) mode setting
AAD_VENDOR_MODES="/usr/share/apparmor/modes"
AAD_SRC_DIR="/usr/share/apparmor.d"
PKG_CACHE_DIR="/var/cache/pacman/pkg"
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
  AAD_MODES_FILE="${T_AAD_MODES_FILE:-$AAD_MODES_FILE}"
  AAD_VENDOR_MODES="${T_AAD_VENDOR_MODES:-$AAD_VENDOR_MODES}"
  AAD_SRC_DIR="${T_AAD_SRC_DIR:-$AAD_SRC_DIR}"
  PKG_CACHE_DIR="${T_PKG_CACHE_DIR:-$PKG_CACHE_DIR}"
  LSM_SYSFS="${T_LSM_SYSFS:-$LSM_SYSFS}"
  APPARMOR_SYSFS="${T_APPARMOR_SYSFS:-$APPARMOR_SYSFS}"
  PROC_CMDLINE="${T_PROC_CMDLINE:-$PROC_CMDLINE}"
fi

ACTION=""
AI_MODE=""
ASSUME_YES=0
DRY_RUN=0
FORCE_UFW=0
NO_AUR=0
AAD_ACTION_RUNNING=0 # 1 while --apparmor-d-on/off runs (Ctrl+C must not undo the whole setup)
AAD_WANT=""         # 1 = apparmor.d on, 0 = off (asked during setup)
OPT_NO_COLOR=0
SHOW_HELP=0
SHOW_VERSION=0
ORIG_ARGS=()

STEP_N=0
STEP_TOTAL=1
STEP_FAILS=0
CURRENT_PID=""
STOP_REQUESTED=0     # set by Ctrl+C / Ctrl+Z; acted on between steps
IN_SAFE_STOP=0
STEP_KILLABLE=0      # 1 = the running step may be cancelled at once (AUR build)
WATCH_PID=""
ENABLE_RUNNING=0     # 1 while --enable is changing the system (for auto-undo)
AUTO_UNDO_DONE=0
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

# Like box_text, but every wrapped line is indented by 4 spaces.
box_indent() {
  local bc=$1 line
  shift
  while IFS= read -r line; do
    box_row "$bc" "    ${line}"
  done < <(printf '%s\n' "$*" | fold -s -w $((UI_WIDTH - 8)))
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
    if (( STOP_REQUESTED )); then
      step_live "${SPIN_FRAMES[i % ${#SPIN_FRAMES[@]}]}" "$desc  (stopping after this step...)"
    else
      step_live "${SPIN_FRAMES[i % ${#SPIN_FRAMES[@]}]}" "$desc"
    fi
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
  # The step ignores Ctrl+C / Ctrl+Z itself (the script decides when to stop),
  # so a package install or boot-menu update is never cut off halfway.
  { trap '' INT QUIT TSTP TTIN TTOU; "$@"; } </dev/null >>"$LOG_FILE" 2>&1 &
  CURRENT_PID=$!
  spin_until_done "$CURRENT_PID" "$desc"
  # 'wait' returns early when Ctrl+C / Ctrl+Z arrives; keep waiting until the
  # step has really finished, so nothing is ever left half-done.
  while :; do
    wait "$CURRENT_PID"; rc=$?
    if (( rc > 128 )) && kill -0 "$CURRENT_PID" 2>/dev/null; then continue; fi
    break
  done
  CURRENT_PID=""
  log "<<< exit code $rc"
  if (( rc == 0 )); then
    step_final ok "$desc" "$(( SECONDS - start ))s"
  else
    STEP_FAILS=$(( STEP_FAILS + 1 ))
    step_final fail "$desc" "failed"
    show_log_tail "$mark"
  fi
  (( STOP_REQUESTED && ! IN_SAFE_STOP )) && safe_stop
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
  local rc=$?
  # The script ended unexpectedly in the middle of --enable (an error, a crash,
  # or a "die" message): undo everything so the system is never left half-done.
  if (( ENABLE_RUNNING && ! IN_SAFE_STOP && ! DRY_RUN && rc != 0 )); then
    trap '' INT TERM USR1
    auto_rollback "the script stopped unexpectedly (exit code $rc)."
  fi
  cursor_show
  [[ -n ${WATCH_PID:-} ]] && kill "$WATCH_PID" 2>/dev/null
  if [[ -n ${RUN_TMP:-} && -d $RUN_TMP ]]; then rm -rf "$RUN_TMP"; fi
}

# --- Safe stop with Ctrl+C or Ctrl+Z ------------------------------------------
# Ctrl+Z normally freezes a program in the middle of what it is doing. Freezing
# pacman or a boot-loader update would leave the package database locked or the
# boot menu half-written, so this script turns Ctrl+Z into a SAFE STOP instead:
#   * The script and every program it starts ignore the freeze signal (TSTP).
#   * A tiny watcher process still notices Ctrl+Z and tells the script (USR1).
#   * The running step is allowed to finish; then the script stops and offers
#     to undo its changes. The AUR build is the only step cancelled at once,
#     because cancelling a compile is harmless.
start_stop_watcher() {
  local parent=$$
  (
    exec 9>&-          # never hold the "already running" lock
    trap 'kill -USR1 "$parent" 2>/dev/null' TSTP
    trap 'exit 0' TERM
    while kill -0 "$parent" 2>/dev/null; do
      ( trap '' TSTP; exec sleep 1 ) &
      wait $! 2>/dev/null
    done
  ) </dev/null >/dev/null 2>&1 &
  WATCH_PID=$!
  trap '' TSTP TTIN TTOU
}

kill_tree() {
  local pid=$1 c
  for c in $(pgrep -P "$pid" 2>/dev/null); do kill_tree "$c"; done
  kill -TERM "$pid" 2>/dev/null || true
}

on_interrupt() {
  if (( IN_SAFE_STOP )); then
    printf '\n'; warn "Please wait - I am putting things back safely."
    return 0
  fi
  if [[ -n $CURRENT_PID ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    if (( STEP_KILLABLE )) && ! mark_has no_kill; then
      STOP_REQUESTED=1
      kill_tree "$CURRENT_PID"
      return 0
    fi
    if (( ! STOP_REQUESTED )); then
      STOP_REQUESTED=1
      printf '\n'
      warn "Stop requested. Finishing the current step first so nothing is left half-done..."
    fi
    return 0
  fi
  safe_stop
}

safe_stop() {
  IN_SAFE_STOP=1
  STOP_REQUESTED=0
  cursor_show
  printf '\n'
  warn "Stopped safely before the script finished."
  aur_leftover_cleanup
  if (( AAD_ACTION_RUNNING )); then
    pkg_installed apparmor.d || state_del INSTALLED_APPARMOR_D
    info "Your existing setup was not touched. apparmor.d is $(pkg_installed apparmor.d && echo ON || echo 'still OFF')."
    exit 130
  fi
  if [[ -t 0 ]] && manifest_nonempty && (( ! DRY_RUN )); then
    offer_rollback Y "You stopped the script while it was changing files."
  elif [[ -s ${STATE_FILE:-/nonexistent} ]] && (( ! DRY_RUN )); then
    info "Nothing is left half-done, but the steps that finished are active (for example the firewall)."
    info "To continue, run the script again. To undo everything:  ./${SCRIPT_FILE} --uninstall"
  else
    info "Nothing was changed. Run the script again any time."
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
    usage_error "please choose only ONE of --enable, --disable, --uninstall, --rollback, --status, --apparmor-d-on, --apparmor-d-off."
  fi
  ACTION=$1
}

set_ai() {
  if [[ -n $AI_MODE && $AI_MODE != "$1" ]]; then
    usage_error "--complain (--allow-ai-agent) and --enforce (--disable-ai-agent) cannot be used together."
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
      --allow-ai-agent|--complain) set_ai allowed ;;
      --disable-ai-agent|--enforce) set_ai blocked ;;
      --apparmor-d-on)      set_action aadon ;;
      --apparmor-d-off)     set_action aadoff ;;
      -y|--yes)             ASSUME_YES=1 ;;
      --dry-run)            DRY_RUN=1 ;;
      --force-ufw)          FORCE_UFW=1 ;;
      --no-aur)             NO_AUR=1 ;;
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
    usage_error "--complain / --enforce only work together with the normal install, or on their own."
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

${C_BOLD}APPARMOR.D${C_RESET}  (1500+ extra AppArmor profiles)
  --apparmor-d-on      Install apparmor.d and turn it on.
  --apparmor-d-off     Remove apparmor.d (AppArmor, firewall, kernel settings stay).

${C_BOLD}MODE SWITCH${C_RESET}  (works on Arch, Manjaro, Omarchy, EndeavourOS and Garuda)
  --complain, --allow-ai-agent
                       AppArmor profiles go to "complain" (log only).
                       NOTE: This only affects programs that HAVE a profile.
                       Unprofiled programs are not confined either way.
  --enforce, --disable-ai-agent
                       The most secure mode (AppArmor blocks).
                       Don't use it on Hyprland (Omarchy), Sway or i3.
  A normal run asks: apparmor.d on/off, then complain/enforce (defaults:
  on, complain). With -y, or with one of these options, it does not ask.
  Recommended: week 1 complain, check "sudo aa-log", week 2 enforce
  (KDE Plasma, GNOME, XFCE only).

${C_BOLD}EXTRA OPTIONS${C_RESET}
  -y, --yes            Do not ask questions.
  --dry-run            Show what would happen; change nothing.
  --force-ufw          Replace firewalld by ufw (firewalld config is backed up).
  --no-aur             Do not build the apparmor.d profiles from the AUR.
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
    # The braces matter: "exec 9>file 2>/dev/null" would silence stderr for the
    # whole script, hiding every question prompt (read -p writes to stderr).
    { exec 9>"$LOCK_FILE"; } 2>/dev/null || return 0
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

  local ai_now
  ai_now=${AI_MODE:-$(state_get AI_AGENT 2>/dev/null || true)}
  case $ai_now in
    blocked) info "AI agents      : blocked (AppArmor enforce mode)" ;;
    *)       info "AI agents      : allowed (AppArmor complain mode, default)" ;;
  esac
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

# --- Switching AppArmor profiles between complain and enforce -----------------
# FIX v3.2.1: aa-complain / aa-enforce must NOT be used with apparmor.d.
#  * apparmor.d replaces some upstream profiles (brave, chrome, opera, ...):
#    it installs its own copy as <name>.apparmor.d and disables the upstream
#    one. aa-enforce does not understand disabled profiles and stops with
#    "Conflicting profiles for brave defined in two files" (apparmor.d #727;
#    upstream says: set the mode through apparmor.d itself).
#  * apparmor.d's pacman hook re-runs "aa-install --install" after every
#    package transaction, so aa-complain/aa-enforce changes would be lost.
#  * The upstream apparmor package ships many placeholder profiles with
#    flags=(unconfined) (only to allow user namespaces). They must never be
#    switched to complain or enforce: enforcing them breaks those programs.
# So: with apparmor.d, write the mode to /etc/apparmor/modes and let
# aa-install rebuild the profiles. Without it, only switch real profiles.

aa_is_disabled() { [[ -e $APPARMOR_DIR/disable/$1 ]]; }

# Real profiles in /etc/apparmor.d that may be switched: not disabled, not an
# unconfined placeholder, not a backup/pacman leftover.
aa_switchable_profiles() {
  local f b
  while IFS= read -r -d '' f; do
    b=${f##*/}
    aa_is_disabled "$b" && continue
    grep -qE '^[[:space:]]*profile[[:space:]]' "$f" 2>/dev/null || continue
    grep -qE '^[[:space:]]*profile[[:space:]].*flags=\([^)]*unconfined' "$f" 2>/dev/null && continue
    printf '%s\n' "$b"
  done < <(find "$APPARMOR_DIR" -maxdepth 1 -type f ! -name '.*' ! -name '*.pacnew' ! -name '*.pacsave' \
             ! -name '*.pacorig' ! -name '*~' ! -name '*.backup' ! -name '*.backup.*' -print0 2>/dev/null)
}

# Repair damage from v3.2.0 and older: those versions ran aa-complain on every
# file, which turned upstream flags=(unconfined) placeholders into complain
# mode. Put such a file back to the packaged version ONLY when the flags are
# the sole difference (so a user's own edits are never touched). Best effort.
aa_repair_upstream_flags() {
  local ver pkgf tmp f b cur fixed=0
  (( DRY_RUN )) && return 0
  have pacman && have bsdtar || return 0
  ver=$(pacman -Q apparmor 2>/dev/null | awk '{print $2}') || return 0
  [[ -n $ver ]] || return 0
  pkgf=$(ls -1 "$PKG_CACHE_DIR"/apparmor-"$ver"-*.pkg.tar.* 2>/dev/null | grep -v '\.sig$' | head -n1)
  [[ -n $pkgf && -f $pkgf ]] || return 0
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/asec-aafix.XXXXXX") || return 0
  if bsdtar -xf "$pkgf" -C "$tmp" etc/apparmor.d 2>/dev/null; then
    for f in "$tmp"/etc/apparmor.d/*; do
      [[ -f $f ]] || continue
      b=${f##*/}; cur=$APPARMOR_DIR/$b
      [[ -f $cur ]] || continue
      grep -qE '^[[:space:]]*profile[[:space:]].*flags=\([^)]*unconfined' "$f" || continue
      cmp -s "$f" "$cur" && continue
      if [[ "$(sed -E 's/[[:space:]]*flags=\([^)]*\)//' "$f")" == "$(sed -E 's/[[:space:]]*flags=\([^)]*\)//' "$cur")" ]]; then
        # Keep a copy OUTSIDE /etc/apparmor.d (AppArmor would load a copy in
        # there as a second profile), and do not list it for rollback: a
        # rollback must never bring the broken flags back.
        mkdir -p "$STATE_DIR/repaired-profiles" && cp -p -- "$cur" "$STATE_DIR/repaired-profiles/$b.$(date +%Y%m%d%H%M%S)" || continue
        cat "$f" >"$cur" && fixed=$(( fixed + 1 )) && echo "Restored the packaged (unconfined) version of $cur"
      fi
    done
  fi
  rm -rf -- "$tmp"
  (( fixed )) && echo "Repaired $fixed upstream placeholder profile(s)."
  return 0
}

aad_has_tools() { have aa-install && [[ -d $AAD_SRC_DIR ]]; }

# Write "default complain|enforce" to /etc/apparmor/modes. aa-install reads
# only ONE modes file (the admin one wins whole), so start from the vendor
# file to keep its other keys.
aad_write_mode() {
  local want=$1 tmp
  track_file "$AAD_MODES_FILE" || return 1
  mkdir -p "${AAD_MODES_FILE%/*}" || return 1
  tmp=$(mktemp "${TMPDIR:-/tmp}/asec-modes.XXXXXX") || return 1
  if [[ -f $AAD_MODES_FILE ]]; then cat "$AAD_MODES_FILE" >"$tmp"
  elif [[ -f $AAD_VENDOR_MODES ]]; then cat "$AAD_VENDOR_MODES" >"$tmp"
  else printf 'include default\nreload yes\nfsp no\n' >"$tmp"; fi
  if grep -qE '^[[:space:]]*default[[:space:]]' "$tmp"; then
    sed -i -E "s/^[[:space:]]*default[[:space:]].*/default ${want}/" "$tmp"
  else
    [[ -s $tmp && $(tail -c1 "$tmp" | od -An -c | tr -d ' ') != '\n' ]] && printf '\n' >>"$tmp"
    printf 'default %s\n' "$want" >>"$tmp"
  fi
  cat "$tmp" >"$AAD_MODES_FILE" && rm -f "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 644 "$AAD_MODES_FILE"
  seal_file "$AAD_MODES_FILE"
}

aa_set_mode() {
  local mode=$1 want files=()
  [[ $mode == allowed ]] && want=complain || want=enforce
  aa_repair_upstream_flags
  if aad_has_tools; then
    echo "apparmor.d detected: setting its mode to '${want}' in ${AAD_MODES_FILE} and rebuilding the profiles."
    aad_write_mode "$want" || { echo "Could not write ${AAD_MODES_FILE}."; return 1; }
    aa-install --install || { echo "aa-install failed (see the lines above)."; return 1; }
    return 0
  fi
  if pkg_installed apparmor.d; then
    if [[ $want == complain ]]; then
      echo "This apparmor.d version installs its profiles in complain mode already - nothing to switch."
      return 0
    fi
    echo "Your apparmor.d package is too old to switch modes safely (it has no aa-install tool)."
    echo "Update it from the AUR (run this script again without --no-aur, or rebuild apparmor.d), then try again."
    return 1
  fi
  have aa-complain && have aa-enforce || { echo "The AppArmor tools (aa-complain / aa-enforce) are missing."; return 1; }
  mapfile -t files < <(aa_switchable_profiles)
  if (( ${#files[@]} == 0 )); then echo "No real profiles in $APPARMOR_DIR to switch."; return 0; fi
  ( cd "$APPARMOR_DIR" && if [[ $want == complain ]]; then aa-complain "${files[@]}"; else aa-enforce "${files[@]}"; fi )
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
    # Keep the restored boot menu files: if the refresh fails, put them back,
    # so a broken boot-loader tool can never leave the boot menu worse off.
    local keep="" gp gi=0
    if [[ -n ${RUN_TMP:-} && -d $RUN_TMP ]]; then
      keep="$RUN_TMP/bootkeep"; mkdir -p "$keep"
      for line in "${lines[@]}"; do
        IFS='|' read -r kind gp _ _ <<<"$line"
        [[ $kind == generated && -f $gp ]] || continue
        gi=$(( gi + 1 )); cp -p -- "$gp" "$keep/$gi" && printf '%s\n' "$gp" >>"$keep/list"
      done
    fi
    if ! bootloader_regen; then
      echo "Note: the boot menu could not be refreshed; keeping the restored boot menu files."
      if [[ -n $keep && -f $keep/list ]]; then
        gi=0
        while IFS= read -r gp; do gi=$(( gi + 1 )); cp -p -- "$keep/$gi" "$gp"; done <"$keep/list"
      fi
    fi
    [[ -n $keep ]] && rm -rf -- "$keep"
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

# --- Automatic undo after a failed setup ---------------------------------------
# Puts the system back to how it was before this script: switches off what it
# turned on, restores every original file from its .backup copy (and deletes
# files it created), and removes the packages it installed. Runs without
# questions. Prints one problem per line for anything it could not undo.
state_add_list() {
  local cur
  cur=$(state_get "$1" 2>/dev/null || true)
  [[ " $cur " == *" $2 "* ]] && return 0
  state_set "$1" "${cur:+$cur }$2"
}

# base-devel / git that this script installed only to build apparmor.d.
remove_build_tools() {
  local t keep=()
  for t in $(state_get INSTALLED_BUILD_TOOLS 2>/dev/null || true); do
    pkg_installed "$t" && keep+=("$t")
  done
  (( ${#keep[@]} )) || return 0
  pacman_lock_wait || return 1
  pacman -Rns --noconfirm "${keep[@]}" || pacman -R --noconfirm "${keep[@]}" || return 1
  state_del INSTALLED_BUILD_TOOLS
}

undo_everything() {
  local errs=0 inst
  fw_undo || { echo "UNDO-PROBLEM: the firewall could not be switched back."; errs=$(( errs + 1 )); }
  aa_undo || { echo "UNDO-PROBLEM: AppArmor could not be switched back."; errs=$(( errs + 1 )); }
  if [[ -n $(state_get KERNEL_PARAM_BOOTLOADER 2>/dev/null) ]]; then BOOTLOADER=$(state_get KERNEL_PARAM_BOOTLOADER); fi
  undo_files force || { echo "UNDO-PROBLEM: some files could not be restored (look for *.backup)."; errs=$(( errs + 1 )); }
  inst=$(state_get INSTALLED_APPARMOR_D 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed apparmor.d; then
    pkg_remove apparmor.d || { echo "UNDO-PROBLEM: the apparmor.d package could not be removed."; errs=$(( errs + 1 )); }
  fi
  if [[ $(state_get CREATED_EARLYPOLICY 2>/dev/null) == 1 ]]; then rm -rf -- /etc/apparmor/earlypolicy; fi
  remove_build_tools || echo "NOTE: base-devel/git (installed for the AUR build) were left installed."
  inst=$(state_get INSTALLED_UFW 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed ufw; then
    pkg_remove ufw || { echo "UNDO-PROBLEM: the ufw package could not be removed."; errs=$(( errs + 1 )); }
  fi
  inst=$(state_get INSTALLED_APPARMOR 2>/dev/null || echo 0)
  if [[ $inst == 1 ]] && pkg_installed apparmor; then
    pkg_remove apparmor || { echo "UNDO-PROBLEM: the AppArmor package could not be removed."; errs=$(( errs + 1 )); }
  fi
  if (( errs == 0 )); then cleanup_state; fi
  return "$errs"
}

auto_rollback() {
  local why=$1 ok=1 mark
  (( AUTO_UNDO_DONE || DRY_RUN )) && return 0
  AUTO_UNDO_DONE=1
  ENABLE_RUNNING=0
  IN_SAFE_STOP=1          # Ctrl+C / Ctrl+Z now only asks to wait
  aur_leftover_cleanup
  log "AUTO-ROLLBACK: $why"
  mark=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
  STEP_N=0; STEP_TOTAL=1
  section "Something failed - putting your system back automatically"
  run_step "Undoing every change I made (original files back, my packages removed)" undo_everything || ok=0
  printf '\n'
  if (( ok )); then
    box_top "$C_YELLOW"
    box_row "$C_YELLOW" "${C_BOLD}${C_YELLOW}${SYM_WARN}  Sorry, I failed - but your system is safe${C_RESET}"
    box_sep "$C_YELLOW"
    box_text "$C_YELLOW" "" "What went wrong: ${why^}"
    box_text "$C_YELLOW" "" "I undid everything automatically: my edited files are gone, your original files are back, and the packages I installed were removed. Your system is exactly as it was before you ran this script."
    box_text "$C_YELLOW" "$C_DIM" "Full details: ${LOG_FILE}"
    box_text "$C_YELLOW" "$C_DIM" "Fix the problem above, then run the script again."
    box_bot "$C_YELLOW"
  else
    box_top "$C_RED"
    box_row "$C_RED" "${C_BOLD}${C_RED}${SYM_FAIL}  Sorry, I failed - and I could not undo everything${C_RESET}"
    box_sep "$C_RED"
    box_text "$C_RED" "" "What went wrong: ${why^}"
    while IFS= read -r l; do box_text "$C_RED" "" "${l#UNDO-PROBLEM: }"; done < <(tail -c +"$(( mark + 1 ))" "$LOG_FILE" | grep '^UNDO-PROBLEM:' || true)
    box_text "$C_RED" "" "Every original file still has a copy named <file>.backup next to it. Try:  ./${SCRIPT_FILE} --uninstall"
    box_text "$C_RED" "$C_DIM" "Full details: ${LOG_FILE}"
    box_bot "$C_RED"
  fi
  printf '\n'
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
# Install apparmor.d (from the repos when they have it, else built from the
# AUR as the normal user). Honours AAD_WANT=0 (user chose "off").
aad_install_step() {
  local bu
  if pkg_installed apparmor.d; then
    if [[ $AAD_WANT == 0 ]]; then
      skip_step "Installing AppArmor profiles (apparmor.d)" "you chose off, but it was already installed; use --apparmor-d-off to remove it"
    else
      skip_step "Installing AppArmor profiles (apparmor.d)" "already installed"
    fi
    return 0
  fi
  if [[ $AAD_WANT == 0 ]]; then
    skip_step "Installing AppArmor profiles (apparmor.d)" "$( (( NO_AUR )) && echo '--no-aur given' || echo 'you chose off')"
    add_note "apparmor.d is off. Turn it on any time with: ./${SCRIPT_FILE} --apparmor-d-on"
    return 0
  fi
  if pacman -Si apparmor.d >/dev/null 2>&1; then
    state_set INSTALLED_APPARMOR_D 1
    run_step "Installing AppArmor profiles (apparmor.d)" pkg_install apparmor.d \
      || { state_set INSTALLED_APPARMOR_D 0; add_note "apparmor.d could not be installed; AppArmor will have very few profiles."; }
    return 0
  fi
  bu=$(aur_build_user)
  if [[ -z $bu ]]; then
    skip_step "Installing AppArmor profiles (apparmor.d)" "no normal user to build it as"
    add_note "apparmor.d is built from the AUR as a normal user. Run this script as your normal user (it asks for sudo itself) to install it automatically."
    return 0
  fi
  state_set INSTALLED_APPARMOR_D 1
  STEP_KILLABLE=1
  run_step "Building and installing AppArmor profiles (apparmor.d, from the AUR, a few minutes)" aur_install_apparmor_d "$bu" \
    || { state_set INSTALLED_APPARMOR_D 0; add_note "apparmor.d could not be built from the AUR; details are in $LOG_FILE. AppArmor still works with the stock profiles."; }
  STEP_KILLABLE=0; mark_clear no_kill
  return 0
}

# Ask, during a normal run, whether apparmor.d should be on or off.
choose_aad() {
  (( AA_KERNEL_SUPPORTED )) || return 0
  local saved def ans tries=0
  if (( NO_AUR )); then AAD_WANT=0; return 0; fi
  saved=$(state_get APPARMOR_D 2>/dev/null || true)
  [[ $saved == off ]] && def=2 || def=1
  if (( ASSUME_YES )) || [[ ! -t 0 ]]; then
    [[ $def == 2 ]] && AAD_WANT=0 || AAD_WANT=1
    return 0
  fi
  printf '\n'
  box_top "$C_BLUE"
  box_row "$C_BLUE" "${C_BOLD}APPARMOR.D  -  1500+ EXTRA SECURITY PROFILES${C_RESET}"
  box_sep "$C_BLUE"
  box_text "$C_BLUE" "$C_DIM" "AppArmor alone has rules for only a few programs. apparmor.d gives over 1500 programs their own rulebook, so a hacked app can't reach the rest of your system."
  box_row "$C_BLUE" ""
  box_row "$C_BLUE" "${C_GREEN}${C_BOLD}[1] On${C_RESET}   ${C_DIM}(recommended)${C_RESET}"
  box_indent "$C_BLUE" "Install apparmor.d. Next you pick complain or enforce mode."
  box_row "$C_BLUE" ""
  box_row "$C_BLUE" "${C_BOLD}[2] Off${C_RESET}"
  box_indent "$C_BLUE" "Skip it. AppArmor keeps only its few built-in profiles."
  box_sep "$C_BLUE"
  box_text "$C_BLUE" "$C_DIM" "Change it later: --apparmor-d-on / --apparmor-d-off"
  box_bot "$C_BLUE"
  cursor_show
  while :; do
    ans=""
    read -r -p "  Your choice [1/2] (Enter = ${def}): " ans || { ans=$def; printf '\n'; }
    ans=${ans//[[:space:]]/}
    [[ -z $ans ]] && ans=$def
    case ${ans,,} in
      1|on|y|yes) AAD_WANT=1; break ;;
      2|off|n|no) AAD_WANT=0; break ;;
    esac
    tries=$(( tries + 1 ))
    if (( tries >= 3 )); then
      [[ $def == 2 ]] && AAD_WANT=0 || AAD_WANT=1
      warn "No valid answer - keeping option ${def}."
      break
    fi
    warn "Please type 1 or 2."
  done
  cursor_hide
  if (( AAD_WANT )); then good "apparmor.d: ON"; else good "apparmor.d: OFF"; fi
  return 0
}

# Which desktop is running? apparmor.d officially supports only GNOME, KDE
# Plasma and XFCE. Under sudo XDG_CURRENT_DESKTOP is usually gone, so look
# at the running processes too. Prints "Name|supported" or "Name|other".
detect_desktop() {
  local d="${XDG_CURRENT_DESKTOP:-}:${DESKTOP_SESSION:-}:${XDG_SESSION_DESKTOP:-}"
  d=${d,,}
  if have pgrep; then
    pgrep -x Hyprland  >/dev/null 2>&1 && d+=":hyprland"
    pgrep -x sway      >/dev/null 2>&1 && d+=":sway"
    pgrep -x i3        >/dev/null 2>&1 && d+=":i3"
    pgrep -x niri      >/dev/null 2>&1 && d+=":niri"
    pgrep -x plasmashell >/dev/null 2>&1 && d+=":kde"
    pgrep -x gnome-shell >/dev/null 2>&1 && d+=":gnome"
    pgrep -x xfce4-session >/dev/null 2>&1 && d+=":xfce"
  fi
  case $d in
    *hyprland*) echo "Hyprland|other" ;;
    *sway*)     echo "Sway|other" ;;
    *niri*)     echo "niri|other" ;;
    *i3*)       echo "i3|other" ;;
    *kde*|*plasma*) echo "KDE Plasma|supported" ;;
    *gnome*)    echo "GNOME|supported" ;;
    *xfce*)     echo "XFCE|supported" ;;
    *)          if is_omarchy; then echo "Hyprland|other"; else echo "unknown|unknown"; fi ;;
  esac
}

# Ask, during a normal run, whether AI agents may work freely (AppArmor
# complain / log-only) or are blocked (AppArmor enforce). Only asked when the
# mode was not given on the command line, not with -y, and only on a terminal.
choose_ai_mode() {
  (( AA_KERNEL_SUPPORTED )) || return 0
  [[ -n $AI_MODE ]] && return 0
  [[ $AAD_WANT == 0 ]] && ! pkg_installed apparmor.d && return 0
  local saved def ans tries=0 info dname dsup
  saved=$(state_get AI_AGENT 2>/dev/null || true)
  [[ $saved == blocked ]] && def=2 || def=1
  if (( ASSUME_YES )) || [[ ! -t 0 ]]; then return 0; fi
  info=$(detect_desktop); dname=${info%%|*}; dsup=${info##*|}

  printf '\n'
  box_top "$C_MAGENTA"
  box_row "$C_MAGENTA" "${C_BOLD}APPARMOR MODE  -  AI AGENTS ALLOWED OR BLOCKED?${C_RESET}"
  box_sep "$C_MAGENTA"
  box_text "$C_MAGENTA" "$C_DIM" "AI coding agents can edit system files, install packages and change configs. AppArmor can let them work, or block the programs it has rules for."
  box_row "$C_MAGENTA" ""
  box_row "$C_MAGENTA" "${C_GREEN}${C_BOLD}[1] Complain${C_RESET} = AI agents allowed  ${C_DIM}(recommended)${C_RESET}"
  box_indent "$C_MAGENTA" "AppArmor only LOGS what it would block. Nothing breaks."
  box_row "$C_MAGENTA" ""
  box_row "$C_MAGENTA" "${C_RED}${C_BOLD}[2] Enforce${C_RESET}  = AI agents blocked  ${C_DIM}(maximum protection)${C_RESET}"
  box_indent "$C_MAGENTA" "AppArmor BLOCKS profiled programs that break their rules. Agents and some apps may fail."
  box_sep "$C_MAGENTA"
  case $dsup in
    other)     box_text "$C_MAGENTA" "$C_YELLOW" "Your desktop: ${dname}. apparmor.d does not support it, so choose 1. Blocking can break apps or the desktop itself." ;;
    supported) box_text "$C_MAGENTA" "$C_DIM" "Your desktop: ${dname} (supported). Best plan: week 1 complain, check 'sudo aa-log', week 2 enforce." ;;
    *)         box_text "$C_MAGENTA" "$C_DIM" "Desktop not detected. If unsure, choose 1." ;;
  esac
  box_text "$C_MAGENTA" "$C_DIM" "Firewall and kernel hardening stay on either way. Switch any time: --complain / --enforce"
  box_bot "$C_MAGENTA"

  cursor_show
  while :; do
    ans=""
    read -r -p "  Your choice [1/2] (Enter = ${def}): " ans || { ans=$def; printf '\n'; }
    ans=${ans//[[:space:]]/}
    [[ -z $ans ]] && ans=$def
    case ${ans,,} in
      1|a|allow) AI_MODE=allowed; break ;;
      2|b|block) AI_MODE=blocked; break ;;
    esac
    tries=$(( tries + 1 ))
    if (( tries >= 3 )); then
      [[ $def == 2 ]] && AI_MODE=blocked || AI_MODE=allowed
      warn "No valid answer - keeping option ${def}."
      break
    fi
    warn "Please type 1 or 2."
  done
  if [[ $AI_MODE == blocked && $dsup != supported ]]; then
    if [[ $dsup == other ]]; then
      warn "Blocking on ${dname} may break apps or your desktop."
    else
      warn "Desktop not detected. Blocking is only safe on KDE Plasma, GNOME or XFCE."
    fi
    if ! ask_yes_no "Block anyway?" N; then AI_MODE=allowed; fi
  fi
  cursor_hide
  if [[ $AI_MODE == allowed ]]; then
    good "Mode: COMPLAIN - AI agents allowed (AppArmor logs only)."
  else
    good "Mode: ENFORCE - AI agents blocked (AppArmor enforces its rules)."
  fi
  return 0
}

show_enable_plan() {
  section "What I am about to do"
  if [[ $FW_MODE == keep ]]; then
    info "Firewall: firewalld is already protecting this PC, so I keep it."
  else
    info "Firewall: install ufw, block unrequested incoming connections, allow outgoing."
  fi
  if (( AA_KERNEL_SUPPORTED )); then
    info "AppArmor: install it and switch it on at boot (one reboot needed)."
    info "Mode: switch any time with --complain / --enforce."
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
    info "apparmor.d is installed; its profiles follow the mode chosen above."
  else
    if [[ $AAD_WANT == 0 ]]; then
      info "apparmor.d: OFF (turn it on later with --apparmor-d-on)."
    elif [[ -z $(aur_build_user) ]] && ! pacman -Si apparmor.d >/dev/null 2>&1; then
      info "For full coverage, install apparmor.d from the AUR after setup."
    else
      if pacman -Si apparmor.d >/dev/null 2>&1; then
        info "apparmor.d (over 1500 profiles) will be installed from your package repositories."
      else
        info "apparmor.d (over 1500 profiles) will be built from the AUR as your normal user (a few minutes)."
      fi
    fi
  fi
  info "Backups: before editing a file I save a copy next to it, named <file>.backup."
  info "Everything is permanent and survives a reboot."
  info "Press Ctrl+C or Ctrl+Z at any time to stop safely: I finish the current step first, then offer to undo."
}

do_enable() {
  STEP_TOTAL=12
  local fw_ok=1 aa_ok=1 kp_ok=1 sys_ok=1 prev

  decide_firewall
  choose_aad
  choose_ai_mode
  resolve_ai_mode
  show_enable_plan
  ask_yes_no "Continue?" Y || { info "Okay, nothing was changed."; exit 0; }
  (( DRY_RUN )) || ENABLE_RUNNING=1
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
    skip_step "Tuning AppArmor for apparmor.d" "this kernel has no AppArmor"
    skip_step "Enabling AppArmor in the boot settings" "this kernel has no AppArmor"
    skip_step "Turning AppArmor on, also after every reboot" "this kernel has no AppArmor"
    AA_STATUS=unsupported
    add_note "Your kernel was built without AppArmor. Use the standard 'linux' or 'linux-lts' kernel to get AppArmor."
  else
    if pkg_installed apparmor; then state_set_default INSTALLED_APPARMOR 0; else state_set INSTALLED_APPARMOR 1; fi
    run_step "Installing AppArmor" pkg_install apparmor || aa_ok=0

    if (( aa_ok )); then
      aad_install_step
      if pkg_installed apparmor.d || { (( DRY_RUN )) && [[ $AAD_WANT != 0 ]]; }; then
        run_step "Tuning AppArmor for apparmor.d (fast profile cache, backup first)" aa_parser_conf_tune \
          || add_note "Could not tune $APPARMOR_PARSER_CONF; boot may be a little slower with apparmor.d."
      else
        skip_step "Tuning AppArmor for apparmor.d" "apparmor.d is not installed"
      fi
    else
      skip_step "Installing AppArmor profiles (apparmor.d)" "the AppArmor package is missing"
      skip_step "Tuning AppArmor for apparmor.d" "the AppArmor package is missing"
    fi
    if pkg_installed apparmor.d; then state_set APPARMOR_D on
    elif [[ $AAD_WANT == 0 ]]; then state_set APPARMOR_D off; fi

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
      else
        state_set AI_AGENT_PENDING 1
        add_note "After the reboot, run './${SCRIPT_FILE}' once more to switch the AppArmor profiles to enforce (block) mode."
      fi
    elif [[ $AI_MODE != "$prev" || $(state_get AI_AGENT_PENDING 2>/dev/null) == 1 ]]; then
      if run_step "Applying the AppArmor profile mode (${AI_MODE})" aa_set_mode "$AI_MODE"; then
        state_del AI_AGENT_PENDING
      else
        add_note "The AppArmor profile mode could not be applied to all profiles."
      fi
    else
      skip_step "Applying the AppArmor profile mode" "already in the desired mode"
    fi
    [[ $prev != "$AI_MODE" || -z $(state_get AI_AGENT_SINCE 2>/dev/null) ]] && state_set AI_AGENT_SINCE "$(date +%s)"
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

# --- apparmor.d from the AUR -------------------------------------------------
# makepkg refuses to run as root, so the package is built as the normal user
# who started the script (SUDO_USER) and then installed by root with pacman -U.
# No AUR helper and no extra password prompt are needed.
APPARMOR_D_AUR_URL="https://aur.archlinux.org/apparmor.d.git"
APPARMOR_D_PGP_KEY="06A26D531D56C42D66805049C5469996F0DF68EC"   # Alexandre Pujol (upstream)

aur_build_user() {
  local u=${SUDO_USER:-}
  [[ -n $u && $u != root ]] || return 0
  [[ $(id -u "$u" 2>/dev/null) =~ ^[0-9]+$ ]] || return 0
  (( $(id -u "$u") != 0 )) || return 0
  printf '%s' "$u"
}

aur_install_apparmor_d() {
  local u=$1 home dir d rc=0 key=$APPARMOR_D_PGP_KEY pgp_opt=() pkgs=() f
  local -a need=() temp=()
  home=$(getent passwd "$u" | cut -d: -f6)
  [[ -n $home && -d $home ]] || { echo "PROBLEM: the home folder of '$u' was not found."; return 1; }
  as_user() { runuser -u "$u" -- env HOME="$home" LC_ALL=C "$@"; }

  # Build tools. go and just are only needed for the build and are removed
  # again afterwards if this script installed them.
  for d in base-devel git go just; do pkg_installed "$d" || need+=("$d"); done
  for d in go just; do pkg_installed "$d" || temp+=("$d"); done
  if (( ${#need[@]} )); then
    pkg_install "${need[@]}" || return 1
    for d in "${need[@]}"; do [[ $d == go || $d == just ]] || state_add_list INSTALLED_BUILD_TOOLS "$d"; done
  fi

  dir=$(as_user mktemp -d "${TMPDIR:-/tmp}/asec-aur.XXXXXX") || return 1
  # Remember what to clean up if the build is cancelled with Ctrl+C / Ctrl+Z.
  [[ -n ${RUN_TMP:-} ]] && { printf '%s\n' "$dir" >"$RUN_TMP/aur_dir"; printf '%s\n' "${temp[@]}" >"$RUN_TMP/aur_temp"; }
  echo ">> building apparmor.d as user '$u' in $dir"
  as_user git clone --depth 1 "$APPARMOR_D_AUR_URL" "$dir/src" || rc=1

  if (( rc == 0 )); then
    # The release tarball is signed by upstream. Fetch the key for the build
    # user; if no key server answers, the sha512 sums pinned in the PKGBUILD
    # still protect the download.
    if ! as_user gpg --batch --list-keys "$key" >/dev/null 2>&1; then
      as_user gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$key" \
        || as_user gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" \
        || { echo "NOTE: could not fetch the upstream signing key; relying on the pinned sha512 sums."; pgp_opt=(--skippgpcheck); }
    fi
    ( cd "$dir/src" && as_user makepkg --noconfirm --cleanbuild "${pgp_opt[@]}" ) || { echo "PROBLEM: makepkg failed while building apparmor.d."; rc=1; }
  fi

  if (( rc == 0 )); then
    for f in "$dir"/src/*.pkg.tar.*; do
      [[ $f == *.sig || $f == *-debug-* ]] && continue
      [[ -f $f ]] && pkgs+=("$f")
    done
    (( ${#pkgs[@]} )) || { echo "PROBLEM: makepkg produced no package."; rc=1; }
  fi
  if (( rc == 0 )); then
    mark_set no_kill      # from here on, Ctrl+C / Ctrl+Z waits for pacman
    pacman_lock_wait || rc=1
    (( rc == 0 )) && { pacman -U --noconfirm --needed "${pkgs[@]}" || rc=1; }
    # Mark the helper packages as dependencies so 'pacman -Rns apparmor.d'
    # (used by --uninstall) removes them too.
    (( rc == 0 )) && pacman -D --asdeps apparmor.d-base apparmor.d-tools >/dev/null 2>&1
  fi

  if (( ${#temp[@]} )); then
    pacman_lock_wait && pacman -Rns --noconfirm "${temp[@]}" >/dev/null 2>&1 \
      && echo "Removed the build-only tools again: ${temp[*]}"
  fi
  rm -rf -- "$dir"
  rm -f -- "$RUN_TMP/aur_dir" "$RUN_TMP/aur_temp" 2>/dev/null
  return "$rc"
}

# Clean up after a cancelled AUR build: its temp folder and build-only tools.
aur_leftover_cleanup() {
  local d p
  local -a temp=()
  [[ -n ${RUN_TMP:-} && -f $RUN_TMP/aur_dir ]] || return 0
  d=$(<"$RUN_TMP/aur_dir")
  [[ $d == */asec-aur.* && -d $d ]] && rm -rf -- "$d"
  if [[ -f $RUN_TMP/aur_temp ]]; then
    while IFS= read -r p; do [[ -n $p ]] && pkg_installed "$p" && temp+=("$p"); done <"$RUN_TMP/aur_temp"
  fi
  if (( ${#temp[@]} )); then
    pacman_lock_wait >>"$LOG_FILE" 2>&1 && pacman -Rns --noconfirm "${temp[@]}" >>"$LOG_FILE" 2>&1
  fi
  rm -f -- "$RUN_TMP/aur_dir" "$RUN_TMP/aur_temp"
}

# apparmor.d ships ~100k lines of rules; upstream asks for a compressed,
# early-loaded policy cache in parser.conf.
aa_parser_conf_tune() {
  local f=$APPARMOR_PARSER_CONF line changed=0
  local -a want=("write-cache" "cache-loc /etc/apparmor/earlypolicy/" "Optimize=compress-fast")
  [[ -f $f ]] || { echo "$f not found - skipping."; return 0; }
  for line in "${want[@]}"; do
    grep -qxF -- "$line" "$f" || { changed=1; break; }
  done
  (( changed )) || { echo "$f is already tuned."; return 0; }
  track_file "$f" || return 1
  for line in "${want[@]}"; do
    grep -qxF -- "$line" "$f" || printf '%s\n' "$line" >>"$f"
  done
  if [[ ! -d /etc/apparmor/earlypolicy ]]; then
    mkdir -p /etc/apparmor/earlypolicy && state_set CREATED_EARLYPOLICY 1
  fi
  echo "Tuned $f for apparmor.d."
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
  if [[ $(state_get CREATED_EARLYPOLICY 2>/dev/null) == 1 ]] && (( ! DRY_RUN )); then
    rm -rf -- /etc/apparmor/earlypolicy && state_del CREATED_EARLYPOLICY
  fi
  if [[ -n $(state_get INSTALLED_BUILD_TOOLS 2>/dev/null) ]]; then
    run_step "Removing the build tools I installed for apparmor.d" remove_build_tools \
      || add_note "base-devel/git could not be removed; remove them by hand if you do not need them."
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
    if pkg_installed apparmor.d; then
      warn "apparmor.d's authors say: use complain mode for about a week and check 'aa-log' first."
      warn "apparmor.d officially supports GNOME, KDE and XFCE. On other desktops (Hyprland/Omarchy, Sway, ...)"
      warn "some programs, or the desktop itself, may be blocked. Undo with: ./${SCRIPT_FILE} --allow-ai-agent"
      ask_yes_no "Switch apparmor.d to enforce mode anyway?" N || { info "Okay, nothing was changed."; exit 0; }
    fi
  fi
  if ! pkg_installed apparmor; then
    state_set AI_AGENT "$AI_MODE"
    step_final warn "AppArmor is not installed yet" "(setting saved; run ./${SCRIPT_FILE} to install)"
    return 0
  fi
  [[ $(state_get AI_AGENT 2>/dev/null) != "$AI_MODE" ]] && state_set AI_AGENT_SINCE "$(date +%s)"
  fg_step "Saving the setting" state_set AI_AGENT "$AI_MODE"
  if aa_active; then
    run_step "Switching the AppArmor profiles" aa_set_mode "$AI_MODE"
  else
    skip_step "Switching the AppArmor profiles" "AppArmor is not running yet; reboot, then run this again"
  fi
  if (( STEP_FAILS )); then finish_simple_fail "The profile mode could not be applied" "See ${LOG_FILE}."
  else finish_simple "AppArmor profile mode is now: ${AI_MODE}" "$([[ $AI_MODE == allowed ]] && echo 'AppArmor only logs. The firewall is unchanged.' || echo 'AppArmor is blocking again (most secure).')"; fi
}

# --apparmor-d-on: install apparmor.d on a system that already has AppArmor.
do_aad_on() {
  STEP_TOTAL=3
  section "apparmor.d: turning ON"
  if (( ! AA_KERNEL_SUPPORTED )); then
    finish_simple_fail "apparmor.d can't be used here" "This kernel was built without AppArmor. Use the standard 'linux' or 'linux-lts' kernel."
  fi
  if ! pkg_installed apparmor; then
    finish_simple_fail "AppArmor is not set up yet" "Run ./${SCRIPT_FILE} first (it asks about apparmor.d during setup)."
  fi
  if pkg_installed apparmor.d; then
    state_set APPARMOR_D on
    finish_simple "apparmor.d is already ON" "Switch its mode with --complain or --enforce."
  fi
  info "This installs apparmor.d (over 1500 profiles). From the AUR it takes a few minutes."
  info "Its profiles start in the mode you chose before: $( [[ $(state_get AI_AGENT 2>/dev/null) == blocked ]] && echo 'ENFORCE' || echo 'COMPLAIN (log only)')."
  ask_yes_no "Turn apparmor.d on now?" Y || { info "Okay, nothing was changed."; exit 0; }
  AAD_ACTION_RUNNING=1
  AAD_WANT=1
  aad_install_step
  if (( DRY_RUN )); then finish_simple "Dry-run finished" "Nothing was changed."; fi
  if ! pkg_installed apparmor.d; then
    finish_simple_fail "apparmor.d could not be installed" "Nothing else was changed. Details: ${LOG_FILE}"
  fi
  state_set APPARMOR_D on
  run_step "Tuning AppArmor for apparmor.d (fast profile cache, backup first)" aa_parser_conf_tune \
    || add_note "Could not tune $APPARMOR_PARSER_CONF."
  resolve_ai_mode
  if aa_active; then
    run_step "Applying the AppArmor profile mode (${AI_MODE})" aa_set_mode "$AI_MODE" \
      || add_note "The profile mode could not be applied; run --complain or --enforce again."
  else
    skip_step "Applying the AppArmor profile mode" "AppArmor starts after the reboot"
    state_set AI_AGENT_PENDING 1
  fi
  NEED_REBOOT=1
  finish_simple "apparmor.d is ON" "Mode: $( [[ $AI_MODE == blocked ]] && echo 'ENFORCE (blocking)' || echo 'COMPLAIN (log only)'). Reboot so every profile is loaded."
}

# --apparmor-d-off: remove apparmor.d. AppArmor itself, the firewall and the
# kernel hardening stay on.
do_aad_off() {
  local line
  STEP_TOTAL=3
  section "apparmor.d: turning OFF"
  if ! pkg_installed apparmor.d; then
    state_set APPARMOR_D off
    finish_simple "apparmor.d is already OFF" "Turn it on any time with --apparmor-d-on."
  fi
  info "This removes the apparmor.d package and its 1500+ profiles."
  info "AppArmor (with its few built-in profiles), the firewall and the kernel hardening stay on."
  ask_yes_no "Turn apparmor.d off now?" Y || { info "Okay, nothing was changed."; exit 0; }
  AAD_ACTION_RUNNING=1
  run_step "Removing the apparmor.d package" pkg_remove apparmor.d \
    || finish_simple_fail "apparmor.d could not be removed" "Nothing else was changed. Details: ${LOG_FILE}"
  if line=$(manifest_find "$AAD_MODES_FILE"); then
    run_step "Restoring ${AAD_MODES_FILE}" restore_entry "$line" 1
  else
    skip_step "Restoring ${AAD_MODES_FILE}" "I never changed it"
  fi
  if line=$(manifest_find "$APPARMOR_PARSER_CONF"); then
    run_step "Restoring ${APPARMOR_PARSER_CONF}" restore_entry "$line" 1
  else
    skip_step "Restoring ${APPARMOR_PARSER_CONF}" "I never changed it"
  fi
  state_del INSTALLED_APPARMOR_D
  state_del AI_AGENT_PENDING
  state_set APPARMOR_D off
  NEED_REBOOT=1
  finish_simple "apparmor.d is OFF" "Its profiles stay loaded until you reboot. Turn it back on with --apparmor-d-on."
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

  if pkg_installed apparmor.d; then status_row "apparmor.d" ok "ON (1500+ profiles)"
  else status_row "apparmor.d" off "OFF (turn on: --apparmor-d-on)"; fi

  local since days dinfo
  since=$(state_get AI_AGENT_SINCE 2>/dev/null || true)
  days=""; [[ $since =~ ^[0-9]+$ ]] && days=$(( ( $(date +%s) - since ) / 86400 ))
  case $(state_get AI_AGENT 2>/dev/null || echo allowed) in
    blocked) status_row "Mode" ok "ENFORCE - AI agents blocked${days:+ (for $days days)}" ;;
    *)       status_row "Mode" warn "COMPLAIN - AI agents allowed, log only${days:+ (for $days days)}"
             if pkg_installed apparmor.d && [[ -n $days ]] && (( days >= 7 )); then
               dinfo=$(detect_desktop)
               if [[ ${dinfo##*|} == supported ]]; then
                 printf '    %sWeek 1 is done. If "sudo aa-log" shows little or nothing, switch on: --enforce%s
' "$C_DIM" "$C_RESET"
               elif [[ ${dinfo##*|} == other ]]; then
                 printf '    %sOn %s, stay in complain mode.%s
' "$C_DIM" "${dinfo%%|*}" "$C_RESET"
               fi
             fi ;;
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
  local verdict=ok bc n why=""
  ENABLE_RUNNING=0
  if (( ! DRY_RUN )); then
    [[ $FW_STATUS == fail ]]  && why+="The firewall could not be set up. "
    [[ $AA_STATUS == fail ]]  && why+="AppArmor could not be set up. "
    [[ $SYS_STATUS == fail ]] && why+="The kernel settings could not be applied. "
    (( BOOT_BROKEN ))         && why+="The boot settings could not be updated safely. "
    if [[ -n $why ]]; then
      for n in "${NOTES[@]}"; do log "NOTE: $n"; done
      auto_rollback "${why% }"
      exit 1
    fi
  fi
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
  start_stop_watcher
  trap on_interrupt INT TERM USR1
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
    aadon)     do_aad_on ;;
    aadoff)    do_aad_off ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi