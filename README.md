<div align="center">

# 🛡️ Arch Linux Security Setup

**One script. A firewall, AppArmor and safe kernel hardening, with full undo.**

![Version](https://img.shields.io/badge/version-3.3.0-blue)
![Last updated](https://img.shields.io/badge/last%20updated-12%20Oct%202026-brightgreen)
![Shell](https://img.shields.io/badge/shell-bash-green)
![Init](https://img.shields.io/badge/requires-systemd-orange)

`Arch Linux` · `Omarchy` · `EndeavourOS` · `Manjaro` · `Garuda Linux`

</div>

> 📅 **Last updated: 12 October 2026** (v3.3.0)
>
> Arch and Arch-based distros change fast: boot loaders, packages and defaults move over time. If this date is more than about 6 months old, check the [commits](https://github.com/boss-defender/Enable-Security-Arch-Linux/commits/main) and [issues](https://github.com/boss-defender/Enable-Security-Arch-Linux/issues) before running, test on a VM or snapshot first, or [refresh the script with an AI](#-script-out-of-date-refresh-it-with-ai).

---

## ✨ What it does

Run it once and your system gets a solid security baseline that survives every reboot.

| Layer | What you get |
|---|---|
| 🔥 **Firewall (ufw)** | Blocks unrequested incoming connections and allows outgoing. A running SSH server is detected (including `sshd.socket`), and its port stays open with rate limiting so you can't lock yourself out. |
| 🧱 **AppArmor** | Installs AppArmor, adds the correct `lsm=` setting to your boot loader and enables it at every boot. Profiles start in **complain (log-only)** mode, so your desktop won't break. |
| 📚 **apparmor.d profiles** *(you choose on or off)* | Builds [apparmor.d](https://github.com/roddhjav/apparmor.d) (over 1500 profiles) from the AUR **automatically**, as your normal user, with no AUR helper needed. It checks the upstream signature and tunes the profile cache for a fast boot. |
| ⚙️ **Kernel hardening** | Applies safe `sysctl` settings: hides kernel pointers and `dmesg`, restricts `ptrace`, turns on SYN cookies and reverse-path filtering, ignores ICMP redirects, and protects hard links and symlinks. |

## 🧠 Built to be safe

- 🛟 **Fails safe, automatically.** If anything goes wrong, or the script crashes, it undoes everything on its own: original files come back, and the packages it installed are removed. Then it tells you: *"Sorry, I failed, but your system is safe."*
- 💾 **Backs up every file before touching it.** Each one gets a `<file>.backup` copy, and a manifest records every change.
- ↩️ **Full undo** with `--rollback`, `--disable` or `--uninstall`. Your original files come back exactly as they were.
- 🩺 **Checks the boot menu** after every edit. If the new setting didn't reach it, the script offers to undo straight away.
- 🔁 **Safe to run twice.** A second run changes nothing.
- ✋ **Stop any time with `Ctrl+C` or `Ctrl+Z`.** The script finishes the step it's on, so pacman or your boot menu is never cut off halfway. Then it stops and offers to undo.
- 🧪 **`--dry-run`** shows every step without changing anything.
- 🔍 **Detects your boot loader on its own:** GRUB, systemd-boot (classic and UKI), and Limine (including Omarchy's `+=` lines and `/etc/limine-entry-tool.d/` drop-ins).
- 🚧 **Respects what's already there.** It never mixes AppArmor with SELinux, keeps an active **firewalld** unless you pass `--force-ufw`, skips AppArmor on kernels built without it, and refuses to run inside containers.
- 🔑 **Handles common pacman problems:** it clears a stale lock, repairs broken keyrings, updates an outdated package database (only after asking before `-Syu`) and checks for low disk space first.

## 🚀 Quick start

```bash
git clone https://github.com/boss-defender/Enable-Security-Arch-Linux.git
cd Enable-Security-Arch-Linux
chmod +x enable-security-for-arch-linux.sh

./enable-security-for-arch-linux.sh --dry-run   # preview, changes nothing
./enable-security-for-arch-linux.sh             # install and enable
sudo reboot                                     # one reboot switches AppArmor on
./enable-security-for-arch-linux.sh --status    # check everything
```

> The script asks for `sudo` by itself. During setup it asks two questions: **apparmor.d on or off?**, then **complain or enforce?** Just press Enter for the safe defaults (on + complain). After the reboot, run it **once more** to finish the AppArmor profile setup.

## 🧰 Commands

| Command | What it does |
|---|---|
| *(no option)* / `--enable` | Install and enable everything |
| `--status` | Show what is installed and active |
| `--disable` | Turn everything **off** (nothing is uninstalled) |
| `--rollback` | Undo only the file edits, and switch off what it enabled |
| `--uninstall` | Turn off, restore the **original** files, remove the packages it installed |
| `--apparmor-d-on` | Install apparmor.d and turn it **on** |
| `--apparmor-d-off` | Remove apparmor.d (AppArmor, firewall and kernel hardening stay on) |
| `--complain` *(or `--allow-ai-agent`)* | Profiles → **complain** (log only, AI agents allowed) |
| `--enforce` *(or `--disable-ai-agent`)* | Profiles → **enforce** (block, AI agents blocked) |
| `-y`, `--yes` | Don't ask questions (safe defaults) |
| `--dry-run` | Preview only |
| `--force-ufw` | Replace an active firewalld with ufw (firewalld config is backed up) |
| `--no-aur` | Skip apparmor.d (same as choosing **Off**) |
| `--no-color`, `-h`, `-V` | Plain output, help, version |

## 📚 apparmor.d, explained for beginners

### What is it?
**AppArmor** is a security guard built into the Linux kernel. For each program it reads a **profile**, a rulebook of what that program may touch. For example: *Firefox may read Downloads and use the internet, but it may not read your SSH keys or change system files.*

Out of the box, AppArmor on Arch has rules for only **a handful** of programs. **[apparmor.d](https://github.com/roddhjav/apparmor.d)** is a community project that adds **over 1,500 profiles**: browsers, desktop apps, system services and core tools.

> **AppArmor** = the guard. **apparmor.d** = the big book of rules the guard uses.

### Why use it?
Say a website exploits a bug in your browser, or a booby-trapped PDF hacks your viewer. Without a profile, the attacker can reach everything your account can: files, passwords, SSH keys. With apparmor.d, the attacker is **stuck inside that program's rulebook**, so the damage stays small.

### Is it necessary?
**No, it's optional:** an extra layer on top of the basics. In order of importance: 1) keep your system updated, 2) firewall, 3) kernel hardening (the script does 2 and 3 either way), 4) AppArmor + apparmor.d.

### What it does NOT do
It's not an antivirus, it doesn't stop things you run yourself with `sudo`, it doesn't confine programs without a profile, and in complain mode it only watches.

### On or off: what changes?

| | **apparmor.d ON** | **apparmor.d OFF** |
|---|---|---|
| Programs with rules | 1,500+ | Only a handful |
| A hacked app can… | only do what its rulebook allows (in enforce mode) | reach everything your account can |
| Risk of breaking apps | None in complain mode | None |
| Install time | A few minutes (built from the AUR) | — |
| Firewall + kernel hardening | ✅ On | ✅ On |

### The two modes

| Mode | What happens | AI agents | Best for |
|---|---|---|---|
| 🟢 **Complain** (default) | Rule-breaking is only **written to a log** | Allowed: work freely | Week 1, Hyprland/Omarchy, AI agent sessions |
| 🔴 **Enforce** | Rule-breaking is **blocked** | Blocked: they can fail when a profiled tool is stopped | Daily use on KDE, GNOME or XFCE, after testing |

AI agents such as coding assistants often need to edit system files, install packages or change configs. That's why the script labels the modes "AI agents allowed" and "AI agents blocked".

### What the script asks during setup

```text
APPARMOR.D  -  1500+ EXTRA SECURITY PROFILES
  [1] On   (recommended)   Install apparmor.d. Next you pick the mode.
  [2] Off                  Skip it. AppArmor keeps only its few built-in profiles.

APPARMOR MODE  -  AI AGENTS ALLOWED OR BLOCKED?      (only asked when On)
  [1] Complain = AI agents allowed  (recommended)
  [2] Enforce  = AI agents blocked  (maximum protection)
  Your desktop: Hyprland. apparmor.d does not support it, so choose 1.
```

- Press **Enter** for the safe defaults: **On + Complain**.
- On Hyprland (Omarchy), Sway, i3 or niri it warns you and asks again before enforcing.
- On a rerun, Enter keeps your last choice.
- It asks nothing with `-y` (it keeps your saved choices; defaults are on + complain), without a terminal, or when you pass `--complain` / `--enforce` / `--no-aur`.
- If you choose Enforce on a fresh install, it's applied when you run the script again after the reboot.

### Change your mind any time

```bash
./enable-security-for-arch-linux.sh --apparmor-d-on    # turn apparmor.d on
./enable-security-for-arch-linux.sh --apparmor-d-off   # turn apparmor.d off
./enable-security-for-arch-linux.sh --complain         # log only  (AI agents allowed)
./enable-security-for-arch-linux.sh --enforce          # block     (AI agents blocked)
./enable-security-for-arch-linux.sh --status           # see what's on, the mode, and for how many days
```

### 🗓️ Recommended plan: week 1 complain, week 2 enforce

| Your desktop | Plan |
|---|---|
| **KDE Plasma, GNOME, XFCE** (officially supported) | ✅ **Week 1:** stay in complain and use your PC normally (browser, apps, updates). **End of week 1:** run `sudo aa-log`. Empty or almost empty? **Week 2:** run `--enforce`. Lots of entries for apps you use? Stay in complain. |
| **Hyprland** (Omarchy), Sway, i3, niri and other window managers | ❌ **Stay in complain for good.** apparmor.d isn't built for these, so enforce can block apps or even your login/desktop. |

`--status` counts the days for you: after 7 days in complain mode on a supported desktop, it reminds you to check `sudo aa-log` and switch.

**If something breaks after enforcing:** press `Ctrl+Alt+F3`, log in, run `./enable-security-for-arch-linux.sh --complain`, then reboot.

### How the script installs it
It clones the apparmor.d package, builds it **as your normal user** (never as root), checks the developer's signing key and installs it with pacman. The build takes a few minutes. `go` and `just` are only needed for the build, so they're removed afterwards; `base-devel` and `git` stay installed. The mode is set the way apparmor.d itself does it: `default complain|enforce` in `/etc/apparmor/modes`, then `aa-install --install`.

- Run the script as your **normal user**, not from a root shell. It asks for `sudo` itself.
- On Manjaro or Garuda, a prebuilt apparmor.d from your repos is used when one is available.
- `--uninstall` removes apparmor.d only if the script installed it. `--apparmor-d-off` removes it either way, because you asked.

> **Honest note:** AppArmor only affects programs that have a profile. Complain mode doesn't give an agent root, and enforce mode doesn't confine an agent that has no profile. System-level edits still need `sudo`, so keep an eye on what your agent runs.

## 🖥️ Supported systems

| System | Status |
|---|---|
| Arch Linux · Omarchy · EndeavourOS · Manjaro · Garuda Linux | ✅ Supported |
| Other Arch-based distros (`ID_LIKE=arch`) | ⚠️ Asks before continuing |
| CachyOS | ⛔ Refused (AppArmor has caused boot problems with some CachyOS kernels) |
| Artix | ⛔ Refused (no systemd) |

**Requirements:** systemd, pacman, a kernel with AppArmor support (the stock `linux`, `linux-lts`, `linux-zen` and `linux-hardened` kernels have it), and internet access for packages.

## 🗂️ Where things live

| Path | Purpose |
|---|---|
| `/etc/sysctl.d/99-arch-security.conf` | Kernel hardening settings |
| `/etc/apparmor/parser.conf` | Profile cache settings for apparmor.d (backed up first) |
| `/etc/apparmor/modes` | apparmor.d mode: `default complain` or `default enforce` (backed up first) |
| `<file>.backup` | Original copy of every edited file |
| `/var/lib/arch-security/` | State and change manifest (used for undo) |
| `/var/log/arch-security.log` | Full log of every run |

## 🆘 Troubleshooting

**`ERROR: Conflicting profiles for brave defined in two files` (fixed in v3.2.1)**
Older versions used `aa-enforce`, which breaks with apparmor.d (it replaces some upstream profiles such as `brave` with its own `brave.apparmor.d`). v3.2.1 switches the mode the way apparmor.d itself does it: it writes `default enforce` / `default complain` to `/etc/apparmor/modes` and runs `aa-install --install`. It also repairs upstream placeholder profiles that older versions switched by mistake. Just run the new version: `./enable-security-for-arch-linux.sh --complain`.

> ⚠️ apparmor.d officially supports GNOME, KDE and XFCE. On other desktops (Hyprland/Omarchy, Sway, …) enforce mode may block programs or the desktop. The script asks before enforcing; undo with `--complain`.


- **Won't boot after the first reboot?** In the boot menu, press `e` (GRUB, systemd-boot or Limine) and delete the `lsm=… security=apparmor apparmor=1` part for that one boot. Then run `--rollback`.
- **An app misbehaves in enforce mode?** Run `--complain`, then check `sudo aa-log`.
- **Something failed?** Read `/var/log/arch-security.log`. Fix the cause and run the script again. Running it again is safe.

> ⚠️ **Before you run it:** try it on a VM or a snapshot first, and keep a live USB nearby for the first reboot. That's good practice for any script that touches your boot loader.

## 🔄 Script out of date? Refresh it with AI

Arch moves fast. If the **Last updated** date is old (6+ months), use any AI agent or chat (Claude, ChatGPT, Gemini, Copilot, a coding agent…) to bring the script up to date:

1. Download `enable-security-for-arch-linux.sh` from this repo.
2. Copy the prompt below.
3. Paste it into the AI and **attach the script file** (or paste its contents after the prompt).
4. Read what it changed, then test the new script on a **VM or snapshot** before using it on your real PC.

```text
You are a senior Linux security engineer and Bash expert. I am attaching
"enable-security-for-arch-linux.sh", a hardening script for Arch-based
systems (ufw firewall + AppArmor + apparmor.d + sysctl kernel hardening,
with backups, rollback and an AI-agent complain/enforce switch).

The script may be outdated. Today's date is: [WRITE TODAY'S DATE]

Your job: update it so it is correct for TODAY.

1. RESEARCH FIRST, using the newest official sources (search the web if you
   can; if you cannot, say so clearly and list what I must check by hand):
   - Every distro the script supports: Arch Linux, Omarchy, EndeavourOS,
     Manjaro, Garuda Linux. Check each distro's latest docs/release notes for
     changes to the default boot loader, kernel command line files, package
     names, init system and security defaults.
   - Distros the script refuses (CachyOS, Artix): check if the reason still
     holds. Do not add support unless it is clearly safe; explain your view.
   - Boot loaders: GRUB, systemd-boot (classic + UKI, kernel-install,
     /etc/kernel/cmdline, /etc/cmdline.d), Limine (limine-entry-tool,
     /etc/default/limine, /etc/limine-entry-tool.d drop-ins, "+=" syntax).
   - AppArmor: Arch Wiki "AppArmor" page, current lsm= order, kernel support,
     aa-status / aa-log / aa-enforce / aa-complain behaviour.
   - apparmor.d (github.com/roddhjav/apparmor.d): install method, AUR package
     name, build dependencies, signing key, /etc/apparmor/modes, aa-install,
     supported desktops, known conflicts, recommended parser.conf settings.
   - ufw, firewalld, sysctl hardening keys (Arch Wiki "Security" and
     "Sysctl"), pacman/keyring behaviour.
   For every change you make, cite the source (URL) and its date.

2. UPDATE THE SCRIPT
   - Keep every existing feature and safety net: dry-run, backups + manifest,
     automatic rollback on failure or crash, safe Ctrl+C/Ctrl+Z, --status,
     --disable, --rollback, --uninstall, the apparmor.d on/off question, the
     complain/enforce question and switches, SSH-port protection, firewalld
     detection, SELinux/container checks, idempotent re-runs.
   - Never enforce AppArmor automatically. Keep complain as the default.
   - Fix anything outdated or wrong; remove anything deprecated.
   - Bump the version number and the "vX.Y.Z changes" header.
   - Keep the friendly, beginner-safe messages.

3. CHECK YOUR WORK
   - The script must pass "bash -n" and shellcheck with no errors.
   - Walk through a fresh run, a second run, a reboot + run, --status,
     --disable and --uninstall on every supported distro and boot loader,
     and explain why each one works.
   - List anything you could not verify, and anything risky.

4. OUTPUT
   - The complete updated script in one code block (no placeholders, no
     "rest unchanged").
   - A changelog: what changed, why, and the source for each change.
   - An updated "Last updated" date and version for the README.

Be honest: if something is uncertain, say so instead of guessing.
```

> ⚠️ An AI can make mistakes. Always read the changelog, run `--dry-run` first, and test on a VM or snapshot before trusting a refreshed script on your real system.

## 🤝 Contributing

Found a bug or tested it on another setup? Issues and pull requests are welcome.
