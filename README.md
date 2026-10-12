<div align="center">

# 🛡️ Arch Linux Security Setup

**One script. A firewall, AppArmor and safe kernel hardening, with full undo.**

![Version](https://img.shields.io/badge/version-3.2.0-blue)
![Last updated](https://img.shields.io/badge/last%20updated-12%20Oct%202026-brightgreen)
![Shell](https://img.shields.io/badge/shell-bash-green)
![Init](https://img.shields.io/badge/requires-systemd-orange)

`Arch Linux` · `Omarchy` · `EndeavourOS` · `Manjaro` · `Garuda Linux`

</div>

> 📅 **Last updated: 12 October 2026** (v3.2.0)
>
> Arch and Arch-based distros change fast: boot loaders, packages and defaults move over time. If this date is more than about 6 months old, check the [commits](https://github.com/boss-defender/Enable-Security-Arch-Linux/commits/main) and [issues](https://github.com/boss-defender/Enable-Security-Arch-Linux/issues) before running, and test on a VM or snapshot first.

---

## ✨ What it does

Run it once and your system gets a solid security baseline that survives every reboot.

| Layer | What you get |
|---|---|
| 🔥 **Firewall (ufw)** | Blocks unrequested incoming connections and allows outgoing. A running SSH server is detected (including `sshd.socket`), and its port stays open with rate limiting so you can't lock yourself out. |
| 🧱 **AppArmor** | Installs AppArmor, adds the correct `lsm=` setting to your boot loader and enables it at every boot. Profiles start in **complain (log-only)** mode, so your desktop won't break. |
| 📚 **apparmor.d profiles** | Builds [apparmor.d](https://github.com/roddhjav/apparmor.d) (over 1500 profiles) from the AUR **automatically**, as your normal user, with no AUR helper needed. It checks the upstream signature and tunes the profile cache for a fast boot. |
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

> The script asks for `sudo` by itself. After the reboot, run it **once more** to finish the AppArmor profile setup.

## 🧰 Commands

| Command | What it does |
|---|---|
| *(no option)* / `--enable` | Install and enable everything |
| `--status` | Show what is installed and active |
| `--disable` | Turn everything **off** (nothing is uninstalled) |
| `--rollback` | Undo only the file edits, and switch off what it enabled |
| `--uninstall` | Turn off, restore the **original** files, remove the packages it installed |
| `--allow-ai-agent` | AppArmor profiles → **complain** (log only) |
| `--disable-ai-agent` | AppArmor profiles → **enforce** (block) |
| `-y`, `--yes` | Don't ask questions (safe defaults) |
| `--dry-run` | Preview only |
| `--force-ufw` | Replace an active firewalld with ufw (firewalld config is backed up) |
| `--no-aur` | Skip building apparmor.d from the AUR |
| `--no-color`, `-h`, `-V` | Plain output, help, version |

## 🤖 AI agents (every supported system)

Whether you're on Arch, Manjaro, Omarchy, EndeavourOS or Garuda, AI agents such as coding assistants often need to edit system files, install packages or change configs. AppArmor in **enforce** mode can block the programs it has profiles for, which makes an agent's work fail in confusing ways.

The **AI-agent switch** lets you choose:

```bash
# Let agents work freely: AppArmor only LOGS what it would block (default)
./enable-security-for-arch-linux.sh --allow-ai-agent

# Lock it down again: AppArmor BLOCKS policy violations
./enable-security-for-arch-linux.sh --disable-ai-agent

# See which mode you're in
./enable-security-for-arch-linux.sh --status
```

| Mode | Best for | Effect |
|---|---|---|
| 🟢 **Allowed** (complain) | Letting AI agents configure the system | Violations are logged, never blocked |
| 🔴 **Blocked** (enforce) | Daily use, maximum protection | Profiled programs can't step outside their rules |

> **Honest note:** AppArmor only affects programs that have a profile. The switch doesn't give an agent root, and it doesn't confine an agent that has no profile. System-level edits still need `sudo`, so keep an eye on what your agent runs. The firewall and kernel hardening stay on in both modes.

**Tip:** switch to *allowed* before a big agent session, then back to *blocked* when it's done.

## 🖥️ Supported systems

| System | Status |
|---|---|
| Arch Linux · Omarchy · EndeavourOS · Manjaro · Garuda Linux | ✅ Supported |
| Other Arch-based distros (`ID_LIKE=arch`) | ⚠️ Asks before continuing |
| CachyOS | ⛔ Refused (AppArmor has caused boot problems with some CachyOS kernels) |
| Artix | ⛔ Refused (no systemd) |

**Requirements:** systemd, pacman, a kernel with AppArmor support (the stock `linux`, `linux-lts`, `linux-zen` and `linux-hardened` kernels have it), and internet access for packages.

## 📚 About apparmor.d

The script builds **apparmor.d** from the AUR on its own: it clones the package, builds it as the user who ran the script, and installs it with pacman. The build takes a few minutes. `go` and `just` are only needed for the build, so they're removed again afterwards. `base-devel` and `git` stay installed.

- Run the script as your **normal user**, not from a root shell. It asks for `sudo` itself.
- On Garuda, a prebuilt apparmor.d from your repos is used when one is available.
- Upstream officially supports GNOME, KDE and XFCE. On Hyprland (Omarchy) it stays safe in complain mode; test well before enforcing.
- Prefer to skip it? Use `--no-aur`.

## 🗂️ Where things live

| Path | Purpose |
|---|---|
| `/etc/sysctl.d/99-arch-security.conf` | Kernel hardening settings |
| `/etc/apparmor/parser.conf` | Profile cache settings for apparmor.d (backed up first) |
| `<file>.backup` | Original copy of every edited file |
| `/var/lib/arch-security/` | State and change manifest (used for undo) |
| `/var/log/arch-security.log` | Full log of every run |

## 🆘 Troubleshooting

- **Won't boot after the first reboot?** In the boot menu, press `e` (GRUB, systemd-boot or Limine) and delete the `lsm=… security=apparmor apparmor=1` part for that one boot. Then run `--rollback`.
- **An app misbehaves in enforce mode?** Run `--allow-ai-agent`, then check `journalctl -k | grep apparmor`.
- **Something failed?** Read `/var/log/arch-security.log`. Fix the cause and run the script again. Running it again is safe.

> ⚠️ **Before you run it:** try it on a VM or a snapshot first, and keep a live USB nearby for the first reboot. That's good practice for any script that touches your boot loader.

## 🤝 Contributing

Found a bug or tested it on another setup? Issues and pull requests are welcome.
