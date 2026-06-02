#!/bin/bash
# build-iso — build the Lictor Isolation OS bootable image (Debian live-build, in Docker).
# Output: out/lictor-isolation-os.iso  →  flash to a USB stick (dd / balenaEtcher) → boot.
#
# The ISO boots straight into a kiosk browser on the Lictor launcher, with the
# whole OS network-locked to the public internet only (no LAN/domain). Files
# live only in ~/projects. Ephemeral — nothing persists unless you add a data
# partition.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/out"

command -v docker >/dev/null || { echo "docker required"; exit 1; }
echo "[build-iso] building in a Debian live-build container — ~15-40 min, ~1.5 GB download…"

docker run --rm --privileged -v "$HERE":/work -w /build debian:bookworm bash -euo pipefail -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq live-build ca-certificates >/dev/null

  lb config --distribution bookworm --architectures amd64 \
            --binary-images iso-hybrid --debian-installer none \
            --archive-areas "main contrib non-free non-free-firmware"

  mkdir -p config/package-lists
  printf "xserver-xorg\nxinit\nopenbox\nchromium\niptables\nnetwork-manager\ndbus-x11\nsudo\n" \
    > config/package-lists/lictor.list.chroot

  mkdir -p config/includes.chroot/opt/lictor config/includes.chroot/usr/local/bin
  cp /work/includes/launcher.html  config/includes.chroot/opt/lictor/launcher.html
  cp /work/includes/ai-egress-lock config/includes.chroot/usr/local/bin/ai-egress-lock
  cp /work/includes/ai-kiosk       config/includes.chroot/usr/local/bin/ai-kiosk
  chmod +x config/includes.chroot/usr/local/bin/ai-*

  # autologin user "user" on tty1
  mkdir -p config/includes.chroot/etc/systemd/system/getty@tty1.service.d
  printf "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin user --noclear %%I \$TERM\n" \
    > config/includes.chroot/etc/systemd/system/getty@tty1.service.d/autologin.conf

  # on login: lock egress, then launch X → kiosk
  mkdir -p config/includes.chroot/home/user
  printf "sudo /usr/local/bin/ai-egress-lock 2>/dev/null || true\n[ -z \"\$DISPLAY\" ] && [ \"\$(tty)\" = \"/dev/tty1\" ] && exec startx /usr/local/bin/ai-kiosk\n" \
    > config/includes.chroot/home/user/.bash_profile

  # create the user + passwordless sudo just for the egress lock
  mkdir -p config/hooks/live
  printf "#!/bin/sh\nid user >/dev/null 2>&1 || useradd -m -s /bin/bash user\npasswd -d user || true\necho \"user ALL=(ALL) NOPASSWD: /usr/local/bin/ai-egress-lock\" > /etc/sudoers.d/lictor\n" \
    > config/hooks/live/0100-user.hook.chroot
  chmod +x config/hooks/live/0100-user.hook.chroot

  lb build
  cp live-image-amd64.hybrid.iso /work/out/lictor-isolation-os.iso
'

echo "[build-iso] ✓ done → $HERE/out/lictor-isolation-os.iso"
echo "  flash:  sudo dd if=$HERE/out/lictor-isolation-os.iso of=/dev/diskN bs=4m   (or balenaEtcher)"
echo "  then boot the stick, pick a vendor, sign in — and confirm your LAN is unreachable."
