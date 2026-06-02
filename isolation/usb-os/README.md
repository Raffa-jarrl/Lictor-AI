# Lictor Isolation OS — the bootable AI workspace

> The flagship. A USB stick you boot into a clean, isolated OS: the top AI
> clients, **your own accounts**, and **zero access to your company network**.
> Browser-only, one folder, ephemeral. Pull it out — no trace.

## What boots

1. **Egress lock** (`ai-egress-lock`) runs first — the whole OS can reach the
   public internet (so the browser talks to Claude / ChatGPT / Gemini) but every
   path to a private network (your LAN, domain, prod) is dropped. Air-gap by
   construction — the same red/black boundary we proved in the container red-zone.
2. **Kiosk** (`ai-kiosk`) launches Chromium full-screen on the **launcher**
   (`launcher.html`) — pick a vendor, sign in with your own account. No terminal,
   no file manager, no way out of the browser.
3. **Files** live only in `~/projects` (folder-per-project). The profile is
   ephemeral — wiped each boot unless you add a data partition.

## Build it

```bash
./build-iso.sh        # Debian live-build in Docker → out/lictor-isolation-os.iso
```

Needs Docker (you have it). ~15–40 min, ~1.5 GB first time.

## Flash + test (you have the stick)

```bash
# find your USB disk first: diskutil list   (be careful with the device!)
sudo dd if=out/lictor-isolation-os.iso of=/dev/diskN bs=4m && sync
# …or use balenaEtcher (safer, GUI)
```

Then boot the stick (hold the boot-menu key) and check:
- ✅ The launcher appears, you can open Claude/ChatGPT/Gemini and sign in
- ✅ Your company LAN is **unreachable** (no internal sites resolve/connect)
- ✅ Nothing writes outside `~/projects`; reboot = clean slate

## Status — v0.1 recipe

The isolation, kiosk, and launcher logic are real and correct. The **ISO build
itself is the step to run + iterate** — first live images almost always need a
boot-test cycle or two (driver/firmware, autologin timing, GPU). That's expected;
the recipe is the foundation, your USB stick is the test rig.

## Roadmap to "pay → download → boot"
- v0.2: per-vendor images (a Claude build, a Gemini build), persistent encrypted
  `~/projects`, signed image + checksum.
- Store: Stripe checkout → gated download of the signed `.iso`. (Wires up once the
  image boots clean on your stick.)
