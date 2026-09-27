# Shortcut Virus Remover

A small Windows tool that cleans the classic USB "shortcut virus" off drives and PCs.

You plug a pendrive into some random PC, and next thing you know every folder on it is hidden and replaced with fake shortcuts. That is this worm. This tool finds it, quarantines the files, unhides your folders and repairs what the worm breaks (Defender settings, startup entries, scheduled tasks).

Written in plain C# / WinForms. The only requirement is .NET Framework 4.x, which Windows 10 and 11 already ship with, so nothing else needs to be installed.

## What it detects

- `sysvolume` worm folders and `uXXXXXX.vbs/.bat` droppers on drive roots
- Fake shortcuts (.lnk) that run scripts instead of opening your folders
- Folders hidden with the system attribute
- SubDir / wsvcz payload folders under System32
- Invisible-character file names and fake double extensions (photo.jpg.exe)
- autorun.inf droppers on USB drives
- .scr stagers dropped in the Startup folder
- Suspicious scheduled tasks, registry run keys and running processes
- Defender exclusions the malware added for itself, and real-time protection it turned off
- Known malware files by SHA256 (samples from the September 2026 outbreak)

## Features

- Quick scan, full scan, or scan any single folder
- Real-time protection: USB drives are checked the moment they are plugged in
- Quarantine with restore, nothing is deleted right away
- One-click fix for everything it finds (asks for admin only when it is really needed)
- Unhide tool for folders the worm locked away
- A text report for every scan
- Lives in the system tray, scans run in the background

## Build

The app builds with the C# compiler that ships with Windows itself:

```
build.bat             -> dist\ShortcutVirusRemover.exe
build-installer.bat   -> dist\ShortcutVirusRemover-Setup.exe
```

The installer needs WiX 3.14. Put its binaries in `tools\wix`, or install WiX and make sure `candle.exe` is on PATH.

## Notes

- This is a focused remover for this worm family, not a general antivirus. Keep Defender on.
- Quarantined files and logs live in `%LOCALAPPDATA%\ShortcutVirusRemover`.
- For a headless scan: `ShortcutVirusRemover.exe --console --full`, add `--autoclean` to also clean what it finds.

## License

MIT, see LICENSE.
