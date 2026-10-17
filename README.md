# GodEx

GodEx is a Windows desktop app for managing a WireGuard tunnel, with a custom dark glass-inspired WPF interface.

## What currently works in the code

- Import and basic validation of a user-supplied WireGuard `.conf` file.
- Locate the official WireGuard for Windows executable in standard Program Files folders.
- Request Windows administrator approval and call WireGuard's tunnel service install/uninstall commands.
- Windows x64 self-contained EXE workflow using GitHub Actions.

## Important limits

GodEx does **not** provide a VPN server, account, endpoint, or configuration. You must obtain a valid WireGuard configuration from a VPN provider or operate your own server. The app does not upload the configuration, but the file contains a private key: keep it private and never commit it to GitHub.

Starting a tunnel does not prove that traffic reaches a particular service. Codex availability depends on OpenAI's current supported regions, account eligibility, network conditions, and applicable terms and laws. GodEx cannot guarantee Codex access in Russia, and it does not spoof account region or change account eligibility.

## Build

```powershell
dotnet publish GodEx.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

Or open **Actions → Build GodEx for Windows → Run workflow** and download the `GodEx-Windows-x64` artifact after a successful run.
