# Tunnel Guard

Tunnel Guard is a Windows 11 desktop app for a system-wide VPN kill switch and split routing. It works with v2rayN and its Mihomo core. Import and manage your VPN profile in v2rayN, then use Tunnel Guard to check readiness, control the firewall, and edit routing rules.

## Install on Windows

You need Windows 11 x64, [v2rayN for Windows](https://github.com/2dust/v2rayN/releases) with Mihomo, and an active VPN profile. If you are setting up v2rayN for the first time, extract a Windows build with the cores bundled, import your profile, and connect in v2rayN. Changing the kill switch requires Windows administrator approval.

1. Open [GitHub Releases](https://github.com/ed1ct7/tunnel-guard/releases) and download the `Tunnel Guard_*_x64-setup.exe` asset. If the releases page has no installer, follow [Build from source](#build-from-source).
2. Run the setup EXE and open **Tunnel Guard** from the Start menu. The installer includes the desktop app and the `guardctl.exe` command-line tool.
3. Keep your existing v2rayN session running. In v2rayN, use a Mihomo profile in **Rule** mode with **Enable TUN** turned on. The Mihomo mixed proxy and HTTP controller must be reachable on IPv4 loopback and owned by the same Mihomo process. Tunnel Guard reads the controller port and optional key from v2rayN’s generated Mihomo config.
4. In **Connection** (**Подключение**), choose **Auto-detect** (**Найти автоматически**). Verify the path to `v2rayN.exe`, the exact Windows TUN adapter name, and the local mixed proxy port. Choose **Save connection** (**Сохранить подключение**). You can fill in those values manually if v2rayN is running elevated and Windows hides its executable path.
5. In **Connection**, choose a **Protection method** (**Способ защиты**) and save the connection. **Local Group Policy** is the default for existing settings. **Windows Filtering Platform (WFP)** is the preview method for Windows Home. Switch methods while protection is off.
6. In **Overview** (**Обзор**), review **Protection readiness** (**Готовность к защите**). Once the checks pass, select **Enable protection** (**Включить защиту**) and approve the Windows administrator prompt. Confirm that the app reports protection on and shows which method is active.

If the app cannot open because WebView2 is missing, install the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) and reopen Tunnel Guard.

### Firewall behavior and recovery

- With protection on, ordinary applications use the selected TUN adapter. The policy allows Mihomo to reach the VPN server and permits DHCPv4. Applications lose internet access if the TUN adapter disappears. While Mihomo is running, its `DIRECT` rules still allow traffic to exit directly.
- The **Local Group Policy** method applies the Windows Firewall policy and saves the previous profile settings in `%LOCALAPPDATA%\TunnelGuard\original-policy.xml`. It requires Windows to enforce Local Group Policy firewall settings. On the Windows 11 Home system tested, Windows ignored those settings and activation rolled back. See [Microsoft’s Windows configuration tools guide](https://support.microsoft.com/en-au/windows/experience/system-configuration-tools-in-windows?facet1=startup) for edition availability.
- The **WFP preview** uses its own boot-time outbound filters and persistent IPv4 and IPv6 filters for Windows host traffic. Windows Firewall can still block traffic allowed by the WFP exceptions. If Windows recreates the TUN adapter with a new identity, WFP keeps blocking direct traffic. To update the adapter binding, disable protection, confirm that the new TUN is connected, and enable protection again. Test VPN loss, reboot, and guest networking in an isolated environment before relying on this preview.
- Activation compares the public IPv4 address reached over normal HTTPS with the address reached through Mihomo’s local proxy. It queries ipify, with icanhazip as a fallback if either request fails. It then checks whether a previously reachable direct IPv4 test route is blocked while VPN HTTPS still works. WFP also checks a direct IPv6 route when there is a non-TUN IPv6 gateway.
- Closing the window hides it in the notification area. Quitting Tunnel Guard leaves the firewall rules active. Use **Disable protection** (**Выключить защиту**) and approve the administrator prompt to restore the previous policy. Do this before uninstalling the app or changing VPN clients, adapters, or ports.
- If the GUI is unavailable, run `guardctl.exe protection disable --confirm` from an administrator PowerShell in the installation directory. It removes the active Tunnel Guard protection, including an incomplete WFP policy after a failed activation.
- If the protection check reports a policy conflict, inspect existing outbound rules in Local Group Policy before trying again. If the HTTPS check fails, verify that ordinary traffic and the mixed proxy use the same VPN exit on the verification request.

## Split routing

Back up your v2rayN configuration before editing rules. Turn on **Enable Mixin Content** in v2rayN’s Mihomo settings to use the rules that Tunnel Guard saves.

In **Routing** (**Маршрутизация**), add a domain suffix, executable name, or full executable path and choose a route. The saved rules go into `prepend-rules` in `guiConfigs/Mixin.yaml` inside the selected v2rayN folder.

- **Profile routing** keeps the profile’s routing for traffic outside your rules.
- **Only selected traffic through the VPN** (**Только выбранное через VPN**) sends unmatched traffic directly while Mihomo is running, even with the kill switch on. Add at least one rule targeting a VPN exit before selecting this mode.

Choose **Apply now** (**Применить сейчас**) when the saved rules differ from the running rules. Tunnel Guard sends the updated rules to Mihomo in place. If the generated config is stale, the app asks you to refresh it through v2rayN before applying changes.

## Command-line usage

Run these commands from the installation directory. `guardctl` works with the same settings as the desktop app and returns JSON on stdout. Failures report `ok: false` and a nonzero exit code.

```powershell
.\guardctl.exe status
.\guardctl.exe doctor
.\guardctl.exe settings get
.\guardctl.exe rules list
.\guardctl.exe rules active
.\guardctl.exe rules targets
.\guardctl.exe core state
```

Set the connection explicitly if auto-detection needs help. Substitute your local values.

```powershell
.\guardctl.exe settings set --client-path 'C:\Apps\v2rayN\v2rayN.exe' --adapter Meta --proxy-port 10808
```

Select the protection method with `guardctl settings set --protection-backend wfp` or `guardctl settings set --protection-backend group-policy`. The `status` response reports `active_backend` when it can identify the active method.

For routing changes, use `rules add` or `rules remove` with `domain`, `process-name`, or `process-path`. `rules add` defaults to `DIRECT`. Pass `--via` with a destination from `rules targets` to route through a VPN exit. Use `rules mode vpn-only` or `rules mode profile` to switch the default route. Run `core reload` to apply saved rules and `rules active` to verify what Mihomo loaded.

For a bulk edit, save the output of `guardctl config` as UTF-8 JSON in `snapshot.json`, prepare `rules.json` as an array of rule strings, then run `guardctl rules replace --file rules.json --expected snapshot.json`. The snapshot prevents overwriting concurrent changes.

`protection enable`, `protection disable --confirm`, and `protection clean-legacy` require an administrator console. Run `guardctl --help` to see all commands.

### Process groups

Use **Processes** (**Процессы**) to create groups by executable name or path, Windows package family, command-line fragment for a specific executable, or exact service name. Groups can include other saved groups. Preview the matches before stopping a group. Stopping a group can also close child processes. Service control depends on Windows permissions.

Use **Stop** (**Завершить**) to close the processes and services in a group. To restrict network access separately, add the applications with **Full path** selectors and choose **Block network** (**Заблокировать сеть**). Tunnel Guard requests administrator approval and installs IPv4 and IPv6 WFP filters for the specified executables. The network block stays active until you choose **Restore network** (**Вернуть сеть**). Restore access before modifying or deleting the group or uninstalling Tunnel Guard.

Full-path filters cover the listed executables. Add dedicated helpers as separate paths if you need to block them as well. An application update can move its binaries to a different path. Check the paths after updating. Process-name, argument, package-family, and service selectors still control which processes and services the stop action targets. The network feature is independent of the system kill switch and does not isolate files, local IPC, network requests brokered by other executables, or traffic inside a virtual machine.

Groups are stored in `%LOCALAPPDATA%\TunnelGuard\process-groups.json`. The CLI supports `processes list`, `processes set --file groups.json --expected previous.json`, `processes preview <group-id>`, and `processes stop <group-id> --confirm`. Use the previous UTF-8 JSON output of `processes list` as `previous.json`. Exit code `2` from `processes stop` means some targets remain active.

Check a group with `guardctl processes network <group-id>`. From an administrator PowerShell, use `guardctl processes network <group-id> block --confirm` to apply the group's network filters, or `guardctl processes network <group-id> unblock` to remove them.

## Build from source

Build on x64 Windows with [Node.js 24](https://nodejs.org/), [Rust stable with the MSVC toolchain](https://rustup.rs/), and the Visual Studio **Desktop development with C++** workload, including MSVC and a Windows SDK. Install WebView2 for testing. See [Tauri’s Windows prerequisites](https://v2.tauri.app/start/prerequisites/) for toolchain setup.

```powershell
git clone https://github.com/ed1ct7/tunnel-guard.git
cd tunnel-guard
npm ci
npm run tauri -- build
Get-ChildItem .\src-tauri\target\release\bundle\nsis\*-setup.exe
```

The final command lists the [NSIS installer](https://v2.tauri.app/distribute/windows-installer/) to install or share. For a local unpackaged build, run `npm run tauri -- build --no-bundle`. The runnable binaries are `src-tauri/target/release/tunnel-guard.exe` and `src-tauri/target/release/guardctl.exe`.

Run `npm run dev` to develop the browser UI against a mock backend. Use the scenario switcher or open the Vite URL with `?mock=off-ready`, `?mock=tun-down`, or `?mock=rules-pending`.

```powershell
npm run typecheck
npm run lint
npm run format:check
cargo fmt --manifest-path .\src-tauri\Cargo.toml --check
cargo clippy --manifest-path .\src-tauri\Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path .\src-tauri\Cargo.toml --locked
```

## Publish the installer on GitHub

1. For a new version, update the version in `package.json`, `package-lock.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and `src-tauri/tauri.conf.json`. Commit and push the source, then build and test the installer from that commit.
2. On the repository’s **Releases** page, choose **Draft a new release**. Select or create the matching version tag and target the commit used to build the installer. For a preview build, use a tag such as `v0.6.0-preview.1` and mark the release as a pre-release.
3. Attach the `*-setup.exe` from `src-tauri/target/release/bundle/nsis/` to the draft. Use the setup file so users receive the Start menu entry and both binaries. If the installer is unsigned, mention that in the release notes so users know to expect a possible Windows warning.
4. To let users verify the download, run the command below and paste the installer’s SHA-256 hash into the release notes. Publish the release and check that its installer is listed under **Assets**. See [Managing releases on GitHub](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository).

```powershell
Get-ChildItem .\src-tauri\target\release\bundle\nsis\*-setup.exe | Get-FileHash -Algorithm SHA256
```

## Repository layout

- `src/` contains the React and Vite frontend.
- `src-tauri/` contains the Rust/Tauri desktop app, the `guardctl` CLI, and the Windows PowerShell backend.
- `legacy/` contains archived PowerShell and .NET prototypes.
