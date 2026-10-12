# PolarisSentinel

Polaris Sentinel Project aims to create a prototype that automatically detects and response to network threats using AI.

The system continuously monitors network traffic, extracts relevant features and applies a pretrained AI model to determine whether the traffic is benign or malicious. 
The inference results are then passed to a policy decision engine governed by administrator defined rules to decide if source IP address or port should be blocked. Administrators can view real-time network traffic and AI-generated results, configure policies, and manage rules through web dashboard management console. 

The goal is to allow the AI continually to reinforce the organization’s security posture while keeping humans in the loop. 

The architecture follows a detection, decision, response and enforcement model. Given the constraints of a capstone timeline. 

The prototype narrows its focus to inbound traffic and targets three of the most common and high impact attack types observed in this traffic: Denial-of-Service (DoS), port scanning, and brute-force login attempts on Windows-based environment

## Getting Started

### Prerequisites

- .NET 10 SDK (Windows)
- SQL Server or SQL Server LocalDB
- Npcap / WinPcap driver (required for packet capture)
- Administrator privileges (needed for packet capture and Windows Firewall rules)

### Run locally

```powershell
dotnet run --project PolarisSentinel.Web
```

The dashboard is served at `http://localhost:5180`.

### First login

The initial administrator account is provisioned automatically on first startup by `SentinelDbInitializer`
(see `PolarisSentinel.Data/Data/SentinelDbInitializer.cs`).

| Field    | Value                 |
|----------|-----------------------|
| URL      | `http://localhost:5180/Account/Login` |
| Username | `admin`               |
| Password | `Admin@123`           |

The default password is configured under `AdminSeed:Password` in `PolarisSentinel.Web/appsettings.json`.
On first sign-in the account is flagged `MustChangePassword`, so you are forced to set a new password
before the dashboard becomes reachable.

> **Security note:** `Admin@123` is a development/demo default only. For any real deployment, remove
> `AdminSeed:Password` from `appsettings.json` and supply it through an environment variable or
> user-secrets instead:
>
> ```powershell
> # Environment variable (double underscore maps to the ':' separator)
> [Environment]::SetEnvironmentVariable("AdminSeed__Password", "<strong-password>", "Machine")
>
> # Or user-secrets during development
> dotnet user-secrets set "AdminSeed:Password" "<strong-password>" --project PolarisSentinel.Web
> ```
>
> An environment variable takes precedence over `appsettings.json`. If `AdminSeed:Password` is empty
> and no environment variable is set, no admin account is created and the app logs
> `AdminSeed:Password is not configured. Skipping admin creation.`

### Publishing

```powershell
dotnet publish PolarisSentinel.Web/PolarisSentinel.Web.csproj -c Release -r win-x64 --self-contained false -o C:\PolarisSentinel
```

Run the produced `PolarisSentinel.Web.exe` **as administrator**. In desktop mode a tray icon appears
(double-click it to open the dashboard); when installed as a Windows service the tray icon is skipped
and the dashboard is reached through the browser.

To install as a Windows service:

```powershell
sc.exe create PolarisSentinel binPath= "C:\PolarisSentinel\PolarisSentinel.Web.exe" start= auto
sc.exe start PolarisSentinel
```

> Windows services run in session 0 and do **not** inherit per-user environment variables. Set
> `AdminSeed__Password` at the machine level, or keep it in the published `appsettings.json`, so the
> service can read it.

Before enabling real enforcement, consider setting `Firewall:DryRun` to `true` in `appsettings.json`
to log decisions without applying firewall rules. It can be toggled at runtime from the Settings page.

