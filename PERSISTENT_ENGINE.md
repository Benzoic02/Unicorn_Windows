# Persistent UniWind engine

The injection engine normally runs for the lifetime of the UniWind UI. To keep
mod effects active after closing the UI, install the optional Windows service
from an elevated PowerShell window:

```powershell
Set-Location 'C:\path\to\UniWind'
.\windhawk-ui.exe --install-engine-service
```

Close any running UniWind UI before installation. The PowerShell window must be
opened with **Run as administrator** and its UAC prompt approved. The service is
installed as an automatic-start LocalSystem service; its executable and engine
are copied under `%ProgramFiles%\UniWind`, rather than being run from the
portable folder. It scans for new processes once per second and handles Windows
session logon/logoff notifications. The Service Control Manager restarts the
service after a failed exit.

The service uses the portable installation's existing `AppData` folder for
settings and mods. Keep the portable folder at its current location while the
service is installed. Safe Mode is read from the same settings file; enabling it
stops the service's engine session.

To remove the service, run this from an elevated PowerShell window while in the
same portable folder:

```powershell
.\windhawk-ui.exe --uninstall-engine-service
```

The management commands currently support x64 portable installations.
