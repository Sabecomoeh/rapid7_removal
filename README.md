A few practical notes

If you want the most conservative behavior, run it once with -WhatIf.

If you want the most aggressive cleanup, use:

PowerShellUninstall-Rapid7InsightAgentHardended -PurgeInstallerProductKeys -Confirm:$false

If your environment uses an uninstall token, include -UninstallToken.

