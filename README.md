A few practical notes

If you want the most conservative behavior, run it once with -WhatIf.
If you want the most aggressive cleanup, use:
PowerShellUninstall-Rapid7InsightAgentHardended -PurgeInstallerProductKeys -Confirm:$falseShow more lines

If your environment uses an uninstall token, include -UninstallToken.

If you want, I can also give you a second version tailored for Intune / RMM deployment with:

cleaner exit codes,
reduced console noise,
explicit 3010 reboot handling, and
an RMM-friendly one-line result summary.
