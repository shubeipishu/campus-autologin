Dim shell, cmd
Set shell = CreateObject("WScript.Shell")
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & _
      Replace(WScript.ScriptFullName, "run-campus-login-hidden.vbs", "run-campus-login.ps1") & """"
' 0 = hidden window, False = do not wait
shell.Run cmd, 0, False
