' 以隐藏窗口方式启动守护脚本 run-loop.bat
Dim fso, shell, dir
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.Run "cmd /c """ & dir & "\run-loop.bat""", 0, False
