@echo off
ml64.exe /c /Cx  /nologo /Fo"x64\Release\skill_enchant.asm.obj" /W3 /Zi /errorReport:prompt  /Ta.\skill_enchant.asm
if errorlevel 1 goto VCReportError
goto VCEnd
:VCReportError
echo Project : error PRJ0019: A tool returned an error code from "Assembling..."
exit 1
:VCEnd