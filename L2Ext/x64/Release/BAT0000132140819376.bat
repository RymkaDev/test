@echo off
ml64.exe /c /Cx  /nologo /Fo"x64\Release\iob.asm.obj" /W3 /Zi /errorReport:prompt  /Ta.\iob.asm
if errorlevel 1 goto VCReportError
goto VCEnd
:VCReportError
echo Project : error PRJ0019: Una herramienta devolvi¢ un c¢digo de error de "Assembling..."
exit 1
:VCEnd