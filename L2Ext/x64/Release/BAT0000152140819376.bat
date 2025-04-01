@echo off
ml64.exe /c /nologo /Fo "x64\Release\pck.obj" /Zi "i:\Servidores\L2OFF_INTERLUDE\Extender\L2Ext\pck.asm"

if errorlevel 1 goto VCReportError
goto VCEnd
:VCReportError
echo Project : error PRJ0019: Una herramienta devolvi¢ un c¢digo de error de "Realizando paso de generaci¢n personalizada"
exit 1
:VCEnd