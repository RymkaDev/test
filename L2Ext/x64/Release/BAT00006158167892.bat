@echo off
ml64.exe /c /nologo /Fo "x64\Release\ItemDistribution.obj" /Zi "c:\Users\AHSGI\Desktop\interlude\interlude\L2Ext\ItemDistribution.asm"

if errorlevel 1 goto VCReportError
goto VCEnd
:VCReportError
echo Project : error PRJ0019: A tool returned an error code from "Performing Custom Build Step"
exit 1
:VCEnd