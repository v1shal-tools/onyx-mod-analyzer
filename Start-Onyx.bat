@echo off
title Onyx Mod Analyzer
chcp 65001 >nul
mode con cols=100 lines=50 >nul 2>&1
if "%~1"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0OnyxModAnalyzer.ps1"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0OnyxModAnalyzer.ps1" -Path "%~1"
)
if errorlevel 1 pause
