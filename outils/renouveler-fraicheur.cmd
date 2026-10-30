@echo off
rem Tache planifiee : signe la fraicheur de l'index du registre et la pousse. Usage : renouveler-fraicheur.cmd CLE_FRAICHEUR [CHEMIN_DE_PYTHON]
rem La cle de fraicheur est a faible pouvoir (jamais la racine). Le journal est .journal-fraicheur.log a la racine du depot (ignore par git).
cd /d "%~dp0.."
set LOG=%CD%\.journal-fraicheur.log
set PY=%~2
if "%PY%"=="" set PY=python
echo ===== %DATE% %TIME% >> "%LOG%"
"%PY%" outils\fraicheur.py renouveler --cle "%~1" >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%
