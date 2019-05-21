@echo oFF
Mode 78,23
color 0a
echo.
cd %CD%
net session >nul 2>&1

:TOPO
@TITLE Script Atualiza Projeto GitHub

cls
 echo.
 echo      ฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐ
 echo      ฐฐ                                                               ฐฐ
 echo      ฐฐ ษอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออป ฐฐ
 echo      ฐฐ บ             SCRIPT ATUALIZA PROJETO GITHUB                บ ฐฐ
 echo      ฐฐ ศอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออผ ฐฐ
 echo      ฐฐ                                                               ฐฐ
 echo      ฐฐ                                                               ฐฐ
 CECHO      ฐฐ                                              {blue}By: MARDONIO{#}     ฐฐ{\n}
 echo      ฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐ
 echo.

git add *
git status
set COMMIT=
set /p COMMIT=Quais foram as alteracoes feitas no projeto:

git commit -a -m "%COMMIT%"
echo.
echo.
echo.
echo.
git push
echo.
echo.
echo.
echo. Atualizacao concluida!

@PAUSE