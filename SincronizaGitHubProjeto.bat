@echo oFF
Mode 78,23
color 0A
echo.
cd %CD%
net session >nul 2>&1

:TOPO
@TITLE Sincroniza Projeto com o GitHub

cls
 echo.
 echo      ฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐ
 echo      ฐฐ                                                               ฐฐ
 echo      ฐฐ ษอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออป ฐฐ
 echo      ฐฐ บ        SCRIPT SINCRONIZA PROJETO COM O GITHUB             บ ฐฐ
 echo      ฐฐ ศอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออผ ฐฐ
 echo      ฐฐ                                                               ฐฐ
 echo      ฐฐ                                                               ฐฐ
 CECHO      ฐฐ                                              {01}BY: MARDONIO{#}     ฐฐ{\n}
 echo      ฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐฐ
 echo.

CECHO {0C}Sincronizando, aguarde...{#}{\n}
git pull


@PAUSE