# Author: Foster anonymous
# Date: 16/04/2019,
# PowerShell script para automatizar registro de ponto


#variaveis para preencher o formulario do ponto
$url_ponto = 'http://portalhoras.stefanini.com/'
$funcao = 1
$usuario = 1003246
$senha = '039'

# inicializando o browser

$ie = new-object -com internetExplorer.Application
$ie.visible = $true
$ie.navigate($url_ponto)
while ($ie.busy) {
 start-sleep -milliseconds 1000 #aguarda 1 segundo antes de continuar
 }

$captcha = (Read-Host "Digite o captcha ")

# preenchendo o formulário
($ie.document.getElementsByName("func_relogio_8002") | select -first 1).value = $funcao
($ie.document.getElementsByName("userName_relogio_8002") | select -first 1).value = $usuario
($ie.document.getElementsByName("password_relogio_8002") | Select-Object -Unique ).Value = $senha
($ie.document.getElementsByName("insert_captcha_8002") | Select-Object -Unique).Value = $captcha


# definindo o horário para marcação
$hora_definida = Read-Host "Insira um horário (no formato hh:mm:ss)"

do { 
cls
$falta_minutos = [math]::round(((get-date $hora_definida) - (get-date)).TotalMinutes,2)
"Faltam $falta_minutos minutos para o horário definido."
Start-Sleep -seconds 5

} until (((get-date $hora_definida) - (get-date)).TotalSeconds -lt 0 ) 

#click no botão Marcação
($ie.Document.getElementById("ext-gen61") | select -first 1).click()
