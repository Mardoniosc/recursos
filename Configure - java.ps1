<#
	.NOTES
	===========================================================================
	 Created on:   	29/06/2018
	 Created by:   	p787958 - Lucas Bonfim de Oliveira Lima
	 Organization: 	Caixa Econômica Federal / Stefanini
	 Filename:     	SISAG - Agente - Configure.ps1
	===========================================================================
	.DESCRIPTION
		Script para configuração do Agente SISAG.
    .UPDATES
        24/07/2018 - p787958 - Adicionado função $ServiceDesk.
        09/08/2018 - p787958 - Adicionado função GetProgram.
#>

# Suprime as mensagens de erro.
$ErrorActionPreference = 'SilentlyContinue'

# Busca o caminho do servidor passado como parâmetro e carrega o arquivo de configuração.
$caminho_scripts = $args[0]
."$caminho_scripts\Config\ServiceDesk.ps1" | Out-Null

# Valida o acesso do funcionário ao banco de dados.
$ServiceDesk._CHECKUSER()

# Define a data e hora de início, produto selecionado e o tipo de pacote relacionado ao produto.
$inicio = Get-Date
$produto = 'SISAG - Agente'
$pacote = 'Configuração'

# Inicia o processo de log.
$ServiceDesk._LOGSTART($produto, $pacote, $inicio)
$historico = "Iniciando procedimentos..."
$ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)

$UNINSTALL_PATHS = @( 
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

Function GetProgram ($Name) {
    foreach ($UNINSTALL in $UNINSTALL_PATHS) {
        if (Test-Path -Path $UNINSTALL) {
            $SubKeys = Get-ItemProperty -Path "$UNINSTALL\*"
            foreach ($SubKey in $SubKeys) {
                if ($SubKey.DisplayName -like "*$Name*") {
                    $SubKey.DisplayName
                }
            }
        }
    }
}

# Pesquisa na lista de programas para ver se o Java está instalado.
$Java8u31 = GetProgram -Name 'Java 8 Update 31'
if ($Java8u31 -eq 'Java 8 Update 31') {
    
    # Pesquisa na lista de programas para ver se o SISAG foi instalado.
    $AgenteSisag = GetProgram -Name 'Sisag Agente'
    if ($AgenteSisag -eq 'Sisag Agente') {
        
        # Finaliza os processos que podem interromper a execução.
        Get-Process -Name 'browsercore32'  | Stop-Process -Force
        Get-Process -Name 'java'           | Stop-Process -Force
        Get-Process -Name 'jawaw'          | Stop-Process -Force
        Get-Process -Name 'javaws'         | Stop-Process -Force
        Get-Process -Name 'SisagNavegador' | Stop-Process -Force
        Get-Process -Name 'msiexec'        | Stop-Process -Force
        Get-Process -Name 'WmiPrvSE'       | Stop-Process -Force

        # Concede permissão ao grupo Usuários
        $historico = "Atualizando permissões..."
        $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
        C:\Windows\System32\icacls.exe 'C:\SISTEMAS\SISAG' /grant Usuários:'(OI)(CI)F' /T | Out-Null

        # Define o arquivo a ser buscado e executa o script de localização de arquivos.
        $arquivo = 'cacerts'.ToUpper()
        $historico = "Buscando arquivo $arquivo..."
        $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
        $FTP = $ServiceDesk._SERVERS('FTP')
        $caminho = "$FTP\CETEC\Celula_Intranet\Certificacao_Digital\cacerts"

        if (Test-Path -Path $caminho) {
                                        
            # Exclui o arquivo CACERTS do computador local.
            if (Test-Path -Path 'C:\Program Files (x86)\Java\jre1.8.0_31\lib\security\cacerts') {
                Remove-Item -Path 'C:\Program Files (x86)\Java\jre1.8.0_31\lib\security\cacerts' -Force
            }

            # Obtém a HASH do arquivo no servidor.
            $ServerHash = $ServiceDesk._GETHASH($caminho)
                    
            # Copia o arquivo.
            $historico = "Copiando arquivo $arquivo..."
            $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
            $ServiceDesk._COPYFILE($caminho_scripts, $caminho, 'C:\Program Files (x86)\Java\jre1.8.0_31\lib\security')

            # Obtém a HASH do arquivo no computador local.
            $LocalHash = $ServiceDesk._GETHASH("C:\Program Files (x86)\Java\jre1.8.0_31\lib\security\$arquivo")
                    
            # Compara as HASH's do servidor e do arquivo copiado.
            $historico = "Verificando integridade do arquivo $arquivo..."
            $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
            if ($ServerHash -eq $LocalHash) {

                $historico = "Configurando políticas de segurança..."
                $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)

                # Habilita o perfil do Firewall.
                Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True | Out-Null

                # Remove todas as regras relacionadas ao Sisag e Java;
                Remove-NetFirewallRule -DisplayName "*SISAG*" | Out-Null
                Remove-NetFirewallRule -DisplayName "*JAVA*" | Out-Null

                # Cria regras TCP e UDP para liberar o Sisag Navegador.
                New-NetFirewallRule -DisplayName "sisagnavegador" -Program "C:\sistemas\sisag\navegadorsisag\sisagnavegador.exe" -Direction Inbound -Profile Any -Action Allow -Enabled True -Protocol TCP | Out-Null
                New-NetFirewallRule -DisplayName "sisagnavegador" -Program "C:\sistemas\sisag\navegadorsisag\sisagnavegador.exe" -Direction Inbound -Profile Any -Action Allow -Enabled True -Protocol UDP | Out-Null

                # Cria regras TCP e UDP para liberar o Java.
                New-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" -Program "C:\program files (x86)\java\jre1.8.0_31\bin\java.exe" -Direction Inbound -Profile Any -Action Allow -Enabled True -Protocol TCP | Out-Null
                New-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" -Program "C:\program files (x86)\java\jre1.8.0_31\bin\java.exe" -Direction Inbound -Profile Any -Action Allow -Enabled True -Protocol UDP | Out-Null

                # Libera todas as regras relacionadas ao Internet Explorer e Java.
                Set-NetFirewallRule -DisplayName “*Internet Explorer*","*Java*","*sisagnavegador*" –Enabled True -Action Allow | Out-Null

                $historico = "Associando extensão (.JAR)..."
                $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)

                # Concatena variáveis e strings.
                $REGISTRY = 'Registry::'
                $HKCR = "$REGISTRY"+"HKCR"
                $HKLM = "$REGISTRY"+"HKLM"

                # Cria chaves na HKEY_CLASSES_ROOT para extensão .JAR.
                New-Item "$HKCR\.jar" -Value 'jarfile' -Force | Out-Null
                New-Item "$HKCR\jar_auto_file\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null
                New-Item "$HKCR\jarfile\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null

                # Cria chaves na HKEY_LOCAL_MACHINE para extensão .JAR.
                New-Item "$HKLM\SOFTWARE\Classes\.jar" -Value 'jarfile' -Force | Out-Null
                New-Item "$HKLM\SOFTWARE\Classes\jar_auto_file\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null
                New-Item "$HKLM\SOFTWARE\Classes\jarfile\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null

                # Busca e separa os usuários por SID;;
                $SIDS = (Get-ChildItem -Path "Registry::HKEY_USERS" -Name | Where-Object -FilterScript {($_ -notlike  "*.DEFAULT") -and ($_ -notlike "*S-1-5-18") -and ($_ -notlike "*S-1-5-19") -and ($_ -notlike  "*S-1-5-20") -and ($_ -notlike  "*_Classes")})

                # Cria as chaves de associação do Java para cada SID.
                foreach($SID in $SIDS) {
                    $SID = "Registry::HKU\$SID"
    
                    New-Item "$SID\SOFTWARE\Classes\.jar" -Value 'jar_auto_file' -Force | Out-Null
                    New-Item "$SID\SOFTWARE\Classes\jar_auto_file\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null
    
                    New-Item "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\OpenWithList" -Force | Out-Null
                    Set-ItemProperty "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\OpenWithList" -Name "a" -Value "javaw.exe" | Out-Null
                    Set-ItemProperty "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\OpenWithList" -Name "MRUList" -Value "a" | Out-Null

                    New-Item "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\OpenWithProgids" -Force | Out-Null

                    New-Item "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\UserChoice" -Force | Out-Null
                    Set-ItemProperty "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jar\UserChoice" -Name "ProgId" -Value "Applications\javaw.exe" | Out-Null
                }

                # Busca e separa as classes de usuários por SID.
                $SIDS_CLASSES = Get-ChildItem -Path "Registry::HKEY_USERS" -Name | Where-Object -FilterScript {($_ -like  "*_Classes")}

                # Cria as chaves de associação do Java para cada classe de SID.
                foreach($SID_CLASSES in $SIDS_CLASSES) {
                    $SID_CLASSES = "Registry::HKU\$SID_CLASSES"
    
                    New-Item "$SID_CLASSES\.jar" -Value 'jar_auto_file' -Force | Out-Null
                    New-Item "$SID_CLASSES\jar_auto_file\shell\open\command" -Value '"C:\Program Files (x86)\Java\jre1.8.0_31\bin\javaw.exe" -jar "%1" %*' -Force | Out-Null
                }

                # Identifica se houve sucesso no processo de associação.
                if ($?) {
                    $historico = "Procedimento finalizado com sucesso."
                    $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
                    $STATUS = "Sucesso"
                } else {
                    $historico = "ERRO - Não foi possível associar a extensão."
                    $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
                    $STATUS = "Falha"
                }

            } else { # Interrompe a execução caso o arqivo CACERTS tenha sido corrompido durante a cópia.
                $historico = "ERRO - Arquivo $arquivo corrompido."
                $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
                $STATUS = "Falha"
            }

        } else { # Interrompe a execução caso não consiga encontrar o CACERTS.
            $historico = "ERRO - Arquivo $arquivo não encontrado no servidor."
            $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
            $STATUS = "Falha"
        }

    } else { # Interrompe a execução caso não consiga instalar o SISAG.
        $historico = "ERRO - Não foi possível localizar o SISAG Agente."
        $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
        $status = 'Falha'
    }

} else { # Interrompe a execução caso não consiga identificar a instalação do Java.
    $historico = "ERRO - Não foi possível encontrar a versão 8.31 do JAVA."
    $ServiceDesk._LOGHISTORY($produto, $pacote, $inicio, $historico)
    $STATUS = "Falha"
}

# Termina o processo de log.
$ServiceDesk._LOGEND($produto, $pacote, $inicio, $STATUS)