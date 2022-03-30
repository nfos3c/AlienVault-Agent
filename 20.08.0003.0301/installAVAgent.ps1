new-module -name install_agent -scriptblock {
    $BaseInstallPath = "$($env:SYSTEMDRIVE)\Program Files\osquery"
    $OldBaseInstallPath = "$($env:SYSTEMDRIVE)\ProgramData\osquery"
    $SysmonSrc = "https://download.sysinternals.com/files/Sysmon.zip"
    $SysmonDst = "$($env:TEMP)\Sysmon.zip"
    $SysmonConfigSrc = "https://raw.githubusercontent.com/nfos3c/AlienVault-Agent/main/20.08.0003.0301/sysmon_config_schema4_0.xml"
    $SysmonConfigDst = [System.IO.Path]::GetTempFileName()
    $SysmonInstallDst = "$($env:USERPROFILE)\Documents\Sysmon\"
    $SysmonWinDst = "$($env:WINDIR)\Sysmon.exe"
    $SysmonServiceName = "Sysmon"
    $OsquerySrc = "https://github.com/nfos3c/AlienVault-Agent/blob/main/20.08.0003.0301/alienvault-agent-20.08.0003.0301.msi?raw=true"
    $OsqueryDst = "$env:TEMP\alienvault-agent.msi"
    [bool] $IsSysmonDownloaded = $false
    [bool] $IsSysmonConfigDownloaded = $false
    [bool] $IsLegacyAgent = $true
    $AgentServiceName = "osqueryd"

    function IsUUID() {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]$uuid
        )
        return $uuid -match "^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
    }

    function GetControlNodeIdFromSecretFile() {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]$secretfile
        )
        $controlnodeid = ""

        if ([System.IO.File]::Exists("$secretfile")) {
            $controlnodeid = [IO.File]::ReadAllText("$secretfile").Trim()
            Write-Host "Detected secret file, verifying value"

            if (-not (IsUUID $controlnodeid)) {
                throw "Value in `"${secretfile}`" is corrupted. This could be due to an error during a previous installation. To fix, delete the secret file and re-run the Bootstrap Installation command. Contact AT&T CyberSecurity Support for more information."
            }
        }
        return $controlnodeid
    }

    function GetHostIdFromFlagsFile() {
        param
        (
            [Parameter(Mandatory = $true)]
            [string]$flagfile
        )
        $hostid = ""

        if ([System.IO.File]::Exists($flagfile)) {
            $match = (Select-String -Path $flagfile -Pattern "specified_identifier=(.*)")
            if ($match.Matches.Groups.success) {
                $hostid = $match.Matches.Groups[1].Value.Trim()
                Write-Host "Detected osquery.flags file, verifying specified_identifier"

                if (-not (IsUUID $hostid)) {
                    throw "specified_identifier in `"${flagfile}`" is corrupted. This could be due to an error during a previous installation. To fix, delete the osquery.flags file and re-run the Bootstrap Installation command. Contact AT&T CyberSecurity Support for more information."
                }
            }
            else {
                Write-Host "Existing host id not found in ${flagfile}"
            }
        }
        return $hostid
    }

    function IsAgentRunning() {
        $agentSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$AgentServiceName'"
        return ($agentSvc.state -eq "Running")
    }

    function IsAgentServiceInstalled() {
        $agentSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$AgentServiceName'"
        return ($agentSvc -ne $null)
    }

    function IsSysmonServiceInstalled() {
        $service = Get-Service $SysmonServiceName -ErrorAction SilentlyContinue
        return ($service -ne $null)
    }

    function IsWinSysmonInstalled() {
        return (Test-Path -Path "$SysmonWinDst")
    }

    function IsAgentEverInstalled() {
        $secretfile = $(Join-Path $BaseInstallPath "secret")
        $oldsecretfile = $(Join-Path $OldBaseInstallPath "secret")
        return ([System.IO.File]::Exists("$secretfile") -or [System.IO.File]::Exists("$oldsecretfile"))
    }

    function AgentDoStart() {
        Start-Service $AgentServiceName
        Start-Sleep -s 1
        return (IsAgentRunning)
    }

    function AgentDoStop() {
        Stop-Service $AgentServiceName
        Start-Sleep -s 1
        $proc = Get-Process osqueryd -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "osqueryd still running, killing processes"
            Stop-Process -Force -Name osqueryd
        }
        return (-not (IsAgentRunning))
    }

    function Install-Project() {
        param(
            [string]$apikey="",
            [string]$controlnodeid="",
            [string]$hostid="",
            [string]$assetid="",
            [switch]$nosysmon=$false
        )
        Install-Project-Internal -apikey $apikey -controlnodeid $controlnodeid -hostid $hostid -assetid $assetid -nosysmon $nosysmon
        Write-Host "See install.log for details" -ForegroundColor Cyan
    }

    function Uninstall-Sysmon() {
        # uninstall using Sysmon in Windows dir
        # in case current user is different from installing user
        if (IsWinSysmonInstalled) {
            Write-Host "Uninstalling Sysmon at $($SysmonWinDst)" -ForegroundColor Cyan
            Invoke-Expression -Command "& '$SysmonWinDst' -u force"
            Remove-Item "$SysmonWinDst" -ErrorAction Ignore -Force
        }
        if (Test-Path -Path $SysmonInstallDst) {
            Write-Host "Uninstalling Sysmon at $($SysmonInstallDst)" -ForegroundColor Cyan
            Remove-Item $SysmonInstallDst -Recurse -ErrorAction Ignore
        }
    }

    function Install-Sysmon() {
        #===================================================
        # Prepare Sysmon installation target
        #===================================================
        Write-Host "Preparing Sysmon target path $($SysmonInstallDst)" -ForegroundColor Cyan
        # Suppress output, but not errors:
        [void](New-Item -ItemType Directory -Force -Path $SysmonInstallDst)

        if (-not (Test-Path -Path $SysmonInstallDst)) {
            Write-Error "Skipping Sysmon... Destination path $($SysmonInstallDst) does not exist."
        }
        else {
            #===================================================
            # Unzip Sysmon
            #===================================================
            Unblock-File -Path $SysmonDst
            Write-Host "Uncompressing the Zip file to $($SysmonInstallDst)" -ForegroundColor Cyan

            $FoundExtractionAssembly = 0
            try {
                # Load preferred extraction method's assembly (.NET 4.5 or later)
                # Write-Host "Using preferred extraction method..."
                Add-Type -As System.IO.Compression.FileSystem -ErrorAction Stop
                $FoundExtractionAssembly = 1
            }
            catch [System.Exception] {
                # Write-Host "Preferred extraction method not found. Attempting fall-back method..."
            }

            if ($FoundExtractionAssembly) {
                [IO.Compression.ZipFile]::ExtractToDirectory($SysmonDst, $SysmonInstallDst)
            }
            else {
                # Fall-back method, may fail in sessions lacking access to interactive shell
                $continue_flag = 1
                try {
                    $shell_app = New-Object -COMObject "Shell.Application"
                } catch {
                    Write-Error "Could not create Shell.Application object"
                    $continue_flag = 0
                }
                if ($continue_flag) {
                    $zip_file = $shell_app.namespace($SysmonDst)
                    $destination = $shell_app.namespace($SysmonInstallDst)
                    if ($destination -ne $null) {
                            $destination.Copyhere($zip_file.items(), 0x10)
                    }
                }
            }
        }

        #===================================================
        # Install Sysmon Using Downloaded Config
        #===================================================
        if ( -not ((get-childitem $SysmonConfigDst).length -gt 0 ) ) {
           $command = "& '$SysmonInstallDst\sysmon' -accepteula -i"
           Write-Host "Not using an additional Sysmon configuration file" -ForegroundColor Cyan
        }
        else {
           $command = "& '$SysmonInstallDst\sysmon' -accepteula -i '$SysmonConfigDst'"
           Write-Host "Sysmon configuration file to use $SysmonConfigDst" -ForegroundColor Cyan
        }
        Write-Host "Installing Sysmon with command $command" -ForegroundColor Cyan

        iex $command
    }

    function Install-Project-Internal() {
        param(
            [string]$apikey="",
            [string]$controlnodeid="",
            [string]$hostid="",
            [string]$assetid="",
            [bool]$nosysmon=$false
        )

        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
            Return
        }

        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Error "This script must be run using Powershell version 3 or higher.  You have version $PSVersionTable.PSVersion.Major installed"
            Return
        }

        $secretfile = $(Join-Path $BaseInstallPath "secret")
        $flagfile = $(Join-Path $BaseInstallPath "osquery.flags")

        if (-not ([string]::IsNullOrEmpty($controlnodeid)) -and -not (IsUUID $controlnodeid)) {
            Write-Error "controlnodeid is not valid."
            Return
        }

        if (-not ([string]::IsNullOrEmpty($assetid)) -and -not (IsUUID $assetid)) {
            Write-Error "assetid is not valid."
            Return
        }

        if ([string]::IsNullOrEmpty($hostid)) {
            $hostid = $assetid
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            $apikey = $controlnodeid
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            try {
                $apikey = GetControlNodeIdFromSecretFile $secretfile
            }
            catch {
                Write-Error $PSItem.ToString()
                Return
            }
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            # check old location in ProgramData
            $oldsecretfile = $(Join-Path $OldBaseInstallPath "secret")
            try {
                $apikey = GetControlNodeIdFromSecretFile $oldsecretfile
            }
            catch {
                Write-Error $PSItem.ToString()
                Return
            }
        }

        if ([string]::IsNullOrEmpty($apikey)) {
            Write-Warning "You must supply either the -apikey or -controlnodeid parameters to identify your agent account"
            return
        }

        # use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        #===================================================
        # Download osquery
        #===================================================
        if (-not (Download-Osquery)) {
            Write-Error "Failed to download the Agent installer, exiting..."
            return
        }
        Write-Host "Successfully downloaded the Agent installer"
        
        #===================================================
        # Download Sysmon
        #===================================================
        if (($IsLegacyAgent) -and (-not $nosysmon)) {
            # detect implied no-Sysmon scenarios
            if ((-not (IsAgentEverInstalled)) -or ((IsAgentEverInstalled) -and (IsSysmonServiceInstalled))) { 
                if (Download-Sysmon) {
                    Write-Host "Successfully downloaded the Sysmon package"
                    $IsSysmonDownloaded = $true
                    # Proceed to download Sysmon config file
                    if((Download-SysmonConfig)){
                        Write-Host "Successfully downloaded Sysmon config file"
                        $IsSysmonConfigDownloaded = $true
                    }
                    else {
                        Write-Warning "Failed to download the Sysmon config file, Sysmon installation will be skipped!"
                        Write-Warning "Some Events will NOT be collected by the Agent!"
                    }
                }
                else {
                    Write-Warning "Failed to download the Sysmon package, Sysmon installation will be skipped!"
                    Write-Warning "Some Events will NOT be collected by the Agent!"
                }
            }
        }

        #===================================================
        # Install osquery
        #===================================================
        if (IsAgentRunning) {
            if (AgentDoStop) {
                Write-Host "'$AgentServiceName' system service is stopped." -foregroundcolor Cyan
            }
            else {
                Write-Error "Did not stop osqueryd service.  Hopefully, this is fine."
            }
        }

        Write-Host "Installing Agent"
        try {
            Start-Process C:\Windows\System32\msiexec.exe -ArgumentList "/i $env:TEMP\alienvault-agent.msi ALLUSERS=1 /qn /l*v .\install.log" -wait
            echo "INSTALLATION SUCCESSFULLY COMPLETED" >> .\install.log
        } catch {
            echo "INSTALLATION ERROR (ERRORLEVEL=$LASTEXITCODE)" >> .\install.log
            Write-Error "INSTALLATION ERROR (ERRORLEVEL=$LASTEXITCODE)"
            Return
        }

        # If the install directory doesn't exist, bail
        if (![System.IO.Directory]::Exists("$BaseInstallPath")) {
            echo "Installation directory does not exist: $BaseInstallPath" >> .\install.log
            Write-Error "Installation directory does not exist: $BaseInstallPath"
            Return
        }

        Write-Host "Writing secret"
        [IO.File]::WriteAllLines("$secretfile", $apikey)

        # if hostid is not specified, try to extract from flag file
        if ([string]::IsNullOrEmpty($hostid)) {
            try {
                $hostid = GetHostIdFromFlagsFile $flagfile
            }
            catch {
                Write-Error $PSItem.ToString()
                Return
            }
        }

        # if still not found, check old ProgramData location
        if ([string]::IsNullOrEmpty($hostid)) {
            $oldflagfile = $(Join-Path $OldBaseInstallPath "osquery.flags")
            try {
                $hostid = GetHostIdFromFlagsFile $oldflagfile
            }
            catch {
                Write-Error $PSItem.ToString()
                Return
            }
        }

        echo "Creating flag file"
        copy $BaseInstallPath\osquery.flags.example $flagfile

        Write-Host "Setting host identifier"

        # if still no hostid, use generated default
        if ([string]::IsNullOrEmpty($hostid)) {
            $hostid="00000000-8e0d-4dce-84da-c668c7256ed9"
        }

        $output = "--tls_hostname=api.agent.alienvault.cloud/osquery-api/us-west-2", "--host_identifier=specified", "--specified_identifier=$hostid"
        [IO.File]::AppendAllLines([string]$flagfile, [string[]]$output)

        # add customer certs if present
        $custpem = "$($env:SYSTEMROOT)\System32\drivers\etc\osquery_customer_certs.pem"
        if ([System.IO.File]::Exists($custpem)) {
          Write-Host "Adding customer certs"
          type "$custpem" >> "$BaseInstallPath\certs\certs.pem"
        }

        # install Sysmon only now that osquery is installed
        if (IsSysmonServiceInstalled) {
            Uninstall-Sysmon
        }
        if ((-not $nosysmon) -and ($IsSysmonDownloaded) -and ($IsSysmonConfigDownloaded)) {
            #===================================================
            # Install Sysmon
            #===================================================
            Install-Sysmon
        }

        # make sure the service exists after osquery installation
        if (-not (IsAgentServiceInstalled)) {
            Write-Error "'$AgentServiceName' is not an installed system service."
            return
        }

        # restart service
        if (AgentDoStop) {
            Write-Host "'$AgentServiceName' system service is stopped." -foregroundcolor Cyan
        }
        else {
            Write-Error "Failed to stop '$AgentServiceName' system service."
            return
        }

        if (AgentDoStart) {
            Write-Host "'$AgentServiceName' system service is started." -foregroundcolor Cyan
        }
        else {
            Write-Error "Failed to start '$AgentServiceName' system service."
            return
        }

        Write-Host "Deleting installer"
        del $env:TEMP\alienvault-agent.msi

        if (($BaseInstallPath -ne $OldBaseInstallPath) -and [System.IO.Directory]::Exists($OldBaseInstallPath)) {
           Write-Host "renaming old ProgramData/osquery directory"
           move "$OldBaseInstallPath" "$($OldBaseInstallPath).renamed"
        }

    }

    function Download-Osquery() {
        Write-Host "Downloading Agent installer" -ForegroundColor Cyan
        $webclient = New-Object System.Net.WebClient
        try{
            $webclient.DownloadFile($OsquerySrc, $OsqueryDst)
        } catch {
            Write-Error "Error: $($_.Exception.Message)"
            return $false
        }
        return (Test-Path -Path $OsqueryDst -PathType leaf)
    }

    function Download-Sysmon() {
        Write-Host "Downloading Sysmon from $SysmonSrc" -ForegroundColor Cyan
        try{
            Invoke-WebRequest $SysmonSrc -OutFile $SysmonDst
        }  catch {
            Write-Error "Error: $($_.Exception.Message)"
            return $false
        }
        return (Test-Path -Path $SysmonDst -PathType leaf)
    }

    function Download-SysmonConfig() {
        Write-Host "Downloading Sysmon config file from $SysmonConfigSrc" -ForegroundColor Cyan
        try{
            Invoke-WebRequest -UseBasicParsing $SysmonConfigSrc -OutFile $SysmonConfigDst
        } catch {
            Write-Error "Error: $($_.Exception.Message)"
            return $false
        }
        return ((get-childitem $SysmonConfigDst).length -gt 0)
    }

    set-alias install_agent -value Install-Project
    export-modulemember -alias 'install_agent' -function 'Install-Project'
}
