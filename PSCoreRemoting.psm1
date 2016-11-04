function Install-PSCore
{
    [Cmdletbinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [Version]$Version
    )

    Begin
    {
        switch -Wildcard ((Get-CimInstance Win32_OperatingSystem).version)
        {
            '10*'   { $OS = 'Win10' }
            '6.3*'  { $OS = 'Win81' }
            default { $OS = 'Win10' }
        }
    }

    Process
    {    
        Try
        {    
            if ($Version)
            {
                Write-Verbose -Message "Determine $($Version) PSCore Uri"            
                $Rest = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/PowerShell/releases'
                [string]$Uri = $Rest.assets.browser_download_url | Where-Object { $_ -match "$($Version)\-alpha\.\d+\-$($OS)\-x64\.msi$" }

                if (! $Uri)
                {
                    Throw "Could not find OpenSSH Version: $($Version)"
                }

                Write-Verbose -Message "Downloading $($Version) OpenSSH Archive"
            }
            else
            {
                Write-Verbose -Message "Determine Latest PSCore Uri"
                 
                $Rest = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
                [string]$Uri = $Rest.assets.browser_download_url | Where-Object { $_ -match "$OS.*msi$" }
            
                Write-Verbose -Message "Downloading latest PSCore MSI"
            }

            Invoke-WebRequest -Uri $uri -OutFile "$Env:TEMP\PSCore.msi"

            Write-Verbose -Message "Installting PSCore"
            Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$Env:TEMP\PSCore.msi`" /quiet /norestart" -Wait            
        }
        Catch
        {
            throw
        } 
    }
}


function Uninstall-PSCore
{
    [Cmdletbinding()]
    param
    (
        [switch]$Reboot
    )

    Process
    {
        Try
        {
            Write-Verbose -Message "Find Installed PS Core Packages"
            $PSCore = Get-Package -ProviderName msi | Where-Object { $_.Name -match "^powershell_(\d+\.){3}\d+$" }

            if (!$PSCore)
            {
                Throw "Could not find Installed PSCore Msi Package"
            }

            Write-Verbose -Message "Uninstalling PSCore MSI Packages: $($PSCore.Name | Out-String)"
            $PSCore | Uninstall-Package -Force

            Start-Sleep -Seconds 5

            Write-Verbose -Message "Removing PowerShell Directory"
            Remove-Item -Path "$Env:ProgramFiles\PowerShell" -Recurse -Force -ErrorAction SilentlyContinue

            if ($Reboot)
            {
                Start-Sleep -Seconds 2

                Write-Verbose -Message "Restarting Computer"
                Restart-Computer
            }
        }
        catch
        {
            Throw
        }
    }
}


function Get-PSCoreVersion
{
    [Cmdletbinding()]
    param()

    Process
    {
        if (Test-Path "$Env:ProgramFiles\PowerShell")
        {
            $Version = Get-ChildItem -Path "$Env:ProgramFiles\PowerShell" | Sort-Object -Descending -Property Name | Select-Object -ExpandProperty Name -First 1
        }
        else
        {
            Throw "Could not find PowerShell Core Installation"
        }

        Return $Version
    }
}


function Get-OpenSSH
{
    [Cmdletbinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [Version]$Version
    )

    Begin
    {
        switch ($env:PROCESSOR_ARCHITECTURE)
        {
            'AMD64' { $Architecture = 'Win64' }
            'x86' { $Architecture = 'Win32' }
        }
    }

    Process
    {    
        Try
        {    
            if ($Version)
            {
                Write-Verbose -Message "Determine $($Version) OpenSSH Uri"            
                $Rest = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases'
                [string]$Uri = $Rest.assets.browser_download_url | Where-Object { $_ -match "$Version\/OpenSSH\-$($Architecture)\.zip$" }

                if (! $Uri)
                {
                    Throw "Could not find OpenSSH Version: $($Version)"
                }

                Write-Verbose -Message "Downloading $($Version) OpenSSH Archive"
            }
            else
            {
                Write-Verbose -Message "Determine Latest OpenSSH Uri"            
                $Rest = Invoke-RestMethod 'https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest'
                [string]$Uri = $Rest.assets.browser_download_url | Where-Object { $_ -match $Architecture }

                Write-Verbose -Message "Downloading latest OpenSSH Archive"
            }

            Invoke-WebRequest -Uri $uri -OutFile "$Env:TEMP\OpenSSH.zip"

            Write-Verbose -Message "Extracting OpenSSH Archive"
            Expand-Archive -Path "$Env:TEMP\OpenSSH.zip" -DestinationPath "$Env:TEMP\OpenSSH" -Force

            if (! (Test-Path "$Env:ProgramFiles\OpenSSH" -PathType Container)) { New-Item -Path "$Env:ProgramFiles\OpenSSH" -ItemType Directory }

            Write-Verbose -Message "Copying OpenSSH to Program Files"
            Copy-Item -Path "$Env:TEMP\OpenSSH\OpenSSH-$($Architecture)\*" -Destination "$Env:ProgramFiles\OpenSSH"    
        }
        Catch
        {
            throw
        } 
    }
}


function Install-OpenSSH
{
    [Cmdletbinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [Version]$Version
    )

    Process
    {
        Try
        {
            if ($Version)
            {
                Write-Verbose -Message "Downloading $($Version) OpenSSH for Github"
                Get-OpenSSH -Version $Version
            }
            else
            {
                Write-Verbose -Message "Downloading latest OpenSSH for Github"
                Get-OpenSSH
            }

            Start-Sleep -Seconds 2

            Push-Location -Path "$Env:ProgramFiles\OpenSSH"         
            
            powershell -executionpolicy bypass -file install-sshd.ps1

            .\ssh-keygen.exe -A

            Write-Verbose -Message "Create Firewall Rule for Inbound SSH"
            New-NetFirewallRule -Protocol TCP -LocalPort 22 -Direction Inbound -Action Allow -DisplayName SSH

            Write-Verbose -Message "Set sshd Service to Automatic"
            Set-Service sshd -StartupType Automatic

            Write-Verbose -Message "Set ssh-agent Service to Automatic"
            Set-Service ssh-agent -StartupType Automatic

            Write-Verbose -Message "Set firewall Rule for Workstations"
            netsh advfirewall firewall add rule name='SSH Port' dir=in action=allow protocol=TCP localport=22

            Pop-Location
        }
        catch
        {
            throw
        }
    }
}


function Uninstall-OpenSSH
{
    [Cmdletbinding()]
    param
    (
        [switch]$Reboot
    )

    Process
    {
        Try
        {
            Push-Location -Path "$Env:ProgramFiles\OpenSSH"

            Write-Verbose -Message "Stopping sshd Service"
            Stop-Service sshd
            
            Write-Verbose -Message "Uninstalling sshd"
            powershell.exe -executionpolicy bypass -file uninstall-sshd.ps1

            Write-Verbose -Message "Uninstalling sshlsa"
            powershell.exe -executionpolicy bypass -file uninstall-sshlsa.ps1

            Start-Sleep -Seconds 5

            Write-Verbose -Message "Removing OpenSSH Directory"
            Remove-Item -Path "$Env:ProgramFiles\OpenSSH" -Recurse -Force -ErrorAction SilentlyContinue

            If ($Reboot)
            {
                Start-Sleep -Seconds 2

                Write-Verbose -Message "Restarting Computer"
                Restart-Computer
            }

            Pop-Location
        }
        catch
        {
            Throw
        }
    }
}


function Update-OpenSSHConfig
{
    [Cmdletbinding()]
    param
    (
        $PSCoreVersion = (Get-PSCoreVersion)
    )

    Process
    {
        Try
        {
            Push-Location -Path "$Env:ProgramFiles\OpenSSH"
            
            $Config = Get-Content .\sshd_config

            $Config | ForEach-Object {
                If ($_ -match '#PasswordAuthentication yes')
                {
                    Write-Verbose -Message 'Enable Password Auth'
                    'PasswordAuthentication yes'
                }
                elseif ($_ -match '#RSAAuthentication yes') 
                {
                    Write-Verbose -Message 'Enable RSA Auth'
                    'RSAAuthentication yes'
                }
                elseif ($_ -match '#PubkeyAuthentication yes') 
                {
                    Write-Verbose -Message 'Enable Public Key Auth'
                    'PubkeyAuthentication yes'
                }
                else 
                {
                    # Output unaltered lines                
                    $_    
                }

                if ($_ -match 'Subsystem	sftp	C:/Program Files/OpenSSH/sftp-server.exe')
                {
                    Write-Verbose -Message 'Insert PowerShell Subsystem value'
                    "Subsystem powershell C:/Program Files/PowerShell/$($PSCoreVersion)/powershell.exe -sshs -NoLogo -NoProfile"                    
                }
            } | Out-File -FilePath .\sshd_config -Encoding ascii

            Write-Verbose -Message 'Restarting sshd Service'
            Restart-Service sshd

            Pop-Location
        }
        catch
        {
            throw
        }
    }
}


function Add-OpenSSHToPath
{
    [Cmdletbinding()]
    param()

    Process
    {    
        Try
        {
            $OldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path

            If (! ($Env:PATH | Select-String -SimpleMatch "$Env:ProgramFiles\OpenSSH\"))
            { 
                Write-Verbose -Message 'Adding OpenSSH to Path'
                $NewPath = $OldPath + ';' + "$Env:ProgramFiles\OpenSSH\"
                Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path -Value $NewPath      
            }
            else
            {
                Write-Verbose -Message 'OpenSSH is already in Path'
            }
        }
        catch
        {
            Throw
        }
    }
}

Export-ModuleMember -Function *


