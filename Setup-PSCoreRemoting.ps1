[Cmdletbinding(DefaultParameterSetName='Install')]
param
(
    [parameter(ParameterSetName='Install')]
    [Switch]$InstallPSCore,
    
    [parameter(ParameterSetName='Install')]
    [Version]$PSCoreVersion,

    [parameter(ParameterSetName='Uninstall')]
    [Switch]$UninstallPSCore,

    [parameter(ParameterSetName='Install')]
    [Switch]$InstallOpenSSH,

    [parameter(ParameterSetName='Install')]
    [Version]$OpenSSHVersion,

    [parameter(ParameterSetName='Uninstall')]
    [Switch]$UninstallOpenSSH,

    [parameter(ParameterSetName='Uninstall')]
    [Switch]$Reboot,

    [parameter(ParameterSetName='Install')]
    [Switch]$UpdateOpenSSHConfig,

    [parameter(ParameterSetName='Install')]
    [Switch]$AddOpenSSHToPath
)

Try
{
    Import-Module "$PSScriptRoot\PSCoreRemoting.psm1" -Force

    switch ($psCmdlet.ParameterSetName)
    {
        'Install'
        {   
            if (!$InstallPSCore -AND !$InstallOpenSSH -AND !$UpdateOpenSSHConfig -AND !$AddOpenSSHToPath) { Throw "No Options were Chosen, Please select Setup Options." } 

            if ($InstallPSCore)
            {
                if ($PSCoreVersion)
                {
                    Write-Verbose -Message "Starting: PSCore $($PSCoreVersion) Install"
                    Install-PSCore -Version $PSCoreVersion
                }
                else 
                {
                    Write-Verbose -Message 'Starting: PSCore Install'
                    Install-PSCore    
                }                
            }
            
            if ($InstallOpenSSH)
            {
                If ($OpenSSHVersion)
                {
                    Write-Verbose -Message "Starting: OpenSSH $($Version) Install"
                    Install-OpenSSH -Version $OpenSSHVersion
                }
                else
                {
                    Write-Verbose -Message 'Starting: OpenSSH Install'
                    Install-OpenSSH
                }
            }
                
            if ($UpdateOpenSSHConfig)
            {
                if ($PSCoreVersion)
                {
                    Write-Verbose -Message 'Starting: Update OpenSSH Config'
                    Update-OpenSSHConfig -PSCoreVersion $PSCoreVersion
                }
                else
                {
                    Write-Verbose -Message 'Starting: Update OpenSSH Config'
                    Update-OpenSSHConfig
                }
            }

    
            if ($AddOpenSSHToPath)
            {
                Write-Verbose -Message 'Starting: Add OpenSSH to Path'
                Add-OpenSSHToPath
            }
        }
        'Uninstall'
        {
            if (!$UninstallPSCore -AND !$UninstallOpenSSH) { Throw "No Options were Chosen, Please select Setup Options." }

            if ($UninstallPSCore -AND $UninstallOpenSSH)
            {
                Write-Verbose -Message "Starting: Uninstall OpenSSH"
                Uninstall-OpenSSH

                Write-Verbose -Message "Starting: Uninstall PSCore"
                Uninstall-PSCore -Reboot:$Reboot
            }
            elseif ($UninstallOpenSSH)  
            {
                Write-Verbose -Message "Starting: Uninstall OpenSSH"
                Uninstall-OpenSSH -Reboot:$Reboot
            }
            elseif ($UninstallPSCore) 
            {
                Write-Verbose -Message "Starting: Uninstall PSCore"
                Uninstall-PSCore -Reboot:$Reboot
            }                                                      
        }
    }    
}
catch
{
    Throw
}