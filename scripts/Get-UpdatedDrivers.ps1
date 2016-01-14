<#
.SYNOPSIS
    This script exports drivers that have been updated by Windows Update
.DESCRIPTION
    This script exports drivers that have been updated by Windows Update
.PARAMETER DeleteNonUpdated
    Switch to specify whether you want to delete the Drivers that were exported and were not Updated by Windows Update.
    Useful when troubleshooting.
.EXAMPLE
    Get-UpdatedDrivers.ps1
.EXAMPLE
    Get-UpdatedDrivers.ps1 -DeleteNonUpdated
.NOTES
    I was having issues with Windows Update breaking MDT Task Sequences after booting into WinPE. Windows Update would 
    update the NIC drivers and temporarily disable the NIC which killed the Task Sequence. Even if I used the same version 
    number from the PC vendor, Windows Update was still updating the driver. If I used the exact driver Windows Update was
    pushing it finally supressed the update.
.LINK 

#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [switch]$DeleteNonUpdated
)

Begin
{
    Import-Module -Name 'Dism'

    # Decalre Variables
    $FolderName = (Get-WmiObject Win32_computersystem).model
    $DriverDir = Join-Path -path $PSScriptRoot -ChildPath $FolderName
    $UpdatedDir = Join-Path -Path $DriverDir -ChildPath 'UpdatedDrivers'
    $DriverInfoFile = Join-Path -Path $UpdatedDir -ChildPath 'DriverInfo.txt'
}
Process
{
    try
    {
        # Create Directories
        if (!(Test-Path -Path $DriverDir)) { New-Item -Path $PSScriptRoot -Name $FolderName -ItemType Directory}
        if (!(Test-Path -Path $UpdatedDir)) { New-Item -Path $DriverDir -Name 'UpdatedDrivers' -ItemType Directory }

        # Gather Driver Update Events
        $DriverList = @()

        $Events = Get-winevent Microsoft-Windows-DeviceSetupManager/Admin | where-object { $_.Message -like '*driver update*' }
        $Events | Out-File -FilePath $DriverInfoFile -Force

        foreach ($Event in $Events)
        {
            # Gather Driver Inf Name from Events
            $Record = Get-winevent Microsoft-Windows-DeviceSetupManager/Admin | Where-Object { $_.recordid -eq ($Event.recordid + 1) }
            $DriverInf = ($Record.Message | Select-String -Pattern '\S*\.inf').Matches.Value
    
            # Get Driver Directory Name from the original driver path.
            $DriverDetails = Get-WindowsDriver -Online -Driver $DriverInf
            $DriverDirName = (Get-Item $DriverDetails.originalfilename) | Split-Path -Parent | Split-Path -Leaf | Select-Object -Unique
    
            # Collect Driver Directory Names that have been Updated
            if ($DriverList -notcontains $DriverDirName) { $DriverList += $DriverDirName }

            $Record | Format-List | Out-File -FilePath $DriverInfoFile -Append -NoClobber -Force
            $DriverDetails | Out-File -FilePath $DriverInfoFile -Append -NoClobber -Force
        }

        # Export Windows Drivers
        Export-WindowsDriver -Online -Destination $DriverDir -LogPath "$UpdatedDir\ExportLog.txt"

        # Copy Updated Driver to Updated Driver Folder
        foreach ($DriverName in $DriverList)
        {
            $DriverFolder = Join-Path -Path $DriverDir -ChildPath $DriverName
            Copy-Item -Path $DriverFolder -Destination $UpdatedDir -Container -Recurse -Force
        }

        # Remove Unused Drivers if needed
        if ($DeleteNonUpdated.IsPresent) { Get-ChildItem -Path $DriverDir -Exclude 'UpdatedDrivers' | Remove-Item -Force -Recurse }
    }
    catch
    {
        throw $Error[0]
    }
}
End {}