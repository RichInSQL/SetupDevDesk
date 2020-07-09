#[System.Environment]::OSVersion.Version
#Adapted from https://github.com/Disassembler0/Win10-Initial-Setup-Script

#########################
## 
## Privacy
## 
#########################

#Disable SMB Server
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

#Privacy: Let apps use my advertising ID: Disable
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0

# Privacy: SmartScreen Filter for Store Apps: Disable
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

#Disable Wi-Fi Sense
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) 
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}

if(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
}

if(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
}

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) 
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
}

if(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

# Disable search for app in store for unknown extensions
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) 
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
}

if(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

#Disable Bing Search in Start Menu
if(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")
{
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 -WhatIf
}

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) 
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}

If(!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"))
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

#Disable Telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service diagtrack -StartupType disabled

#Stop and disable WAP Push Service
Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
Set-Service dmwappushservice -startuptype disabled	

#Disable Feedback
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1

###################
## 
## System Settings
## 
###################

#Create a local location to hold all of my development bits
New-Item -Path "C:\" -Name "workspace" -ItemType Directory

#Map network drive to my fileshare
$Cred = Get-Credential -Message "Please enter your username and password for the FileShare"
New-PSDrive -Name "F" -PSProvider FileSystem -Root "\\192.168.1.78\FileShare" -Persist -Credential $Cred

#Set the DNS Settings locally on the machine if you are not globally setting them at the router
Set-DnsClientServerAddress -InterfaceIndex 11 -ServerAddresses ("1.1.1.1") #Lan

#Rename the computer to DevDesk
Rename-Computer -NewName "DevDesk"

#Set desktop background solid black https://www.reddit.com/r/PowerShell/comments/gom9vv/how_to_set_a_desktop_background_to_solid_color/
add-type -typedefinition "using System;`n using System.Runtime.InteropServices;`n public class PInvoke { [DllImport(`"user32.dll`")] public static extern bool SetSysColors(int cElements, int[] lpaElements, int[] lpaRgbValues); }";[PInvoke]::SetSysColors(1, @(1), @(0x000000))

#Set the accent colour to orange
#https://www.thelazyadministrator.com/2019/08/08/configure-windows-10-accent-color-with-intune-and-powershell/#Get_Color_Values
$accentRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"

$AccentColorMenuKey = @{
 Key   = 'AccentColorMenu';
 Type  = "DWORD";
 Value = 'ff008cff'
}

If ($Null -eq (Get-ItemProperty -Path $accentRegPath -Name $AccentColorMenuKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $accentRegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -PropertyType $AccentColorMenuKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $accentRegPath -Name $AccentColorMenuKey.Key -Value $AccentColorMenuKey.Value -Force
}

$AccentPaletteKey = @{
 Key   = 'AccentPalette';
 Type  = "BINARY";
 Value = 'ff,df,b8,00,ff,ca,8a,00,ff,af,4c,00,ff,8c,00,00,b3,62,00,00,72,3f,00,00,45,26,00,00,00,63,b1,00'
}

$hexified = $AccentPaletteKey.Value.Split(',') | ForEach-Object { "0x$_" }

If ($Null -eq (Get-ItemProperty -Path $accentRegPath -Name $AccentPaletteKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $accentRegPath -Name $AccentPaletteKey.Key -PropertyType Binary -Value ([byte[]]$hexified)
}
Else
{
	Set-ItemProperty -Path $accentRegPath -Name $AccentPaletteKey.Key -Value ([byte[]]$hexified) -Force
}

#Start Color Menu Key
$StartMenuKey = @{
 Key   = 'StartColorMenu';
 Type  = "DWORD";
 Value = 'ff0062b3'
}

If ($Null -eq (Get-ItemProperty -Path $accentRegPath -Name $StartMenuKey.Key -ErrorAction SilentlyContinue))
{
	New-ItemProperty -Path $accentRegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -PropertyType $StartMenuKey.Type -Force
}
Else
{
	Set-ItemProperty -Path $accentRegPath -Name $StartMenuKey.Key -Value $StartMenuKey.Value -Force
}

###################
## 
## Setup Powershell
## 
###################

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart

if(!(Test-Path $profile))
{
    New-Item -path $profile -type file –force
}

Install-Module dbatools
Install-Module VSCodeBackup

$profileContent = 'clear-host
Write-Host "Windows PowerShell"
Write-Host "Copyright (C) Microsoft Corporation. All rights reserved."
Write-Host

function Prompt
{
    Write-Host "[" -NoNewline
    Write-Host (Get-Date -Format "HH:mm:ss") -ForegroundColor Gray -NoNewline
    
    try
    {
        $history = Get-History -ErrorAction Ignore
        if ($history)
        {
            Write-Host "][" -NoNewline
            if (([System.Management.Automation.PSTypeName]''Sqlcollaborative.Dbatools.Utility.DbaTimeSpanPretty'').Type)
            {
                Write-Host ([Sqlcollaborative.Dbatools.Utility.DbaTimeSpanPretty]($history[-1].EndExecutionTime - $history[-1].StartExecutionTime)) -ForegroundColor Gray -NoNewline
            }
            else
            {
                Write-Host ($history[-1].EndExecutionTime - $history[-1].StartExecutionTime) -ForegroundColor Gray -NoNewline
            }
        }
    }
    catch { }
    Write-Host "] $($executionContext.SessionState.Path.CurrentLocation.ProviderPath)" -NoNewline
    "> "
}'

$profileContent

Set-Content -Path $profile -Value $profileContent

###################
## 
## UI Changes
## 
###################

#Set apps to use dark mode
if(Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
{
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

#Disable Cortana from start menu search
$CortanPth = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" 
   
IF (!(Test-Path -Path $CortanPth)) { 
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Search"
} 

if(Test-Path -Path $CortanPth)
{
    Set-ItemProperty -Path $CortanPth -Name "AllowCortana" -Value 0 
}

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) 
{
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) 
{
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) 
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}

if(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}

#Disable Auto Play
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

#Show Known File Extensions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

#Show Hidden Files
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

#Show This Computer on desktop
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) 
{
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
}

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) 
{
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
}

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

#Remove Music from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

#Remove Pictures icon from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue

#Remove Videos icon from this pc
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue

#Remove 3D Objects icon from this pc 
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

#Disable thumbs.db
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1

#Disable Auto Run for all devices
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Change Explorer home screen back to "This PC"
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1

# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Type DWord -Value 0

# Disable Quick Access: Frequent Folders
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Type DWord -Value 0

# Disable the Lock Screen (the one before password prompt - to prevent dropping the first character)
If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) 
{
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Personalization | Out-Null
}

Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1

#Set the accent color 
If (-Not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent)) 
{
    New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent -Name AccentColorMenu | Out-Null
}

Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent -Name AccentColorMenu -Type DWord -Value 0x0c63f7

#Set the Start Menu color
If (-Not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent)) 
{
    New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent -Name StartColorMenu | Out-Null
}

Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent -Name StartColorMenu -Type DWord -Value 0xff3f3326

# Use the Windows 7-8.1 Style Volume Mixer
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC")) 
{
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name MTCUVC | Out-Null
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name EnableMtcUvc -Type DWord -Value 0

###################
## 
## Power Plan
## 
###################

# https://facility9.com/2015/07/controlling-the-windows-power-plan-with-powershell/

Try {
    $HighPerf = powercfg -l | %{if($_.contains("Ultimate Performance")) {$_.split()[3]}}
    $CurrPlan = $(powercfg -getactivescheme).split()[3]
    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
} Catch {
    Write-Warning -Message "Unable to set power plan to high performance"
}

cmd /c "powercfg.exe -x -monitor-timeout-ac 0"
cmd /c "powercfg.exe -x -monitor-timeout-dc 0"
cmd /c "powercfg.exe -x -disk-timeout-ac 0"
cmd /c "powercfg.exe -x -disk-timeout-dc 0"
cmd /c "powercfg.exe -x -standby-timeout-ac 0"
cmd /c "powercfg.exe -x -standby-timeout-dc 0"
cmd /c "powercfg.exe -x -hibernate-timeout-ac 0"
cmd /c "powercfg.exe -x -hibernate-timeout-dc 0"

#Disable Hibernation
cmd /c "powercfg.exe -hibernate off"

###################
## 
## Windows Updates
## 
###################

# Change Windows Updates to "Notify to schedule restart"
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

# Disable P2P Update downlods outside of local network
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1

#######################
## 
## Remove Applications
## 
#######################

# Uninstall Windows Media Player
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue

#Xbox Related Applications
$XboxFeaturesApps = @(
    "Microsoft.XboxApp"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxGameOverlay"
    "Microsoft.Xbox.TCUI"
)

#Remove Xbox Apps
foreach ($XboxFeaturesApp in $XboxFeaturesApps) {

    Get-AppxPackage -Name $XboxFeaturesApp -AllUsers | Remove-AppxPackage -AllUsers
    Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ $XboxFeaturesApp | Remove-AppxProvisionedPackage -Online
}

# Uninstall default third party applications
$ThirdPartyBloatApps = @(
    "9E2F88E3.Twitter"
    "king.com.CandyCrushSodaSaga"
    "4DF9E0F8.Netflix"
    "Drawboard.DrawboardPDF"
    "D52A8D61.FarmVille2CountryEscape"
    "GAMELOFTSA.Asphalt8Airborne"
    "flaregamesGmbH.RoyalRevolt2"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "ActiproSoftwareLLC.562882FEEB491"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "Facebook.Facebook"
    "46928bounde.EclipseManager"
    "A278AB0D.MarchofEmpires"
    "KeeperSecurityInc.Keeper"
    "king.com.BubbleWitch3Saga"
    "89006A2E.AutodeskSketchBook"
    "CAF9E577.Plex"
    "A278AB0D.DisneyMagicKingdoms"
    "828B5831.HiddenCityMysteryofShadows"
)

#Remove Third Party Apps
foreach ($ThirdPartyBloatApp in $ThirdPartyBloatApps) {

    Get-AppxPackage -Name $ThirdPartyBloatApp -AllUsers | Remove-AppxPackage -AllUsers
    Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ $ThirdPartyBloatApp | Remove-AppxProvisionedPackage -Online
}

$bloatpack = 

@("king.com.CandyCrushSaga",
    "Microsoft.BingWeather",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingFinance",
    "Microsoft.XboxApp",
    "Microsoft.WindowsPhone",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.Office.OneNote",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.windowscommunicationsapps",
    "Microsoft.SkypeApp",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.3DBuilder",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.WindowsCamera",
    "Microsoft.Messaging",
    "Microsoft.YourPhone",
    "Microsoft.WindowsAlarms",
    "Microsoft.GetHelp",
    "Microsoft.Print3D",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.OneConnect",
    "Microsoft.XboxGamingOverlay"
)

foreach ($package in $bloatpack) {
    Get-AppxPackage -name $package -AllUsers | Remove-AppxPackage	
    Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ $package | Remove-AppxProvisionedPackage -Online        
}


#######################
## 
## Install Applications
## 
#######################

Write-Host -ForegroundColor Gray "Attempting to install Chocolatey"

try {

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

} catch {
Write-Host -ForegroundColor Red "Installing Chocolatey failed"
}

#https://chocolatey.org/packages

$chocolatePackaging = 
@("vscode","firefox","1password","sql-server-management-studio","github-desktop","paint.net","microsoft-windows-terminal","azure-data-studio","git")

foreach ($chocolate in $chocolatePackaging) {

    Write-Host -ForegroundColor Gray "Attempting to install " $chocolate 

    try {
        choco install $chocolate -y
    }
    catch {
        Write-Host -ForegroundColor Red "Installing " $chocolate "failed"
    }
}

#######################
## 
## Finish Up
## 
#######################


#Restart Explorer to change it immediately    
Stop-Process -name explorer

#Wait for explorer to restart
Start-Sleep -Seconds 10

#Restart Computer
Restart-Computer -WhatIf -Force