# Parameters for excluding app installs (broken atm...)
#param($Exclude)

$LastUpdated = '12/07/2022  '

# Set window title
$host.UI.RawUI.WindowTitle = "New PC Setup Script - $env:COMPUTERNAME"

# Set C:\Temp as TEMP variable
$env:TEMP = "C:\Temp"
New-Item -Path $env:TEMP -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

# Start script logging
$LogFile = "$env:TEMP\new-pc-setup_$(Get-Date -Format 'yyyy-MM-ddTHH_mm_ss').log"
Try {Start-Transcript -Path $LogFile -ErrorAction Stop | Out-Null}
Catch {Start-Transcript -Path $LogFile | Out-Null}

# Disable progress bar for faster downloads
$global:ProgressPreference = 'SilentlyContinue'

# Beep alert function
function BeepBoop {
    For ($i=1; $i -le 18; $i++) {(New-Object -ComObject WScript.Shell).SendKeys([char]174)}
    Start-Sleep 2
    [console]::Beep();[console]::Beep()
    Start-Sleep 2
    For ($i=1; $i -le 18; $i++) {(New-Object -ComObject WScript.Shell).SendKeys([char]175)}
}

# Download function
function Download {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$URL,
        [Parameter(Mandatory)][string]$Name,
	    [Parameter()][string]$Filename = $(if ($URL -match "\....$") {(Split-Path $URL -Leaf)}),
        [Parameter()][string]$OutputPath = $env:TEMP
    )
    if (-Not($Filename)) {
        Write-Warning "Filename parameter needed. Download failed."
        Write-Host
        Break
    }
    $Output = $OutputPath + "\$Filename"
    #$Name = $Name -csplit '(?=[A-Z])' -ne '' -join ' '
    #Write-Host "Downloading $Name..."`n
    $Error.Clear()
    if (!(Test-Path $Output)) {(New-Object System.Net.WebClient).DownloadFile($URL, $Output)}
    if ($Error.count -gt 0) {Write-Host "Retrying..."`n; $Error.Clear(); (New-Object System.Net.WebClient).DownloadFile($URL, $Output)}
    if ($Error.count -gt 0) {Write-Warning "$Name download failed";Write-Host}
    New-Variable -Name $Name"Output" -Value $Output -Scope Global -Force
}

# Function to run job with animation
function RunAnimatedJob{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Job = "Job",
        [Parameter(Mandatory)][scriptblock]$Tasks
	)
    Remove-Job * -ErrorAction SilentlyContinue
    Write-Host $Job -NoNewline
    Start-Job -Name $Job -ArgumentList $Tasks -ScriptBlock {
        param (
          [Parameter(Mandatory)][string]$ScriptBlock
        )
        $global:ProgressPreference = 'SilentlyContinue' # Disables progress bar for faster downloads
        $DriveLetter = $env:TEMP.Substring(0,3)
        & ([scriptblock]::Create($ScriptBlock))
    } | Out-Null
    $Colors = @([enum]::GetValues([System.ConsoleColor])) | Where {$_ -notmatch "Dark|Black"}
    do {
        do {
            $Color = Get-Random $Colors
        } until ($Color -ne $LastColor)
        $LastColor = $Color
        Write-Host . -NoNewline -ForegroundColor $Color
        Start-Sleep 1
    } until ((Get-Job -Name $Job -ErrorAction SilentlyContinue).State -eq "Completed")
    Write-Host `n
    Get-Job -Name $Job | Receive-Job
    Remove-Job * -ErrorAction SilentlyContinue
}

# Window size function
function Set-WindowState {
    <# .LINK https://gist.github.com/Nora-Ballard/11240204 #>

    [CmdletBinding(DefaultParameterSetName = 'InputObject')]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]] $InputObject,

        [Parameter(Position = 1)]
        [ValidateSet('FORCEMINIMIZE', 'HIDE', 'MAXIMIZE', 'MINIMIZE', 'RESTORE',
                     'SHOW', 'SHOWDEFAULT', 'SHOWMAXIMIZED', 'SHOWMINIMIZED',
                     'SHOWMINNOACTIVE', 'SHOWNA', 'SHOWNOACTIVATE', 'SHOWNORMAL')]
        [string] $State = 'SHOW',
        [switch] $SuppressErrors = $false,
        [switch] $SetForegroundWindow = $false
    )

    Begin {
        $WindowStates = @{
        'FORCEMINIMIZE'         = 11
            'HIDE'              = 0
            'MAXIMIZE'          = 3
            'MINIMIZE'          = 6
            'RESTORE'           = 9
            'SHOW'              = 5
            'SHOWDEFAULT'       = 10
            'SHOWMAXIMIZED'     = 3
            'SHOWMINIMIZED'     = 2
            'SHOWMINNOACTIVE'   = 7
            'SHOWNA'            = 8
            'SHOWNOACTIVATE'    = 4
            'SHOWNORMAL'        = 1
        }

        $Win32ShowWindowAsync = Add-Type -MemberDefinition @'
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll", SetLastError = true)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
'@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru

        if (!$global:MainWindowHandles) {
            $global:MainWindowHandles = @{ }
        }
    }

    Process {
        foreach ($process in $InputObject) {
            $handle = $process.MainWindowHandle

            if ($handle -eq 0 -and $global:MainWindowHandles.ContainsKey($process.Id)) {
                $handle = $global:MainWindowHandles[$process.Id]
            }

            if ($handle -eq 0) {
                if (-not $SuppressErrors) {
                    Write-Error "Main Window handle is '0'"
                }
                continue
            }

            $global:MainWindowHandles[$process.Id] = $handle

            $Win32ShowWindowAsync::ShowWindowAsync($handle, $WindowStates[$State]) | Out-Null
            if ($SetForegroundWindow) {
                $Win32ShowWindowAsync::SetForegroundWindow($handle) | Out-Null
            }

            Write-Verbose ("Set Window State '{1} on '{0}'" -f $MainWindowHandle, $State)
        }
    }
}

# Maximize window
Get-Process -ID $pid | Set-WindowState -State MAXIMIZE

# Script info
Write-Host "# PC Setup Script #" -ForegroundColor Cyan
Write-Host "# Ray Smalley     #" -ForegroundColor Cyan
Write-Host "# $LastUpdated    #"`n -ForegroundColor Cyan

# Check for internet connection
Write-Host "Checking for Internet connection..."`n
if (-not(Test-NetConnection 9.9.9.9).PingSucceeded) {
    Write-Warning "Internet not detected. Please connect then restart script."
    BeepBoop
    Read-Host "Press ENTER to exit"
    Exit 1
}

# Check if script name is correct
if ($MyInvocation.MyCommand.Name -notlike "new-pc-setup.ps1") {
    Write-Warning "Script name is not correct and may cause issues. Please rename it to new-pc-setup.ps1 and restart it."
    BeepBoop
    Read-Host "Press ENTER to exit"
    Exit 2
}

# Download latest version of script and replace it
Write-Host "Checking if newer version of script is available..."`n
$DriveLetter = $PSScriptRoot.Substring(0,3)
$OldScript = $MyInvocation.MyCommand.Path
$NewScript = $OldScript
$OldScriptHash = Get-FileHash $OldScript -Algorithm SHA1
Invoke-WebRequest https://raw.githubusercontent.com/RaySmalley/NewPCSetup/main/new-pc-setup.ps1 -UseBasicParsing -OutFile $NewScript
$NewScriptHash = Get-FileHash $NewScript -Algorithm SHA1
if ($OldScript -ne $NewScript) {Remove-Item $OldScript -Force}
if ($NewScriptHash.Hash -ne $OldScriptHash.Hash) {
    $ScriptUpdated = $true
    Write-Host "Script updated to latest version"`n
    Start-Sleep 2
} else {
    $ScriptUpdated = $false
    Write-Host "No update available"`n
}

# Test for elevation / restart script
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell "-ExecutionPolicy Bypass -File `"$NewScript`" -Exclude $Exclude" -Verb RunAs
    Exit
} else {
    if ($ScriptUpdated) {
        Write-Host Restarting script...`n
        Start-Sleep 1
        Start-Process PowerShell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
        #& "$PSCommandPath" ### I believe this causes the script to run twice sometimes
    }
}

# Check if script is old
$MasterLastUpdated = ((Invoke-WebRequest https://raw.githubusercontent.com/RaySmalley/PowerShell/master/new-pc-setup.ps1 -UseBasicParsing).ToString() -split "[`r`n]" | Select-String -Pattern "(0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])[- /.](19|20)[0-9]{2}").Matches[0].Value
if ([datetime]$MasterLastUpdated -gt [datetime]$LastUpdated) {
    Write-Warning "Script is out of date. See Ray for latest version."
}

# Rename computer
if (-not(Test-Path $env:TEMP\old-hostname.txt)) {
    BeepBoop
    Write-Host "Current computer name: $env:COMPUTERNAME"
    $NewName = Read-Host "Enter new computer name (leave blank to keep current name)"
    if ($NewName) {
        Rename-Computer -NewName $NewName | Out-Null
        Write-Host
        Write-Host "Renamed PC from $env:COMPUTERNAME to $NewName"`n
        Set-Content -Path $env:TEMP\old-hostname.txt -Value $env:COMPUTERNAME
    } else {
        Write-Host "Computer Name: $env:COMPUTERNAME"`n
    }
}

# Disable UAC (temporarily)
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force | Out-Null

# Set Time
Write-Host "Setting time..."`n
Set-TimeZone -Name "Eastern Standard Time"
Restart-Service "Windows Time"
w32tm /resync | Out-Null

# Remove local admin password if present
if (Get-LocalUser $env:USERNAME -ErrorAction SilentlyContinue) {Set-LocalUser -name "$env:USERNAME" -Password ([SecureString]::New())}

# Change power settings
Write-Host "Changing power settings..."`n
powercfg /change monitor-timeout-ac 20
powercfg /change standby-timeout-ac 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 # USB Selective Suspend

# Delete Edge shortcut from desktop
Remove-Item "C:\Users\*\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

# Allow script to run after reboot
$StartupScript = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\pc-setup-autostart.bat"
if (-not (Test-Path $StartupScript)) {
    New-Item $StartupScript -Force | Out-Null
    Add-Content $StartupScript "Start PowerShell -ExecutionPolicy Bypass -File $PSCommandPath"
}

# Install latest Windows build if not up to date
$OSVersion = [System.Environment]::OSVersion.Version.Major
$CurrentBuild = [System.Environment]::OSVersion.Version.Build
switch ($CurrentBuild) {
    22621 { $FriendlyBuild = "11 22H2" }
    22000 { $FriendlyBuild = "11 21H2" }
    19045 { $FriendlyBuild = "10 22H2" }
    19044 { $FriendlyBuild = "10 21H2" }
    19043 { $FriendlyBuild = "10 21H1" }
    19042 { $FriendlyBuild = "10 20H2" }
    19041 { $FriendlyBuild = "10 2004" }
    18363 { $FriendlyBuild = "10 1909" }
    18362 { $FriendlyBuild = "10 1903" }
    17763 { $FriendlyBuild = "10 1809" }
    17134 { $FriendlyBuild = "10 1803" }
    16299 { $FriendlyBuild = "10 1709" }
    15063 { $FriendlyBuild = "10 1703" }
    14393 { $FriendlyBuild = "10 1607" }
    10586 { $FriendlyBuild = "10 1511" }
}

Write-Host "Current build is Windows $FriendlyBuild"`n

    if ($CurrentBuild -lt 19045) {
        Write-Host "Updating to latest Windows 10 build..."`n
        Download -Name Windows10Upgrade -URL https://go.microsoft.com/fwlink/?LinkID=799445 -Filename Windows10Upgrade.exe
        Start-Process -FilePath $Windows10UpgradeOutput -ArgumentList /SkipEULA, /NoRestartUI -Verb RunAs -Wait
        Start-Sleep 30
    }

#switch ($CurrentBuild) {
#    {$_ -lt 19045} {
#        Write-Host "Updating to latest Windows 10 build..."`n
#        Download -Name Windows10Upgrade -URL https://go.microsoft.com/fwlink/?LinkID=799445 -Filename Windows10Upgrade.exe
#        Start-Process -FilePath $Windows10UpgradeOutput -ArgumentList /SkipEULA, /NoRestartUI -Verb RunAs -Wait
#        Start-Sleep 30
#    }
#    {$_ -ge 22000 -and $_ -lt 22621} {
#        Write-Host "Updating to latest Windows 11 build..."`n
#        Download -Name Windows11Upgrade -URL https://go.microsoft.com/fwlink/?linkid=2171764 -Filename Windows11Upgrade.exe
#        Start-Process -FilePath $Windows11UpgradeOutput -ArgumentList /SkipEULA, /NoRestartUI, /SkipCompatCheck -Verb RunAs -Wait
#        Start-Sleep 30
#    }
#}

# Windows Updates
Write-Host "Checking for Windows Updates..."`n
Install-PackageProvider -Name NuGet -Force | Out-Null
Install-Module PSWindowsUpdate -Force
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    if (Get-WindowsUpdate) {
        Write-Host "Windows Updates found. Installing..."`n
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot
        Write-Host
        Write-Host "Windows Updates installed"`n
        #Restart-Computer -Force -Wait 10
    } else {
        Write-Host "No updates available"`n
    }
} else {
    Write-Warning "Windows Update Module not installed. Cannot look for updates. Try restarting computer/script."
}

# Dell Command Update
if ((Get-WmiObject -Class:Win32_ComputerSystem).Manufacturer -like "*Dell*") {
    [System.Version]$dcuLatest = "4.7.1"
    $dcuVersion = [System.Version](Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -like "*Command | Update*"}).DisplayVersion
    if (-not $dcuVersion) {$dcuVersion = [System.Version](Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -like "*Command | Update*"}).DisplayVersion}
    if ($dcuVersion -lt $dcuLatest) {
    Write-Host "Installing latest Dell Command Update..."`n
        Download -Name DellCommandUpdate -URL https://dl.dell.com/FOLDER09268356M/1/Dell-Command-Update-Windows-Universal-Application_CJ0G9_WIN_4.7.1_A00.EXE
        Start-Process -FilePath $DellCommandUpdateOutput -ArgumentList /s -Wait
    }
    if ((Test-Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe") -or (Test-Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe")) {
        Write-Host "Running Dell Command Update..."
            Start-Process "C:\Program Files*\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList /applyUpdates, -reboot=enable -Wait
            Start-Sleep 15
            Write-Host
    } else {
        Write-Warning "Dell Command Update not installed. Skipping..."; Write-Host
    }
}

# Install Microsoft Store and Pre-installed Packages if missing
if (-Not (Get-AppxPackage -Name Microsoft.WindowsStore)) {
    Write-Host "Microsoft Store is missing. Installing it and all normally pre-installed apps..."`n
    Get-AppXPackage *WindowsStore* -AllUsers | foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
    $Packages = (get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications') | Get-ChildItem
    foreach($Package in $Packages) {
	    $PackageName = $Package | Get-ItemProperty | Select-Object -ExpandProperty PSChildName
	    $PackagePath = [System.Environment]::ExpandEnvironmentVariables(($Package | Get-ItemProperty | Select-Object -ExpandProperty Path))
    	Add-AppxPackage -Register $PackagePath -DisableDevelopmentMode
    }
}

# Install Google Chrome
if (-not (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" | Where {$_.PSChildName -match "chrome"})) {
    if ($Exclude -notmatch "Chrome") {
    Write-Host "Installing Google Chrome..."`n
        Download -Name GoogleChrome -URL http://dl.google.com/chrome/install/375.126/chrome_installer.exe
        Start-Process -FilePath $GoogleChromeOutput -ArgumentList /silent, /install -Wait
        if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" | Where {$_.PSChildName -match "chrome"}) {
            Write-Host "Google Chrome installation complete"`n
        } else {
            Write-Warning "Google Chrome installation failed"; Write-Host
        }
    } else {
        Write-Host "Google Chrome excluded. Skipping..."`n
    }
} else {
   Write-Host "Google Chrome already installed. Skipping..."`n
}

# Install Adobe Reader
if (-not (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" | Where {$_.PSChildName -match "AcroRd32"}) -or ($Exclude -match "Adobe")) {
    if ($Exclude -notmatch "Adobe") {   
        Write-Host "Installing Adobe Reader..."`n
        $ChocoOutput = "$env:TEMP\installChocolatey.ps1"
        Invoke-WebRequest -Uri 'https://chocolatey.org/install.ps1' -UseBasicParsing -OutFile $ChocoOutput
        $Result = Get-AuthenticodeSignature -FilePath $ChocoOutput
        if ($Result.Status -eq 'Valid') {
            $env:ChocolateyInstall='C:\ProgramData\chocoportable'
            Start-Process -FilePath PowerShell -ArgumentList "-noprofile -ExecutionPolicy Bypass -File ""$ChocoOutput""" -Wait -WindowStyle Hidden
            C:\ProgramData\chocoportable\choco.exe install adobereader -params '"/DesktopIcon /UpdateMode:3"' -y --force | Out-Null
            if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" | Where {$_.PSChildName -match "AcroRd32"}) {
                Write-Host "Adobe Reader installation complete"`n
            } else {
                Write-Warning "Adobe Reader installation failed"; Write-Host
            }
        } else {
            Write-Warning "Chocolatey installation script damaged. Adobe Reader installation failed."
            BeepBoop
            Start-Sleep 10
            Write-Host
        }
    } else {
        Write-Host "Adobe Reader excluded. Skipping..."`n
    }
} else {
    Write-Host "Adobe Reader already installed. Skipping..."`n
}

# Download Office Deployment Toolkit
if (((Get-ChildItem "$env:TEMP\Office365\setup.exe" -ErrorAction SilentlyContinue).LastAccessTime -lt (Get-Date).AddMonths(-1)) -or (-not(Test-Path "$env:TEMP\Office365\setup.exe" -ErrorAction SilentlyContinue))) {
    Write-Host "Downloading Office Deployment Tool..."`n
    New-Item -ItemType Directory -Force -Path $env:TEMP\Office365 | Out-Null
    $URL = ((Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117 -UseBasicParsing).links | Where-Object {$_.outerHTML -like "*click here to download manually*"}).href
    Download -Name ODT -URL $URL -Filename ODT.exe
    Start-Process -FilePath $ODTOutput -ArgumentList /quiet, /extract:""$env:TEMP""\Office365\ -Wait
    Remove-Item $env:TEMP\Office365\*.xml -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $env:TEMP\Office365\setup.exe)) {
        Write-Warning "ODT Extraction failed"
        Write-Warning "Not found: $env:TEMP\Office365\setup.exe"
    }
}

# Remove Office trials if installed
$OfficeRemovalXML = @'
<Configuration>
  <Display Level="None" AcceptEULA="True" />
  <Logging Level="Standard" Path="$env:TEMP\OfficeRemovalLogs" />
  <Remove All="TRUE" />
</Configuration>
'@
$OfficeRemovalXML > "$env:TEMP\Office365\RemoveOffice.xml"

if (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where {$_.DisplayName -match "es-es" -or $_.DisplayName -match "Microsoft 365 - en-us"}){
    Write-Host "Removing Office trial..."`n
    Start-Process -FilePath "$env:TEMP\Office365\setup.exe" -ArgumentList /configure, "$env:TEMP\Office365\RemoveOffice.xml" -WindowStyle Hidden -Wait
    if (-not (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where {$_.DisplayName -match "es-es" -or $_.DisplayName -match "Microsoft 365 - en-us"})) {
        Write-Host "Office trial removal complete. Restarting computer..."`n
        Start-Sleep 5
        Restart-Computer -Force
    } else {
        Write-Warning "Office trial removal failed. Please uninstall Office trial manually and restart script."`n
        BeepBoop
        Start-Sleep 10
        Write-Host
    }
}

# Download and install Office 365
function OfficeIsNotInstalled {
    (-not(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where {$_.DisplayName -match "Microsoft 365 Apps for business"}))
}

$Office365BusinessRetailXML = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="Current" SourcePath="$env:TEMP\Office365">
    <Product ID="O365BusinessRetail">
      <Language ID="en-us" />
    </Product>
  </Add>
  <Updates Enabled="TRUE" />
  <Display Level="Full" AcceptEULA="TRUE" />
  <Logging Level="Standard" Path="$env:TEMP\OfficeInstallLogs" />
</Configuration>
"@
$Office365BusinessRetailXML > "$env:TEMP\Office365\Office365BusinessRetail.xml"

if (-not (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where {$_.DisplayName -match "es-es"})) {
    if (OfficeIsNotInstalled) {
        Write-Host "Downloading Office 365..."`n
        $LocalDiskSpace = (Get-Volume ($DriveLetter.Substring(0,1))).SizeRemaining
        $OfficeFilesSize = (Get-ChildItem -Recurse "$env:TEMP\Office365" -ErrorAction SilentlyContinue | Measure-Object -Sum Length).Sum
        if ($LocalDiskSpace -gt $OfficeFilesSize -and $LocalDiskSpace -ge 8GB) {
            if ($OfficeFilesSize -lt 3GB) {
                Start-Process -FilePath $env:TEMP\Office365\setup.exe -ArgumentList /download, $env:TEMP\Office365\Office365BusinessRetail.xml -WindowStyle Hidden -Wait
                $OfficeFilesSize = (Get-ChildItem -Recurse "$env:TEMP\Office365" -ErrorAction SilentlyContinue | Measure-Object -Sum Length).Sum
                if ($OfficeFilesSize -lt 3GB) {
                    Write-Warning "Office download doesn't appear complete. Restarting computer to try again..."
                    for ($i = 5;$i -ne 0) {
                        Write-Host $i
                        $i -= 1
                        Start-Sleep 1
                        if ($i -eq 0) {
                            Write-Host "See ya soon!"
                            Restart-Computer -Force
                        }
                    }
                }
            }
        } else {
            Write-Warning "Not enough space on $DriveLetter to download Office"
            BeepBoop
            Read-Host "Press ENTER to continue"
        }
        $OfficeFilesSize = (Get-ChildItem -Recurse "$env:TEMP\Office365" -ErrorAction SilentlyContinue | Measure-Object -Sum Length).Sum
        if ($OfficeFilesSize -gt 3GB) {
            Write-Host "Installing Office 365..."`n
            Start-Process -FilePath "$env:TEMP\Office365\setup.exe" -ArgumentList /configure, "$env:TEMP\Office365\Office365BusinessRetail.xml" -WindowStyle Hidden -Wait
        } else {
            Write-Warning "Office download still doesn't seem to be the right size. Try deleting it and re-running the script."
            Write-Host
        }
        if (-not(OfficeIsNotInstalled)) {
            Write-Host "Office 365 installation complete"`n
        } else {
            Write-Warning "Office 365 installation failed"
            Write-Warning "Review logs at $env:TEMP\OfficeInstallLogs\"
            BeepBoop
            Read-Host "Press ENTER to continue"
        }
    } else {
        Write-Host "Office 365 already installed. Skipping..."`n
    }
} else {
    Write-Warning "Office trial still installed. Manually uninstall or try re-running script."
    Write-Host
}

# End prompt
Write-Host "Done! Don't forget to install the N-able Agent!"`n -ForegroundColor Green
BeepBoop
Read-Host -Prompt "Press ENTER to wrap things up"

# Add 415 Group local admin
if (-not (Get-LocalUser 415Admin -ErrorAction SilentlyContinue)) {
    Write-Host "Creating 415Admin user..."`n
    net user 415Admin * /add 
    net localgroup Administrators 415Admin /add
    wmic useraccount WHERE "Name='415Admin'" set PasswordExpires=false
    Write-Host "415Admin local admin created"`n
} else {
    Write-Host "Creating a password for 415Admin user..."`n
    net user 415Admin *
    Write-Host "Password created"`n
}

# Remove McAfee products
Write-Host "Removing McAfee products if installed..."`n
function McAfee {Get-Package -Name *McAfee* -ErrorAction SilentlyContinue}
if (McAfee) {
    Download -Name McAfeeRemover -URL https://download.mcafee.com/molbin/iss-loc/SupportTools/MCPR/MCPR.exe
    Start-Process $McAfeeRemoverOutput -Wait
    McAfee | foreach {& $_.Meta.Attributes['UninstallString'] /s; Write-Host "Removing $_.Name"`n}
    if (-not(McAfee)) {
        Write-Host "McAfee removal successful"`n
    } else {
        Write-Warning "McAfee removal failed. Please remove manually."; Write-Host
    }
}

# Cleanup
if ($StartupScript) {Remove-Item $StartupScript -Force -ErrorAction SilentlyContinue}
if ($Windows10UpgradeOutput) {Remove-Item $Windows10UpgradeOutput -Force -ErrorAction SilentlyContinue}
if ($DellCommandUpdateOutput) {Remove-Item $DellCommandUpdateOutput -Force -ErrorAction SilentlyContinue}
if ($GoogleChromeOutput) {Remove-Item $GoogleChromeOutput -Force -ErrorAction SilentlyContinue}
if ($McAfeeRemoverOutput) {Remove-Item $McAfeeRemoverOutput -Force -ErrorAction SilentlyContinue}
if ($ODTOutput) {Remove-Item $ODTOutput -Force -ErrorAction SilentlyContinue}
Remove-Item "$env:TEMP\AdobeReaderSetup.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\new-pc-setup.zip" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\DCU" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\installChocolatey.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\chocolatey" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\chocoportable" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\Office365" -Recurse -Force -ErrorAction SilentlyContinue

# Re-enable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force | Out-Null

Stop-Transcript