$ConsoleWindow = $Host.UI.RawUI                                                                             #Gets the Window Properties
$ConsoleWindow.BackgroundColor = "DarkBlue"                                                                 #Sets the Background Color, Default is -1
$ConsoleWindow.ForegroundColor = "Gray"                                                                     #Sets the Forground (Text) Color, Default is -1

Clear                                                                                                       #Clears any previous text
""
""
$OS = Get-WmiObject -class Win32_OperatingSystem | Select Caption, OSArchitecture, ServicePackMajorVersion  #Gets the OS version, Bit Version (x86/x64), and Service Pack Version
"Your OS is: "
"     " +               $OS.Caption
"     Service Pack: " + $OS.ServicePackMajorVersion
"     " +               $OS.OSArchitecture

CD C:\ | Out-Null
New-Item "HardeningLogs" -ItemType Directory | Out-Null                                                     #Creates the Log Directory
$LogsDirectory = "C:\HardeningLogs"                                                                         #Saves the Directory location to a variable
CD $LogsDirectory
$Desktop = [Environment]::GetFolderPath("Desktop")                                                          #Gets the desktop path and saves it to a variable


#MS08_067 fix
if ($OS.Caption -Like "*2008*") {
  if ($OS.Caption -NotLike "*R2*") {
    if ($OS.OSArchitecture -Like "*64*") {
      $Path = [Environment]::GetFolderPath("Desktop") + "\MS08_067 Fix x64.exe"
      $URL = "https://download.microsoft.com/download/0/f/4/0f425c69-4a1f-4654-b4f8-476a5b1bae1d/Windows6.0-KB958644-x64.msu"
      $Client = New-Object System.Net.WebClient
      $Client.DownloadFile($URL, $Path)
    }
    if ($OS.OSArchitecture -Like "*86*") {
      $Path = [Environment]::GetFolderPath("Desktop") + "\MS08_067 Fix x86.exe"
      $URL = "https://download.microsoft.com/download/d/c/0/dc047ab9-53f8-481c-8c46-528b7f493fc1/Windows6.0-KB958644-x86.msu"
      $Client = New-Object System.Net.WebClient
      $Client.DownloadFile($URL, $Path)
    }
  }
}



#####################################################################################################################################################
#MS09_050
if ($OS.Caption -Like "*2008*") {
  if ($OS.OSArchitecture -Like "*64*") {
    $Path = [Environment]::GetFolderPath("Desktop") + "\MS09_050 Fix x64.exe"
    $URL = "https://download.microsoft.com/download/D/E/6/DE69BD2A-6C70-4716-BD73-E933CC884F23/Windows6.0-KB975517-x64.msu"
    $Client = New-Object System.Net.WebClient
    $Client.DownloadFile($URL, $Path)
  }
  
  if ($OS.OSArchitecture -Like "*86*") {
    $Path = [Environment]::GetFolderPath("Desktop") + "\MS08_050 Fix x64.exe"
    $URL = "https://download.microsoft.com/download/6/A/2/6A2934BE-066F-4280-8B26-FADD7D4080FD/Windows6.0-KB975517-x86.msu"
    $Client = New-Object System.Net.WebClient
    $Client.DownloadFile($URL, $Path)
  }
}

#Disable Remote Management of Windows Firewall
netsh advfirewall firewall set rule group="Windows Remote Management" new enable=no



#####################################################################################################################################################
""
""
"###############################################################################"
"###############################################################################"
"###############################################################################"
"                            BACKING UP FILES                                   "
"###############################################################################"
"###############################################################################"
"###############################################################################"
"Making A Backup Of All Services"
Get-WmiObject -class win32_service | Select-Object DisplayName | Sort-Object -Descending | Out-File "C:\HardeningLogs\Services Before Format.txt"       #Gets all services on the system and saves to a file
Get-Content "C:\HardeningLogs\Services Before Format.txt" | Select-Object -Skip 3 | Out-File "C:\HardeningLogs\Service list for array.txt"              #Gets rid of the first three lines in the file and sorts it before saving into a new file
$ServiceList = Get-Content "C:\HardeningLogs\Service list for array.txt"
"Done!"
"###############################################################################"
"Making a backup of listening connections"
NETSTAT -ARP | Out-File "C:\HardeningLogs\Netstat.txt"                                                      #Gets all listening connections
"Done!"
"###############################################################################"
"Making A Prohibited File Log Of C:\"
#Gets Media/Script/Torrent/etc. type files
Get-ChildItem "C:\Users\*" -Recurse -Include *.air, *.iff, *.m3u, *.m4a, *.mid, *.mp3, *.mpa, *.ra, *.wav, *.wma, *.3g2, *.3gp, *.asf, *.asx, *.avi, *.flv, *.m4v, *.mov, *.mp4, *.mpg, *.rm, *.srt, *.swf, *.vob, *.wmv, *.3dm, *.3ds, *.max, *.obj, *.bmp, *.dds, *.gif, *.jpg, *.png, *.psd, *.pspimage, *.tga, *.thm, *.tif, *.tiff, *.yuv, *.ai, *.eps, *.ps, *.svg, *.indd, *.pct, *.pdf, *.apk, *.app, *.bat, *.cgi, *.com, *.gadget, *.jar, *.pif, *.vb, *.wsf, *.dem, *.gam, *.nes, *.rom, *.sav, *.aspx, *.cer, *.cfm, *.csr, *.css, *.htm, *.html, *.js, *.jsp, *.php, *.rss, *.xhtml, *.crx, *.plugin, *.fnt, *.fon, *.otf, *.ttf, *.cab, *.drv, *.sys, *.cfg, *.ini, *.prf, *.bin, *.cue, *.dmg, *.iso, *.mdf, *.toast, *.vcd, *.c, *.class, *.cpp, *.cd*.dtd, *.fla, *.h, *.java, *.lua, *.m, *.pl, *.py, *.sh, *.sln, *.swift, *.vcxproj, *.xcodeproj, *.back, *.tmp, *.crdownload, *.msi, *.part, *.torrent | Out-File "C:\HardeningLogs\File Extention Report.txt"
Get-ChildItem "C:\*" -Recurse -Include *lsass*, *r57*, *weevely*, *c99*, *b374k*, *caidao*, *php99eb*, *php9cba* | Out-File "C:\HardeningLogs\Possible Backdoors.txt"
"Done!"
"###############################################################################"
"Making Log Of C:\Program Files & C:\ProgramData"
DIR "C:\Program Files" | Out-File "C:\HardeningLogs\Basic Program Files.txt"                                #Gets a basic version of C:\Program Files
Get-ChildItem -Recurse -Path "C:\Program Files" | Out-File "C:\HardeningLogs\Full Program Files.txt"        #Gets a full listing in C:\Program Files
DIR "C:\Program Files" | Out-File "C:\HardeningLogs\Basic ProgramData.txt"                                  #Gets a basic version of C:\ProgramData
Get-ChildItem -Recurse -Path "C:\ProgramData" | Out-File "C:\HardeningLogs\Full ProgramData.txt"            #Gets a full listing in C:\ProgramData
"Done!"
"###############################################################################"
"Making A Backup Of The Hosts File"
$HostsFile = "C:\Windows\System32\drivers\etc\"                                                             #Makes a backup of the current hosts file
CD $HostsFile
Copy-Item hosts $LogsDirectory
CD $LogsDirectory
Rename-Item hosts HostBackup
"Done!"

"###############################################################################"
"###############################################################################"
"###############################################################################"
"                          Checking for programs                                "
"###############################################################################"
"###############################################################################"
"###############################################################################"
""
""
"Checking for SlimCleaner Plus"
$SlimCleaner = Test-Path "C:\Program Files\SlimCleaner Plus"
if ($SlimCleaner -eq "True")
{
  "Removing SlimCleaner Plus"
  Stop-Service -Force -DisplayName "SlimWare Utility Service Launcher"
  Set-Service -StartupType "Disabled" -DisplayName "SlimWare Utility Service Launcher"
  TASKKILL /F /IM "SlimCleanerPlus.exe"
  Remove-Item -Path "C:\Program Files\SlimeCleaner Plus" -Recurse -Force
}



"###############################################################################"
"###############################################################################"
"###############################################################################"
"                          STARTING USER CONTROL                                "
"###############################################################################"
"###############################################################################"
"###############################################################################"
$Users = Get-WmiObject -Class Win32_UserAccount -Filter LocalAccount="False"                              #Gets local Accounts
$ModulesLoaded = Get-Module
if (!$ModulesLoaded -Like "ActiveDirectory") {
  Import-Module ServerManager
  Add-WindowsFeature RSAT-AD-PowerShell
}
$Users = Get-ADUser -Filter * | Out-File "C:\HardeningLogs\AllADUsers.txt"
$Password = "p@55w0rd5@reG0"                                                                              #Hardcoded password
$Computer = [ADSI]("WinNT://$env:COMPUTERNAME, Computer")                                                 #Starts Active Directory Services
$AdminUsers = @()                                                                                         #Array for users that are Admin
$UserUsers = @()                                                                                          #Array for users that are Standard Users
$i = -1                                                                                                   #I want to see the visual representation of this

$Computer.PSBase.Children.Find("Administrators", "Group").PSBase.Invoke("Members") | foreach {            #Populates AdminUsers with all accounts that are admin
  $AdminUsers += $_.GetType().InvokeMember("Name", "GetProperty", $null,  $_, $null)
}
$Computer.PSBase.Children.Find("Users", "Group").PSBase.Invoke("Members") | foreach {                     #Populates UserUsers with all accounts that are Standard Users
  $UserUsers += $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null)
}


foreach($CurrentUser in $Users)
{
  $i = $i + 1                                                                                             #Advances to the next user in the list
  $CurrentUser = $Users[$i].name                                                                          #Current User being proccessed
  $UserAdminCheck = "False"                                                                               #Checks if the Admin Check is correct
  $IsUserAuthorized = Read-Host "Is $CurrentUser supposed to be on this system? (y/n)"                    #Asks whether the user needs to be deleted
  if($IsUserAuthorized -eq "n")                                                                           #Checks if user needs to be deleted
  {
    $DoubleCheck = Read-Host "Delete $CurrentUser? (y/n)"                                                 #Double checks if user needs to be deleted
    if($DoubleCheck -eq "y")
    {
      NET USER /DELETE $CurrentUser                                                                       #Deletes User. Not Out-Null because it checks if its still there
      $UserDeleted = "True"
    }
  }

  if ($UserDeleted -ne "True")                                                                            #Checks if $CurrentUser is in the $AdmingGroup and/or $UsersGroup. If the user was deleted this code block is skipped
  {
    while($UserAdminCheck -ne "True")                                                                     #Checks if the current user is supposed to be Admin. Does not advance unless proper response is given
    {
      $IsSupposedToBeAdmin = Read-Host "Is $CurrentUser supposed to be admin? (y/n)"                      #Asks user if current user is supposed to be Admin.
      if($IsSupposedToBeAdmin -eq "y")                                                                    #User is supposed to be Admian
      {
        $UserAdminCheck = "True"                                                                          #Stops the WHILE loop
      }
      elseif($IsSupposedToBeAdmin -eq "n")                                                                #User is not supposed to be Admin
      {
        $UserAdminCheck = "True"                                                                          #Stops the WHILE loop
      }
      else                                                                                                #Proper Response was not given
      {
        $UserAdminCheck = "False"                                                                         #Continues while loop
      }
    }
    
    if ($IsSupposedToBeAdmin -eq "n" -and $AdminUsers -contains $CurrentUser)                             #The user is not supposed to be in the Admin group but is
    {
      NET LOCALGROUP ADMINISTRATORS $CurrentUser /DELETE                                                  #Removes the current user from the Admin group
      if ($UserUsers -notcontains $CurrentUser)                                                           #The user is not in the Users group but should be
      {
        NET LOCALRGOUP USERS $CurrentUser /ADD                                                            #Adds the current user to the Users group
      }
    }
    
    if ($IsSupposedToBeAdmin -eq "y" -and $AdminUsers -notcontains $CurrentUser)                          #The user is supposed to be admin but is not
    {
      NET LOCALGROUP ADMINISTRATORS $CurrentUser /ADD                                                     #Adds the user to the Admin group
      if ($UserUsers -contains $CurrentUser)                                                              #The user is in Users group but shouldn't be
      {
        NET LOCALGROUP USERS $CurrentUser /DELETE                                                         #Removes Current User from Users group
      }
    }
  
    "Setting $CurrentUser password"
    NET USER $CurrentUser $Password                                                                       #Sets the Current Users password
  }
}
"Done!"


"###############################################################################"
"###############################################################################"
"###############################################################################"
"                          STARTING GROUP POLICY                                "
"###############################################################################"
"###############################################################################"
"###############################################################################"
"Setting All Services"
Set-Service -StartupType "Disabled" -DisplayName "Credidential Manager"
Set-Service -StartupType "Disabled" -DisplayName "Desktop Window Manager Session Manager"
Set-Service -StartupType "Disabled" -DisplayName "Performance Logs & Alerts"
Set-Service -StartupType "Disabled" -DisplayName "Print Spooler"
Set-Service -StartupType "Disabled" -DisplayName "PS3 Media Server"
Set-Service -StartupType "Disabled" -DisplayName "Remote Desktop Services UserMode Port Redirector"
Set-Service -StartupType "Disabled" -DisplayName "Remote Registry"
Set-Service -StartupType "Disabled" -DisplayName "Routing and Remote Access"
Set-Service -StartupType "Disabled" -DisplayName "Telephony"
Stop-Service -Force -DisplayName "Credential Manager"
Stop-Service -Force -DisplayName "Desktop Window Manager Session Manager"
Stop-Service -Force -DisplayName "Performance Logs & Alerts"
Stop-Service -Force -DisplayName "Print Spooler"
Stop-Service -Force -DisplayName "PS3 Media Server"
Stop-Service -Force -DisplayName "Remote Desktop Services UserMode Port Redirector"
Stop-Service -Force -DisplayName "Remote Registry"
Stop-Service -Force -DisplayName "Routing and Remote Access"
Stop-Service -Force -DisplayName "Telephony"



#Set-Service   -StartupType "Automatic" -DisplayName "Bitlocker Drive Encryption Service"
#Set-Service   -StartupType "Automatic" -DisplayName "Performance Logs & Alerts"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Backup"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Defender"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Error Reporting Service"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Event Collector"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Event Log"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Firewall"
Set-Service   -StartupType "Automatic" -DisplayName "Windows Search"
#Start-Service -DisplayName "BitLocker Drive Encryption Service"
#Start-Service -DisplayName "Performance Logs & Alerts"
Start-Service -DisplayName "Windows Backup"
Start-Service -DisplayName "Windows Defender"
Start-Service -DisplayName "Windows Error Reporting Service"
Start-Service -DisplayName "Windows Event Collector"
Start-Service -DisplayName "Windows Event Log"
Start-Service -DisplayName "Windows Firewall"
Start-Service -DisplayName "Windows Search"
"Done"
"###############################################################################"
"Setting Windows Update Options"

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "AUOptions"                        /T "REG_DWORD" /D "4" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "AutoInstallMinorUpdates"          /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "NoAutoRebootWithLoggedOnUsers"    /T "REG_DWORD" /D "0" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "NoAutoUpdate"                     /T "REG_DWORD" /D "0" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "ScheduledInstallDay"              /T "REG_DWORD" /D "0" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "ScheduledInstallTime"             /T "REG_DWORD" /D "9" /F | Out-Null
RED ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V "UseWUServer"                      /T "REG_DWORD" /D "0" /F | Out-Null
"Done!"
"###############################################################################"
"Setting Remote Desktop Options"

$RemoteDesktopEnabled = Read-Host "Should Remote Desktop be enabled? (y/n)"
if ($RemoteDesktopEnabled -ne "y") #If Remote Desktop Needs to be disabled
{
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"    /V "fDenyTSConnections"   /T "REG_DWORD" /D "1" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"    /V "AllowRemoteRPC"       /T "REG_DWORD" /D "0" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance"      /V "fAllowFullControl"    /T "REG_DWORD" /D "0" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance"      /V "fAllowToGetHelp"      /T "REG_DWORD" /D "0" /F | Out-Null
}
 else #If Remote Desktop Needs to be Enabled
{
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"    /V "fDenyTSConnections"   /T "REG_DWORD" /D "0" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"    /V "AllowRemoteRPC"       /T "REG_DWORD" /D "0" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance"      /V "fAllowFullControl"    /T "REG_DWORD" /D "1" /F | Out-Null
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance"      /V "fAllowToGetHelp"      /T "REG_DWORD" /D "1" /F | Out-Null
}

"Done!"


"###############################################################################"
"Set UAC Levels"
#Sets User Account Control Settings from registry
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "FilterAdministratorToken"     /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "ConsentPromptBehaviorAdmin"   /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "ConsentPromptBehaviorUser"    /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableInstallerDetection"     /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "ValidateAdminCodeSignatures"  /T "REG_DWORD" /D "0" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableSecureUIAPaths"         /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA"                    /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "PromptOnSecureDesktop"        /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableVirtualization"         /T "REG_DWORD" /D "1" /F | Out-Null
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableUIDesktopToggle"        /T "REG_DWORD" /D "0" /F | Out-Null
"Done!"


"###############################################################################"
"Setting (Some) Local Seciruty Policies"
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan PrintServices\Servers" /V "AddPrinterDrivers"             /T "REG_DWORD" /D "1"    /F | Out-Null #Do not let users install printer divers
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"                                          /V "NoLmHash"                      /T "REG_DWORD" /D "1"    /F | Out-Null #Disables storing LM Hash value
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"                                          /V "restrictanonymoussam"          /T "REG_DWORD" /D "1"    /F | Out-Null # Restricts anon Sam accounts
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"                     /V "AutoShareWks"                  /T "REG_DWORD" /D "0"    /F | Out-Null #No Admin Shares
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"                           /V "DisabledComponets"             /T "REG_DWORD" /D "0xff" /F | Out-Null #Disables IPv6
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"                    /V "ForceClassicControlPanel"      /T "REG_DWORD" /D "1"    /F | Out-Null #Forces Classic Control Panel View
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar"            /V "TurnoffSidebar"                /T "REG_DWORD" /D "1"    /F | Out-Null #Disables Desktop Gadgets
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar"            /V "TurnoffUserInstalledgadgets"   /T "REG_DWORD" /D "1"    /F | Out-Null #Disables User Gadgets
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"                     /V "LocalAccountTokenFilterPolicy" /T "REG_DWORD" /D "0"    /F | Out-Null #Stigs
"Done!"
