<# 
Microsoft Cloud Workshop: BCDR
.File Name
 - SQLVM1Config.ps1
 
.What calls this script?
 - This is a PowerShell DSC script running as Script Extension called by BCDRIaaSPrimarySite.json

.What does this script do?  
 - Initializes a new data disk, formats and give the letter F:\ and creates Backup, Data and Logs directories
    
 - Sets SQL Configs: Directories made as defaults, Enables TCP, Eables Mixed Authentication SA Account

 - Downloads the ContosoInsurnace Database as a Backup Device, then Restores the Database

 - Adds the Domain Built-In Administrators to the SYSADMIN group

 - Changes to Recovery type of the DB to "Full Recovery" and then performs a Backup to meet the requirements of AOG

 - Opens three Firewall ports in support of the AOG:  1433 (default SQL), 5022 (HADR Listener), 59999 (Internal Loadbalacer Probe)

#>

Configuration Main
{

Param ( [string] $nodeName )

function disable-ssl-2.0 {
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server’ -Force
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server’ -Name Enabled -Value 0 –PropertyType DWORD
    Write-Host "Disabling SSLv2"
}
function disable-ssl-3.0 {
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server’ -Force
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server’ -Name Enabled -Value 0 –PropertyType DWORD
    Write-Host "Disabling SSLv3"
}
function disable-tls-1.0 {
    New-Item “HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\PROTOCOLS” –Name “TLS 1.0”
    New-Item “HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\PROTOCOLS\TLS 1.0” –Name SERVER
    New-ItemProperty “HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\PROTOCOLS\TLS 1.0\SERVER” –Name Enabled –Value 0 –Type DWORD
    Write-Host "Disabling TLSv1.0"
}
function enable-tls-1.1 {
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server’ -Force
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client’ -Force
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server’ -Name ‘Enabled’ -Value ‘0xffffffff’ –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server’ -Name ‘DisabledByDefault’ -Value 0 –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client’ -Name ‘Enabled’ -Value 1 –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client’ -Name ‘DisabledByDefault’ -Value 0 –PropertyType DWORD
    Write-Host "Enabling TLSv1.1"
}
function enable-tls-1.2 {
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server’ -Force
    New-Item ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client’ -Force
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server’ -Name ‘Enabled’ -Value ‘0xffffffff’ –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server’ -Name ‘DisabledByDefault’ -Value 0 –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client’ -Name ‘Enabled’ -Value 1 –PropertyType DWORD
    New-ItemProperty -Path ‘HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client’ -Name ‘DisabledByDefault’ -Value 0 –PropertyType DWORD
    Write-Host "Enabling TLSv1.2"
}

Import-DscResource -ModuleName PSDesiredStateConfiguration

Node $nodeName
  {
    Script ConfigureSql
    {
        TestScript = {
            return $false
        }
        SetScript ={
		$disk = Get-Disk | where-object PartitionStyle -eq "RAW"
		$disk | Initialize-Disk -PartitionStyle MBR -PassThru -confirm:$false
		$partition = $disk | New-Partition -UseMaximumSize -DriveLetter F
		$partition | Format-Volume -Confirm:$false -Force
	
		Start-Sleep -Seconds 60

		$logs = "F:\Logs"
		$data = "F:\Data"
		$backups = "F:\Backup" 
		[system.io.directory]::CreateDirectory($logs)
		[system.io.directory]::CreateDirectory($data)
		[system.io.directory]::CreateDirectory($backups)
		
		# Setup the data, backup and log directories as well as mixed mode authentication
		Import-Module "sqlps" -DisableNameChecking
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo")
		$sqlesq = new-object ('Microsoft.SqlServer.Management.Smo.Server') Localhost
		$sqlesq.Settings.LoginMode = [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed
		$sqlesq.Settings.DefaultFile = $data
		$sqlesq.Settings.DefaultLog = $logs
		$sqlesq.Settings.BackupDirectory = $backups
		$sqlesq.Alter() 

		# Enable TCP Server Network Protocol
		$smo = 'Microsoft.SqlServer.Management.Smo.'  
		$wmi = new-object ($smo + 'Wmi.ManagedComputer').  
		$uri = "ManagedComputer[@Name='" + (get-item env:\computername).Value + "']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='Tcp']"  
		$Tcp = $wmi.GetSmoObject($uri)  
		$Tcp.IsEnabled = $true  
		$Tcp.Alter() 

		# Restart the SQL Server service
		Restart-Service -Name "MSSQLSERVER" -Force

		# Re-enable the sa account and set a new password to enable login
		Invoke-Sqlcmd -ServerInstance Localhost -Database "master" -Query "ALTER LOGIN sa ENABLE"
		Invoke-Sqlcmd -ServerInstance Localhost -Database "master" -Query "ALTER LOGIN sa WITH PASSWORD = 'demo@pass123'"

		# Get the Contoso Insurance database backup 
		$dbsource = "https://github.com/CoskunOzaltin/MCW-Business-continuity-and-disaster-recovery/raw/master/Hands-on%20lab/NestedDeployments/CustomScripts/ContosoInsurance.bak"
		#$dbsource = "https://www.dropbox.com/s/z90t4rpy8b8z1cq/ContosoInsurance.bak?dl=1"
		$dbdestination = "C:\ContosoInsurance.bak"
		Invoke-WebRequest $dbsource -OutFile $dbdestination

		$mdf = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("ContosoInsurance", "F:\Data\ContosoInsurance.mdf")
		$ldf = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("ContosoInsurance_Log", "F:\Logs\ContosoInsurance.ldf")

		# Restore the database from the backup
		Restore-SqlDatabase -ServerInstance Localhost -Database ContosoInsurance `
						    -BackupFile $dbdestination -RelocateFile @($mdf,$ldf) -ReplaceDatabase

		#Add local administrators group as sysadmin
		Invoke-Sqlcmd -ServerInstance Localhost -Database "master" -Query "CREATE LOGIN [BUILTIN\Administrators] FROM WINDOWS"
		Invoke-Sqlcmd -ServerInstance Localhost -Database "master" -Query "ALTER SERVER ROLE sysadmin ADD MEMBER [BUILTIN\Administrators]"

		# Put the database into full recovery and run a backup (required for SQL AG)
        Invoke-Sqlcmd -ServerInstance Localhost -Database "master" -Query "ALTER DATABASE ContosoInsurance SET RECOVERY FULL"
		Backup-SqlDatabase -ServerInstance Localhost -Database ContosoInsurance
	
		# Build Firewall Rules for SQL & AOG
		New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action allow 
		New-NetFirewallRule -DisplayName "SQL AG Endpoint" -Direction Inbound -Protocol TCP -LocalPort 5022 -Action allow 
		New-NetFirewallRule -DisplayName "SQL AG Load Balancer Probe Port" -Direction Inbound -Protocol TCP -LocalPort 59999 -Action allow
			}
        GetScript = {@{Result = "ConfigureSql"}
	  }
	}
  }
}
