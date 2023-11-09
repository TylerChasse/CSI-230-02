# Storyline: Various incident response tactics
cls
# Get location to store results
$location = read-host -Prompt "Where would you like to store the results?"

# Get Running Processes and the path for each process.
Get-Process | Select-Object ProcessName, Path | `
Export-Csv -Path "$location\files\runningProcesses.csv" -NoTypeInformation

# Get All registered services and the path to the executable controlling the service (you'll need to use WMI).
Get-WmiObject win32_service | Select-Object Name, PathName | `
Export-Csv -Path "$location\files\registeredServices.csv" -NoTypeInformation

# Get All TCP network sockets
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess | `
Export-Csv -Path "$location\files\TCPNetworkSockets.csv" -NoTypeInformation

# Get All user account information (you'll need to use WMI)
Get-LocalUser | Export-Csv -Path "$location\files\userAccountInfo.csv" -NoTypeInformation

# Get All NetworkAdapterConfiguration information.
# Used https://lizardsystems.com/articles/viewing-network-settings-powershell/#:~:text=To%20display%20detailed%20IP%20configuration,Filter%20IPEnabled%3DTRUE%20%2DComputerName%20. to help
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Export-Csv -Path "$location\files\netAdaptConfig.csv" -NoTypeInformation

# Use Powershell cmdlets to save 4 other artifacts that would be useful in an incident but only use Powershell cmdlets.
# Used https://www.scriptrunner.com/en/blog/top-10-powershell-commands-for-troubleshooting/ for inspiration
# Chose this cmdlet because it's a very general and overarching way to see a lot of different stuff like available memory, windows version, and much more.
Get-CimInstance -ClassName win32_operatingsystem | Export-Csv -Path "$location\files\cimInstance.csv" -NoTypeInformation

# Chose this cmdlet because seeing the last 100 security events could be useful during an incident
Get-WinEvent -LogName Security -MaxEvents 100 | Export-Csv -Path "$location\files\winLogs.csv" -NoTypeInformation

# Chose this cmdlet because it would be useful to see most recent login information
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Export-Csv -Path "$location\files\recentLogins.csv" -NoTypeInformation

# Chose this cmdlet just because I thought it'd be useful to check your connection and ping status
Test-NetConnection | Select-Object ComputerName, RemoteAddress, InterfaceAlias, SourceAddress, PingSucceeded | Export-Csv -Path "$location\files\netConnection.csv" -NoTypeInformation

function createFileHash{
    # Make sure file has not been created already
    # Used https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path?view=powershell-7.3 to help
    if (!(Test-Path -Path $location\files\hashFile.txt)) {
        # If it hasn't, create it
        # Used https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.3 to help
        New-Item -Path $location\files -Name "hashFile.txt" -ItemType "file"
    }
    # Add each hash to the file
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\runningProcesses.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\registeredServices.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\TCPNetworkSockets.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\userAccountInfo.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\netAdaptConfig.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\cimInstance.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\winLogs.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\recentLogins.csv")
    Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\files\netConnection.csv")
}
createFileHash

# Zip files
# Used https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.3 to help
Compress-Archive -Path $location\files -DestinationPath $location\zip\files.zip

# Add zip file hash to hash file
Add-Content -Path $location\files\hashFile.txt -Value (Get-FileHash "$location\zip\files.zip")
