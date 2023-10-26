# Get the DHCP server IP. Used https://www.reddit.com/r/PowerShell/comments/2fwv8x/find_the_dhcp_server_ip_address_from_the_ipconfig/ to help
ipconfig /all | Select-String -Pattern "DHCP Server"
# Get the DNS server IP. Used https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.3 to help with regex
ipconfig /all | Select-String -Pattern "\d\.\d\.\d\.\d"

# Get running processes 
Get-Process | Select-Object ProcessName, Path, ID | `
Export-Csv -Path "C:\Users\22cha\CSI-230-02\Week9\myProcesses.csv" -NoTypeInformation

# Get running services
Get-Service | Where { $_.Status -eq "Running" } | Select-Object DisplayName, Status |`
Export-Csv -Path "C:\Users\22cha\CSI-230-02\Week9\myServices.csv" -NoTypeInformation

# Open and close calculator
Start-Process -FilePath "C:Windows\System32\calc.exe"
sleep 2
Stop-Process -Name CalculatorApp