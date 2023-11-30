cls
# Array of websites containing threat intel
$drop_urls = @('https://rules.emergingthreats.net/blockrules/emerging-botcc.rules','https://rules.emergingthreats.net/blockrules/compromised-ips.txt')

# Loop through the URLs for the rules list
foreach ($u in $drop_urls) {

    # Extract the filename
    $temp = $u.split("/")
    
    # The last element in the array plucked off is the filename
    $file_name = $temp[-1]

    if (Test-Path $file_name) {

        continue

    } else {

        # Donload the rules list
        Invoke-WebRequest -Uri $u -OutFile $file_name

    }
}

# Array containing the filename
$input_paths = @('.\compromised-ips.txt','.\emerging-botcc.rules')

# Extract the IP addresses
$regex_drop = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# Append the IP addresses to the temporary IP list
Select-String -Path $input_paths -Pattern $regex_drop | `
ForEach-Object { $_.Matches } | `
ForEach-Object { $_.Value } | Sort-Object | Get-Unique | `
Out-File -FilePath "ips-bad.tmp"

# Get choice from user
$choice = Read-Host -Prompt "IPTables or Windows firewall ruleset? (I/W) "
switch ($choice) 
{
    'I' {
        # Get the IP addresses discovered, loop through and replace the beginning of the line with the IPTables syntax
        # After the IP address, add the remaining IPTables syntax and save the results to a file
        # iptables -A INPUT -s IP -j DROP
        (Get-Content -Path ".\ips-bad.tmp") | % `
        { $_ -replace "^","iptables -A INPUT -s " -replace "$", " -j DROP"} | `
        Out-File -FilePath "iptables.bash"
        Write-Host "Ruleset was saved to 'iptables.bash'"
    }
    'W' {
        # Get the IP addresses discovered, loop through and replace the beginning of the line with the Windows syntax
        # After the IP address, add the remaining Windows syntax and save the results to a file
        # netsh advfirewall firewall add rule name=\"BLOCK IP ADDRESS - IP\" dir=in action=block remoteip=IP
        (Get-Content -Path ".\ips-bad.tmp") | % `
        { $_ -replace "^","netsh advfirewall firewall add rule name=\'BLOCK IP ADDRESS - " -replace "$", "\' dir=in action=block remoteip=$_"} | `
        Out-File -FilePath "windowsRuleset.bash"
        Write-Host "Ruleset was saved to 'windowsRuleset.bash'"
    }
}

