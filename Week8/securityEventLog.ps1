# Storyline: Review the Security Event Log

# Directory to save files:

$myDir = "C:\Users\22cha\CSI-230-02\Week8"

# List all the available Windows Event Logs
Get-EventLog -list

# Create a prompt to allow user to select the log to view
$readLog = Read-Host -Prompt "Please select a log to review from the list above"

# Create a prompt to allow user to search for specific message
$msg = Read-Host -Prompt "Enter the message you would like to search for"

# Print the results for the log
Get-EventLog -LogName $readLog -Newest 40 | where {$_.Message -ilike "*$msg*"} | export-csv -NoTypeInformation `
-Path "$myDir\securityLogs.csv"