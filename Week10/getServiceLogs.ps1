#Storyline: Get all registered services and sort into all, stopped, and running

function getServices() {
    cls
    # Create an array for the service logs
    $logsArr = @("All`n`n","`nStopped`n`n","`nRunning`n`n")
    # Get all service logs
    $logsArr[0] += Get-Service
    # Get stopped logs
    $logsArr[1] += Get-Service | Where-Object {$_.Status -eq "Stopped"} 
    # Get running logs
    $logsArr[2] += Get-Service | Where-Object {$_.Status -eq "Running"}

    # Get input
    getInput -logsArr $logsArr
}

function getInput() {
    Param([array]$logsArr)
    cls
    # Get service log type to look for
    $logInput = read-Host -Prompt "Would you like to view the running, the stopped, or all of the service logs? (r/s/a)"
    # If all
    if ($logInput -match "^[a/A]$") {
        # Used https://shellgeek.com/powershell-replace-space-with-newline/ to help format each string
        $logsArr[0].replace(" ","`r`n")
    }
    # If running
    elseif ($logInput -match "^[s/S]$") {
        $logsArr[1].replace(" ","`r`n")
    }
    # If stopped
    elseif ($logInput -match "^[r/R]$") {
        $logsArr[2].replace(" ","`r`n")  
    }
    # If invalid input
    else {
        Write-Host "Invalid input, please try again"
        sleep 2
        # Try again
        getInput -logsArr $logsArr
    }
    # Ask to quit or continue
    $quitInput = Read-Host -Prompt "If you would like to quit enter 'q'. Enter anything else to continue"
    if ($quitInput -match "^[q/Q]$") {
        break
    }
    # Run again
    else {
        getInput -logsArr $logsArr
    }
}

getServices