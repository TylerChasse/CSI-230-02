cls
# Login to a remote SSH server
New-SSHSession -ComputerName '192.168.4.22' -Credential (Get-Credential sys320)

while ($True) {

    # Add a prompt to run commands
    $the_cmd = read-host -Prompt "Please enter a command"

    # Run command on remote SSH server
    (Invoke-SSHCommand -index 0 $the_cmd).Output 

}

Set-SCPFile -Computername '192.168.4.22' -Credential (Get-Credential sys320) `
-RemotePath 'C:\Users\22cha\CSI-230-02\Week12' -LocalFile 'ps.jpg'

Invoke-SSHCommand -index 0 'ls -l' # show above worked