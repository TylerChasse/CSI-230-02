# Storyline: send an email.

# Body of the email
$msg = "Hello there."

# echoing to the screen
write-host -BackgroundColor Red -ForegroundColor white $msg

# Email from address
$email = "tyler.chasse@mymail.champlain.edu"

# To address
$toEmail = "deployer@csi-web"

# Sending the email
Send-MailMessage -From $email -to $toEmail -Subject "A Greeting" -Body $msg -SmtpServer 192.168.6.71