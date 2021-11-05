<# Requires global reader role minimum on Azure app, connects to exchange online and queries for mailflow status summary report,
portable between windows and linux, must generate self-signed certs, upload to Azure app, requires the following two modules; 
sudo sh -c "pwsh -Command 'Install-Module -Name ExchangeOnlineManagement'"
sudo sh -c "pwsh -Command 'Install-Module -Name PSWSMan'"
#>
Connect-ExchangeOnline -CertificateFilePath "<PATH>" -AppID "<APPID>" -Organization "<ORG>.onmicrosoft.com" -CertificatePassword (ConvertTo-SecureString -String '<PASSWORD>' -AsPlainText -Force)
$dte = (Get-Date).AddDays(-30)
Get-MailflowStatusReport -StartDate $dte -EndDate (Get-Date)
Disconnect-ExchangeOnline
