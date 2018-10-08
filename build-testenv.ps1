param(
    $subscriptionName = "",
    $resourceGroupName = "",
    $location = "",
    $appgwsubnetprefix = "10.0.0.0/24",
    $appgwsubnetName = "appgwsubnet",
    $apimsubnetprefix = "10.0.1.0/24",
    $apimsubnetName = "apimsubnet",
    $vnetName = "",
    $vnetPrefix = "10.0.0.0/16",
    $apimSKU = "Developer",
    $apimServiceName = "",
    $apimOrgName = "",
    $apimAdminEmail = "",
    $apimGatewayHostName = "",
    $apimDevPortalHostName = "",
    $certdir = "",
    $apimGatewayCertPassword = "",
    $apimDevPortalCertPassword = ""
)


#Login to Subscription
Login-AzureRmAccount
#Set Subcription Scope
try {
    Get-AzureRmSubscription -SubscriptionName $subscriptionName | Select-AzureRmSubscription 
    Write-Debug "Subcription set to $((Get-AzureRMContext).Name)"
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create ResourceGroup

try {
    New-AzureRmResourceGroup -Name $resourceGroupName -Location $location
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create VNET

try {
    $appgwsubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $appgwsubnetName -AddressPrefix $appgwsubnetprefix
    $apimsubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $apimsubnetName -AddressPrefix $apimsubnetprefix
    $vnet = new-azurermvirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName -Location $location -AddressPrefix $vnetPrefix -Subnet $appgwsubnet,$apimsubnet
    $appgwsubnetdata = $vnet.Subnets[0]
    $apimsubnetdata = $vnet.Subnets[1]
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create APIM Service Endpoint and APIM Service
try {
    $apimVNET = New-AzureRmApiManagementVirtualNetwork -Location $location -SubnetResourceId $apimsubnetdata.Id
    $apimService = New-AzureRmApiManagement -ResourceGroupName $resourceGroupName -Location $location -Name $apimServiceName -Organization $apimOrgName -AdminEmail $apimAdminEmail -VirtualNetwork $apimVNET -VpnType Internal -Sku $apimSKU
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create self-signed certificate for APIM Gateway
try {
    $apimgatewaycert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $apimGatewayHostName
    $apimgwsecStringcertpw = $apimGatewayCertPassword | ConvertTo-SecureString -asplaintext -Force
    $path = 'Cert:\CurrentUser\My\' + $apimgatewaycert.Thumbprint
    $pathprefix = $certdir + '\apimgwcert'
    $apimGatewayCertPfx = $pathprefix + '.pfx'
    $apimGatewayCertCer = $pathprefix + '.cer'
    Export-PfxCertificate -Cert $path -FilePath $apimGatewayCertPfx -Password $apimgwsecStringcertpw
    Export-Certificate -Cert $path -Type CERT -FilePath $apimGatewayCertCer
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create self-signed certificate for APIM Dev Portal
try {
    $apimdevportalcert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $apimDevPortalHostName
    $apimDevPortalSecStringCertpw = $apimDevPortalCertPassword | ConvertTo-SecureString -AsPlainText -Force
    $path = 'Cert:\CurrentUser\My\' + $apimdevportalcert.Thumbprint
    $apimDevPortalCertPfx = $certdir + '\apimdevportal.pfx'
    Export-PfxCertificate -Cert $path -FilePath $apimDevPortalCertPfx -Password $apimDevPortalSecStringCertpw
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Upload the Certificates
try {
    $apimgwsecStringcertpw = $apimGatewayCertPassword | ConvertTo-SecureString -AsPlainText -Force
    $apimDevPortalSecStringCertpw = $apimDevPortalCertPassword | ConvertTo-SecureString -AsPlainText -Force
    $gwCertUploadResult = Import-AzureRmApiManagementHostnameCertificate -ResourceGroupName $resourceGroupName -Name $apimServiceName -HostnameType "Proxy" -PfxPath $apimGatewayCertPfx -PfxPassword $apimgwsecStringcertpw -PassThru
    $devPortalCertUploadResult = Import-AzureRmApiManagementHostnameCertificate -ResourceGroupName $resourceGroupName -Name $apimServiceName -HostnameType "Proxy" -PfxPath $apimDevPortalCertPfx -PfxPassword $apimDevPortalSecStringCertpw -PassThru
    Write-Debug -Message "Status of Gateway Cert upload is $($gwCertUploadResult)"
    Write-Debug -Message "Status of Dev Portal Cert upload is $($devportalcertuploadresult)"    
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}


#Build the Gateway Host Configuration
try {
    $proxyHostnameConfig = New-AzureRmApiManagementHostnameConfiguration -CertificateThumbprint $gwCertUploadResult.Thumbprint -Hostname $apimGatewayHostName
    $portalHostnameConfig = New-AzureRmApiManagementHostnameConfiguration -CertificateThumbprint $devPortalCertUploadResult.Thumbprint -Hostname $apimDevPortalHostName
    $result = Set-AzureRmApiManagementHostnames -Name $apimServiceName -ResourceGroupName $resourceGroupName –PortalHostnameConfiguration $portalHostnameConfig -ProxyHostnameConfiguration $proxyHostnameConfig
    Write-Debug "Setting APIM Host config... Result: $($Result)"
    }
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

# Build Public IP and FE listeners for both AppGw to APIM

try {
    $appGwPublicIp = New-AzureRmPublicIpAddress -ResourceGroupName $resourceGroupName -name "appgwpublicip" -location $location -AllocationMethod Dynamic
    $gipconfig = New-AzureRmApplicationGatewayIPConfiguration -Name "gatewayIP01" -Subnet $appgwsubnetdata
    $fePort = New-AzureRmApplicationGatewayFrontendPort -Name "port443"  -Port 443
    $fipconfig01 = New-AzureRmApplicationGatewayFrontendIPConfig -Name "frontend1" -PublicIPAddress $appGwPublicIp
    $gwcert = New-AzureRmApplicationGatewaySslCertificate -Name "gatewaycert" -CertificateFile $apimGatewayCertPfx -Password $apimgwsecStringcertpw
    $devportalcert = New-AzureRmApplicationGatewaySslCertificate -Name "devportalcert" -CertificateFile $apimDevPortalCertPfx -Password $apimDevPortalSecStringCertpw
    $gwlistener = New-AzureRmApplicationGatewayHttpListener -Name "gatewaylistener" -Protocol "Https" -FrontendIPConfiguration $fipconfig01 -FrontendPort $fePort -SslCertificate $gwcert -HostName $apimGatewayHostName -RequireServerNameIndication true
    $devportalListener = New-AzureRmApplicationGatewayHttpListener -Name "devportallistener" -Protocol "Https" -FrontendIPConfiguration $fipconfig01 -FrontendPort $fePort -SslCertificate $devportalcert -HostName $apimDevPortalHostName -RequireServerNameIndication true
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}