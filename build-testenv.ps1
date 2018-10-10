param(
    $subscriptionName = "",
    $resourceGroupName = "",
    $location = "",
    $appgwsubnetprefix = "10.0.0.0/24",
    $appgwsubnetName = "appgwsubnet",
    $apimsubnetprefix = "10.0.1.0/24",
    $apimsubnetName = "apimsubnet",
    $vnetName = "apim-vnet",
    $vnetPrefix = "10.0.0.0/16",
    $apimSKU = "Developer",
    $apimServiceName = "",
    $apimOrgName = "",
    $apimAdminEmail = "",
    $apimGatewayHostName = "",
    $apimDevPortalHostName = "",
    $certdir = "",
    $apimGatewayCertPassword = "",
    $apimDevPortalCertPassword = "",
    $appGatewayName = "apim-app-gw"
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
    $rg = Get-AzureRMResourceGroup -Name $resourceGroupName -ea 0
    if(!($rg))
    {
        New-AzureRmResourceGroup -Name $resourceGroupName -Location $location
    }
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create VNET

try {
    $vnet = Get-AzureRMVirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName -ea 0
    if(!($vnet))
    {
        $appgwsubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $appgwsubnetName -AddressPrefix $appgwsubnetprefix
        $apimsubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $apimsubnetName -AddressPrefix $apimsubnetprefix
        $vnet = new-azurermvirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName -Location $location -AddressPrefix $vnetPrefix -Subnet $appgwsubnet,$apimsubnet
    
    }

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
    $apimService = Get-AzureRmApiManagement -Name $apimServiceName -ResourceGroupName $resourceGroupName -ea 0

    if(!($apimService))
    {
        $apimVNET = New-AzureRmApiManagementVirtualNetwork -Location $location -SubnetResourceId $apimsubnetdata.Id
        $apimService = New-AzureRmApiManagement -ResourceGroupName $resourceGroupName -Location $location -Name $apimServiceName -Organization $apimOrgName -AdminEmail $apimAdminEmail -VirtualNetwork $apimVNET -VpnType Internal -Sku $apimSKU
    
    }
    else {
        $apimVNET = (Get-AzureRmApiManagement -ResourceGroupName $resourceGroupName -Name $apimServiceName).VirtualNetwork
    }
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create self-signed certificate for APIM Gateway Hostname
try {
    $pathprefix = $certdir + '\apimgwcert'
    $apimGatewayCertPfx = $pathprefix + '.pfx'
    $apimGatewayCertCer = $pathprefix + '.cer'
    
    if(!(Get-ChildItem $apimGatewayCertPfx -ea 0) -or !(Get-ChildItem $apimGatewayCertCer -ea 0))
    {
        $apimgatewaycert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $apimGatewayHostName
        $apimgwsecStringcertpw = $apimGatewayCertPassword | ConvertTo-SecureString -asplaintext -Force
        $path = 'Cert:\CurrentUser\My\' + $apimgatewaycert.Thumbprint
    
        Export-PfxCertificate -Cert $path -FilePath $apimGatewayCertPfx -Password $apimgwsecStringcertpw
        Export-Certificate -Cert $path -Type CERT -FilePath $apimGatewayCertCer
    }


}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Create self-signed certificate for APIM Dev Portal Hostname
try {
    $apimDevPortalCertPfx = $certdir + '\apimdevportal.pfx'
    if(!(get-childitem $apimdevportalcertpfx -ea 0))
    {
        $apimdevportalcert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $apimDevPortalHostName
        $apimDevPortalSecStringCertpw = $apimDevPortalCertPassword | ConvertTo-SecureString -AsPlainText -Force
        $devportalcertpath = 'Cert:\CurrentUser\My\' + $apimdevportalcert.Thumbprint
    
        Export-PfxCertificate -Cert $devportalcertpath -FilePath $apimDevPortalCertPfx -Password $apimDevPortalSecStringCertpw
        #Export-Certificate -Cert $devportalcertpath -FilePath $apimDevPortalCertCer
    }
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Upload the Certificates and Set APIM HostName Configuration
try {
    if(!($apimService.PortalCustomHostnameConfiguration.CertificateInformation))
    {
        $devPortalCertImportObject = Import-AzureRmApiManagementHostnameCertificate -ResourceGroupName $resourceGroupName -Name $apimServiceName -HostnameType "Proxy" -PfxPath $apimDevPortalCertPfx -PfxPassword $apimDevPortalCertPassword -PassThru
        $portalHostnameConfig = New-AzureRmApiManagementHostnameConfiguration -CertificateThumbprint $devPortalCertImportObject.Thumbprint -Hostname $apimDevPortalHostName
        Set-AzureRmApiManagementHostnames -Name $apimServiceName -ResourceGroupName -PortalHostnameConfiguration $portalHostnameConfig
    }
    if(!($apimService.ProxyCustomHostnameConfiguration.CertificateInformation))
    {
        $gwCertImportObject = Import-AzureRmApiManagementHostnameCertificate -ResourceGroupName $resourceGroupName -Name $apimServiceName -HostnameType "Proxy" -PfxPath $apimGatewayCertPfx -PfxPassword $apimGatewayCertPassword -PassThru
        $proxyHostnameConfig = New-AzureRmApiManagementHostnameConfiguration -CertificateThumbprint $gwCertImportObject.Thumbprint -Hostname $apimGatewayHostName
        Set-AzureRmApiManagementHostnames -Name $apimServiceName -ResourceGroupName $resourceGroupName -ProxyHostnameConfiguration $proxyHostnameConfig
    }
}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}




# Build Public IP and App Gateway Configuration Parameters

try {
    $appGwPublicIp = Get-AzureRMPublicIpAddress -ResourceGroupName $resourceGroupName -Name "appgwpublicip" -ea 0 
    if(!($appGwPublicIp))
    {
        $appGwPublicIp = New-AzureRmPublicIpAddress -ResourceGroupName $resourceGroupName -name "appgwpublicip" -location $location -AllocationMethod Dynamic

    }
    
    $gipconfig = New-AzureRmApplicationGatewayIPConfiguration -Name "gatewayIP01" -Subnet $appgwsubnetdata
    $fePort = New-AzureRmApplicationGatewayFrontendPort -Name "port443"  -Port 443
    $fipconfig01 = New-AzureRmApplicationGatewayFrontendIPConfig -Name "frontend1" -PublicIPAddress $appGwPublicIp
    $gwcert = New-AzureRmApplicationGatewaySslCertificate -Name "gatewaycert" -CertificateFile $apimGatewayCertPfx -Password $apimgwsecStringcertpw
    $devportalcert = New-AzureRmApplicationGatewaySslCertificate -Name "devportalcert" -CertificateFile $apimDevPortalCertPfx -Password $apimDevPortalSecStringCertpw
    $gwlistener = New-AzureRmApplicationGatewayHttpListener -Name "gatewaylistener" -Protocol "Https" -FrontendIPConfiguration $fipconfig01 -FrontendPort $fePort -SslCertificate $gwcert -HostName $apimGatewayHostName -RequireServerNameIndication true
    $devportalListener = New-AzureRmApplicationGatewayHttpListener -Name "devportallistener" -Protocol "Https" -FrontendIPConfiguration $fipconfig01 -FrontendPort $fePort -SslCertificate $devportalcert -HostName $apimDevPortalHostName -RequireServerNameIndication true
    $apimgwprobe = New-AzureRmApplicationGatewayProbeConfig -Name "apimproxyprobe" -Protocol "Https" -HostName $apimGatewayHostName -Path "/status-0123456789abcdef" -Interval 30 -Timeout 120 -UnhealthyThreshold 8
    $apimdevPortalProbe = New-AzureRmApplicationGatewayProbeConfig -Name "apimportalprobe" -Protocol "Https" -HostName $apimDevPortalHostName -Path "/signin" -Interval 60 -Timeout 300 -UnhealthyThreshold 8
    $apimgwauthcert = New-AzureRmApplicationGatewayAuthenticationCertificate -Name "whitelistcert1" -CertificateFile $apimGatewayCertCer
    $apimPoolSetting = New-AzureRmApplicationGatewayBackendHttpSettings -Name "apimPoolSetting" -Port 443 -Protocol "Https" -CookieBasedAffinity "Disabled" -Probe $apimgwprobe -AuthenticationCertificates $apimgwauthcert -RequestTimeout 180
    $apimPoolPortalSetting = New-AzureRmApplicationGatewayBackendHttpSettings -Name "apimPoolPortalSetting" -Port 443 -Protocol "Https" -CookieBasedAffinity "Disabled" -Probe $apimdevPortalProbe -AuthenticationCertificates $apimgwauthcert -RequestTimeout 180
    $apimProxyBackendPool = New-AzureRmApplicationGatewayBackendAddressPool -Name "apimbackend" -BackendIPAddresses $apimService.PrivateIPAddresses[0]
    $rule01 = New-AzureRmApplicationGatewayRequestRoutingRule -Name "rule1" -RuleType Basic -HttpListener $gwlistener -BackendAddressPool $apimProxyBackendPool -BackendHttpSettings $apimPoolSetting
    $rule02 = New-AzureRmApplicationGatewayRequestRoutingRule -Name "rule2" -RuleType Basic -HttpListener $devportalListener -BackendAddressPool $apimProxyBackendPool -BackendHttpSettings $apimPoolPortalSetting
    $sku = New-AzureRmApplicationGatewaySku -Name "WAF_Medium" -Tier "WAF" -Capacity 2
    $config = New-AzureRmApplicationGatewayWebApplicationFirewallConfiguration -Enabled $true -FirewallMode "Prevention"

}
catch {
    $exception = $_.Exception
    Write-Error $exception
    throw $exception
}

#Build App Gateway

$appgwparams = @{
    Name = $appGatewayName
    ResourceGroupName = $resourceGroupName
    Location = $location
    BackendAddressPools = $apimProxyBackendPool
    BackendHttpSettingsCollection = @($apimPoolSetting, $apimPoolPortalSetting)
    FrontendIpConfiguration = $fipconfig01
    GatewayIPConfigurations = $gipconfig
    FrontEndPorts = $fePort
    HttpListeners = @($gwlistener, $devportalListener)
    RequestRoutingRules = @($rule01, $rule02)
    Sku = $sku
    WebApplicationFirewallConfig = $config
    SslCertificates = @($gwcert, $devportalcert)
    AuthenticationCertificates = $apimgwauthcert
    Probes = @($apimgwprobe, $apimdevPortalProbe)
}


$appgwObject = New-AzureRmApplicationGateway @appgwparams
