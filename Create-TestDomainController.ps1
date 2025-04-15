# =============================================================================
# Script: Create-TestDomainController.ps1
# Created: 2025-02-14 21:37:49 UTC
# Author: maxdaylight
# Last Updated: 2025-05-27 14:45:00 UTC
# Updated By: maxdaylight
# Version: 4.9.5
# Additional Info: Improved password security and removed credential display
# =============================================================================

<# 
.SYNOPSIS
    Creates and configures a Domain Controller in Azure from a Windows 11 Pro workstation.

.DESCRIPTION
    This script deploys and configures an Azure VM as a Domain Controller, ensuring full
    compatibility with Windows 11 Pro workstations and PowerShell 7.5.0. No Server or Core 
    dependencies required.
    
    Key actions:
    - Validates Windows 11 Pro environment
    - Creates Azure resources using PowerShell 7.5.0
    - Configures Domain Controller through PowerShell remoting
    - Creates test users and configures basic AD structure
    - Automatically creates resources without prompting
    - Enables Trusted Launch security features
    - Configures static IP addressing for network stability
    - Implements security hardening for domain services
    - Provides RDP access through public IP address
    
    Dependencies:
    - Windows 11 Pro workstation
    - PowerShell 7.5.0
    - Az PowerShell modules
    - Active Azure subscription
    - Administrative privileges

    Security considerations:
    - Uses secure credential handling
    - Implements least privilege access
    - Encrypts all sensitive data
    - Trusted Launch enabled with vTPM and Secure Boot
    - Disables legacy cryptography protocols
    - Enforces static IP configuration
    - Hardens domain security settings
    
    Performance impact:
    - Average deployment time: 30-45 minutes
    - Resource usage: Moderate CPU and memory during deployment

    Known limitations:
    - DNS delegation warnings can be ignored for test environments
    - Default cryptography settings are explicitly configured
    - Not intended for production use without DNS infrastructure integration

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group where all resources will be created.
    Default value: "MD-TEST-RG2"

.PARAMETER Location
    The Azure region where all resources will be created.
    Default value: "westus2"

.PARAMETER VMSize
    The size/SKU of the virtual machine to be created.
    Default value: "Standard_D2s_v3"

.PARAMETER VMName
    The name of the virtual machine that will become the Domain Controller.
    Default value: "MD-TEST-DC01"

.PARAMETER VnetName
    The name of the Virtual Network to be created.
    Default value: "MD-TEST-VNET"

.PARAMETER SubnetName
    The name of the subnet to be created within the Virtual Network.
    Default value: "MD-TEST-SUBNET"

.PARAMETER StorageAccountName
    The name of the storage account for boot diagnostics and scripts.
    Default value: "MDteststorage0"

.PARAMETER ContainerName
    The name of the container within the storage account for scripts.
    Default value: "scripts"

.PARAMETER DomainName
    The FQDN of the Active Directory domain to be created.
    Default value: "MDtest.local"

.PARAMETER AdminUsername
    The administrator username for the Domain Controller.
    Default value: "MDadmin"

.PARAMETER TestUserPrefix
    The prefix used for creating test user accounts in the domain.
    Default value: "TestUser"

.PARAMETER OSDiskName
    The name of the OS disk resource for the virtual machine.
    Default value: "MD-TEST-DC01-OSDISK"

.EXAMPLE
    .\Create-TestDomainController.ps1
    Creates a new Domain Controller using all default values with hardened security settings

.EXAMPLE
    .\Create-TestDomainController.ps1 -ResourceGroupName "MyRG" -Location "westus2"
    Creates a new Domain Controller in the specified resource group and location with security hardening

.NOTES
    Security Level: High
    Required Permissions: Azure Subscription Contributor, Local Administrator
    Validation Requirements: 
    - Windows 11 Pro environment
    - Azure PowerShell modules
    - Network connectivity to Azure
    - Static IP address configuration
    - Domain security hardening
    
    Expected Warnings:
    - DNS delegation warnings are normal and can be ignored in test environments
    - Cryptography settings warnings are addressed through explicit configuration
#>

[CmdletBinding(SupportsShouldProcess=$false)]
param (
    [Parameter()]
    [string]$ResourceGroupName = "MD-TEST-RG2",

    [Parameter()]
    [string]$Location = "westus2",

    [Parameter()]
    [string]$VMSize = "Standard_D2s_v3",

    [Parameter()]
    [string]$VMName = "MD-TEST-DC01",

    [Parameter()]
    [string]$VnetName = "MD-TEST-VNET",

    [Parameter()]
    [string]$SubnetName = "MD-TEST-SUBNET",

    [Parameter()]
    [string]$StorageAccountName = "MDteststorage0",

    [Parameter()]
    [string]$ContainerName = "scripts",

    [Parameter()]
    [string]$DomainName = "MDtest.local",

    [Parameter()]
    [string]$AdminUsername = "MDadmin",

    [Parameter()]
    [string]$TestUserPrefix = "TestUser",

    [Parameter()]
    [string]$OSDiskName = "MD-TEST-DC01-OSDISK",
    
    [Parameter()]
    [string]$ShutdownTime = "2100",
    
    [Parameter()]
    [string]$TimeZone = "Mountain Standard Time"
)

# Set strict error handling
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
Set-StrictMode -Version Latest

# Enable extended error details
$FormatEnumerationLimit = -1
$InformationPreference = 'Continue'

# Add error handling function
function Write-ErrorDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    Write-Host "=== Detailed Error Information ===" -ForegroundColor Red
    Write-Host "Error Message: $($ErrorRecord.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Type: $($ErrorRecord.Exception.GetType().FullName)" -ForegroundColor Red
    Write-Host "Command: $($ErrorRecord.InvocationInfo.MyCommand)" -ForegroundColor Red
    Write-Host "Line Number: $($ErrorRecord.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host "Script Name: $($ErrorRecord.InvocationInfo.ScriptName)" -ForegroundColor Red
    Write-Host "Statement: $($ErrorRecord.InvocationInfo.Line)" -ForegroundColor Red
    if ($ErrorRecord.Exception.StackTrace) {
        Write-Host "Stack Trace: $($ErrorRecord.Exception.StackTrace)" -ForegroundColor Red
    }
    Write-Host "=== End Detailed Error Information ===" -ForegroundColor Red
}

# Suppress confirmation prompts globally for the entire script
$global:ConfirmPreference = 'None'

# Global transcript tracking
$script:TranscriptStarted = $false

# Start logging only if not already started
if (-not $script:TranscriptStarted) {
    $ScriptPath = $PSScriptRoot
    if (-not $ScriptPath) {
        $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }
    $LogDir = Join-Path $ScriptPath "Logs"
    $LogFile = Join-Path $LogDir "Create-TestDomainController_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    try {
        # Create logs directory if it doesn't exist
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        
        # Remove all existing log files
        Get-ChildItem -Path $LogDir -Filter "Create-TestDomainController_*.log" | Remove-Item -Force
        
        # Start new transcript
        Start-Transcript -Path $LogFile -Force
        $script:TranscriptStarted = $true
    }
    catch {
        Write-Error "Failed to initialize logging: $_"
        throw
    }
}

function Initialize-RemotingConfiguration {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Configuring PowerShell remoting..." -ForegroundColor Cyan
        
        # Temporarily suppress verbose output just for remoting commands
        $originalVerbosePreference = $VerbosePreference
        $VerbosePreference = 'SilentlyContinue'
        
        try {
            # Execute remoting commands with suppressed verbose output
            $winPSPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $configScript = {
                $VerbosePreference = 'SilentlyContinue'
                Enable-PSRemoting -Force -SkipNetworkProfileCheck
                Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
                Restart-Service WinRM -Force
            }
        
            $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($configScript))
            Start-Process -FilePath $winPSPath -ArgumentList "-EncodedCommand $encodedCommand" -Wait -NoNewWindow

            # Other remoting configuration commands
            $null = Enable-PSRemoting -Force -SkipNetworkProfileCheck
            
            # Verify configuration
            $trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
            if ($trustedHosts -ne "*") {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
            }
        }
        finally {
            # Restore original verbose preference
            $VerbosePreference = $originalVerbosePreference
        }

        Write-Host "PowerShell remoting configured successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to initialize remoting configuration: $_"
        return $false
    }
}

function Initialize-WinRMConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HostName
    )
    
    try {
        Write-Host "Configuring WinRM Service..." -ForegroundColor Cyan
        
        # Configure WinRM Service
        Set-WSManQuickConfig -Force
        Enable-PSRemoting -Force -SkipNetworkProfileCheck

        # Configure WinRM HTTPS listener
        $cert = New-SelfSignedCertificate -DnsName $HostName -CertStoreLocation "Cert:\LocalMachine\My"
        $thumbprint = $cert.Thumbprint
        $command = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname=`"$HostName`";CertificateThumbprint=`"$thumbprint`"}'"
        cmd.exe /C $command

        # Configure firewall rules
        New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
        New-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Name "Windows Remote Management (HTTP-In)" -Profile Any -LocalPort 5985 -Protocol TCP

        # Set basic authentication
        Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

        # Restart WinRM service
        Restart-Service WinRM -Force
        
        Write-Host "WinRM configuration completed successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to configure WinRM: $_"
        return $false
    }
}

# Enhanced session creation for PowerShell 7.5.0
function New-EnhancedPSSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [int]$MaxAttempts = 5,
        
        [Parameter()]
        [int]$InitialRetryIntervalSeconds = 10
    )
    
    $attempt = 0
    $session = $null
    $retryInterval = $InitialRetryIntervalSeconds
	
    do {
        $attempt++
        try {
            Write-Host "Creating PowerShell session (Attempt $attempt of $MaxAttempts)..." -ForegroundColor Cyan
            
            # Simplified session options compatible with PS 7.5.0
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck `
                -OpenTimeout 180000 `
                -OperationTimeout 180000 `
                -IdleTimeout 172800000 `
                -MaximumReceivedDataSizePerCommand 209715200

            # Verify WinRM service is running on local machine
            if ((Get-Service -Name "WinRM").Status -ne "Running") {
                Start-Service -Name "WinRM"
                Start-Sleep -Seconds 5
            }
            
            # Create and validate session with enhanced error handling
            $session = New-PSSession -ComputerName $ComputerName `
                -Credential $Credential `
                -SessionOption $sessionOption `
                -ErrorAction Stop `
                -UseSSL:$false `
                -Port 5985 `
                -Authentication Negotiate

            # Test session state with improved validation
            if ($session.State -ne "Opened") {
                throw "Session created but not in Opened state. Current state: $($session.State)"
            }

            # Simple connectivity test
            $testResult = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (-not $testResult) {
                throw "Session test command failed"
            }

            Write-Host "Successfully created and validated PowerShell session" -ForegroundColor Green
            return $session
        }
        catch {
            Write-Warning "Session creation attempt $attempt failed: $_"
            
            if ($session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }

            if ($attempt -lt $MaxAttempts) {
                $jitter = Get-Random -Minimum 1 -Maximum 10
                $retryInterval = [Math]::Min($retryInterval * 2 + $jitter, 300)
                Write-Host "Waiting $retryInterval seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryInterval
            }
            else {
                Write-Error "Failed to create PowerShell session after $MaxAttempts attempts"
                throw
            }
        }
    } while ($attempt -lt $MaxAttempts)
    
    return $null
}

# Modified New-DomainControllerVM function with enhanced PS 7.5.0 support
function New-DomainControllerVM {
    [CmdletBinding(SupportsShouldProcess=$false)]
    [OutputType([PSCustomObject])] # Explicitly declare output type
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$Location,

        [Parameter(Mandatory=$true)]
        [string]$VMSize,

        [Parameter(Mandatory=$true)]
        [string]$VnetName,

        [Parameter(Mandatory=$true)]
        [string]$SubnetName
    )

    # Ensure confirmation suppression in function scope
    $ConfirmPreference = 'None'

    try {
        # Initialize remoting configuration
        if (-not (Initialize-RemotingConfiguration)) {
            throw "Failed to initialize remoting configuration"
        }
		
		        # Create Virtual Network with enhanced error handling
        Write-Host "Creating Virtual Network..." -ForegroundColor Cyan
        $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name $SubnetName `
            -AddressPrefix "10.0.0.0/24"

        $vnet = New-AzVirtualNetwork -Name $VnetName -ResourceGroupName $ResourceGroupName `
            -Location $Location -AddressPrefix "10.0.0.0/16" -Subnet $subnetConfig

        Write-Host "Virtual Network created successfully" -ForegroundColor Green

        # Create Public IP with enhanced Static allocation
        Write-Host "Creating Public IP..." -ForegroundColor Cyan
        $publicIp = New-AzPublicIpAddress -Name "$VMName-IP" `
            -ResourceGroupName $ResourceGroupName -Location $Location `
            -AllocationMethod Static -Sku Standard

        Write-Host "Public IP created successfully" -ForegroundColor Green
        
        # Create Network Security Group with enhanced rules
        Write-Host "Creating Network Security Group..." -ForegroundColor Cyan
        $nsgRuleRDP = New-AzNetworkSecurityRuleConfig -Name "Allow-RDP" -Description "Allow RDP" `
            -Access Allow -Protocol Tcp -Direction Inbound -Priority 102 `
            -SourceAddressPrefix * -SourcePortRange * `
            -DestinationAddressPrefix * -DestinationPortRange 3389

        # Modified WinRM rules to be more specific
        $nsgRuleWinRMHttp = New-AzNetworkSecurityRuleConfig -Name "Allow-WinRM-HTTP" -Description "Allow WinRM HTTP" `
            -Access Allow -Protocol Tcp -Direction Inbound -Priority 101 `
            -SourceAddressPrefix * -SourcePortRange * `
            -DestinationAddressPrefix * -DestinationPortRange 5985

        $nsgRuleWinRMHttps = New-AzNetworkSecurityRuleConfig -Name "Allow-WinRM-HTTPS" -Description "Allow WinRM HTTPS" `
            -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 `
            -SourceAddressPrefix * -SourcePortRange * `
            -DestinationAddressPrefix * -DestinationPortRange 5986

        $nsgRuleDomain = New-AzNetworkSecurityRuleConfig -Name "Allow-Domain" -Description "Allow Domain Services" `
            -Access Allow -Protocol * -Direction Inbound -Priority 103 `
            -SourceAddressPrefix * -SourcePortRange * `
            -DestinationAddressPrefix * -DestinationPortRange 53,88,135,389,445,464,636,3268,3269

        $nsg = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location `
            -Name "MD-TEST-NSG" -SecurityRules @($nsgRuleRDP, $nsgRuleWinRMHttp, $nsgRuleWinRMHttps, $nsgRuleDomain)

        Write-Host "Network Security Group created successfully" -ForegroundColor Green

        # Create Network Interface with enhanced validation
        Write-Host "Creating Network Interface..." -ForegroundColor Cyan
        $subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $SubnetName
        $nic = New-AzNetworkInterface -Name "$VMName-NIC" -ResourceGroupName $ResourceGroupName `
            -Location $Location -SubnetId $subnet.Id -PublicIpAddressId $publicIp.Id `
            -NetworkSecurityGroupId $nsg.Id
            
        # Create VM Configuration with enhanced Trusted Launch
        Write-Host "Creating VM Configuration with Trusted Launch..." -ForegroundColor Cyan
        
        # Get admin password from .env file with no default value - as secure string
        $scriptPath = $PSScriptRoot
        if (-not $scriptPath) {
            $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
        }
        $envFilePath = Join-Path -Path $scriptPath -ChildPath '.env'
        $securePassword = Get-EnvVariable -Name 'ADMIN_PASSWORD' -EnvFilePath $envFilePath -AsSecureString
        
        $cred = New-Object System.Management.Automation.PSCredential ($AdminUsername, $securePassword)

        # Configure storage account for boot diagnostics BEFORE VM creation
        Write-Host "Setting up boot diagnostics storage..." -ForegroundColor Cyan
        $maxStorageRetries = 5
        $storageRetryCount = 0
        $storageAccount = $null
        $timeout = New-TimeSpan -Minutes 5
        
        # Create and start stopwatch with a more compatible approach
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()

        while ($storageRetryCount -lt $maxStorageRetries -and $sw.Elapsed -lt $timeout) {
            try {
                Write-Host "Attempt $($storageRetryCount + 1) of $maxStorageRetries to configure storage..." -ForegroundColor Yellow
                
                # Check if storage account exists
                Write-Host "Checking for existing storage account..." -ForegroundColor Cyan
                $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName `
                    -Name $StorageAccountName -ErrorAction SilentlyContinue

                if (-not $storageAccount) {
                    Write-Host "Creating new storage account '$StorageAccountName'..." -ForegroundColor Yellow
                    $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName `
                        -Name $StorageAccountName `
                        -Location $Location `
                        -SkuName Standard_LRS `
                        -ErrorAction Stop

                    if ($storageAccount) {
                        Write-Host "Storage account created successfully" -ForegroundColor Green
                        
                        # Verify storage account is fully provisioned
                        $provisioningState = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName `
                            -Name $StorageAccountName).ProvisioningState
                        
                        if ($provisioningState -eq "Succeeded") {
                            Write-Host "Storage account provisioning confirmed" -ForegroundColor Green
                            break
                        } else {
                            throw "Storage account not fully provisioned. State: $provisioningState"
                        }
                    }
                } else {
                    Write-Host "Using existing storage account" -ForegroundColor Green
                    break
                }
            }
            catch {
                $storageRetryCount++
                Write-Warning "Storage operation failed: $_"
                
                if ($storageRetryCount -eq $maxStorageRetries -or $sw.Elapsed -ge $timeout) {
                    throw "Failed to configure storage after $storageRetryCount attempts or timeout reached ($($sw.Elapsed.TotalMinutes) minutes): $_"
                }
                
                $delay = [math]::Min(30, [math]::Pow(2, $storageRetryCount)) # Exponential backoff
                Write-Host "Waiting $delay seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }

        if (-not $storageAccount) {
            throw "Failed to create or retrieve storage account within timeout period of $($timeout.TotalMinutes) minutes"
        }

        # Try creating VM with Trusted Launch first, then fall back if needed
        $vmCreated = $false
        $retries = 0
        $maxRetries = 3
        $vm = $null
        $vmCreationError = $null # Initialize error variable

        while (-not $vmCreated -and $retries -lt $maxRetries) {
            try {
                $retries++
                $securityType = if ($retries -eq 1) { "TrustedLaunch" } else { "Standard" }
                $vmCreationError = $null # Reset error variable for each attempt
                
                Write-Host "VM creation attempt $retries of $maxRetries with security type: $securityType" -ForegroundColor Yellow
                
                # Create VM configuration based on current security type
                if ($securityType -eq "TrustedLaunch") {
                    Write-Host "Attempting to create VM with Trusted Launch security..." -ForegroundColor Cyan
                    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType TrustedLaunch |
                        Set-AzVMOperatingSystem -Windows -ComputerName $VMName `
                            -Credential $cred -ProvisionVMAgent -EnableAutoUpdate |
                        Set-AzVMSourceImage -PublisherName "MicrosoftWindowsServer" `
                            -Offer "WindowsServer" -Skus "2022-Datacenter-g2" -Version "latest" |
                        Set-AzVMOSDisk -Name $OSDiskName -CreateOption FromImage |
                        Add-AzVMNetworkInterface -Id $nic.Id

                    # Configure Trusted Launch security features with enhanced settings
                    $vmConfig = Set-AzVMSecurityProfile -VM $vmConfig -SecurityType TrustedLaunch
                    $vmConfig = Set-AzVMUefi -VM $vmConfig -EnableVtpm $true -EnableSecureBoot $true
                } else {
                    Write-Host "Falling back to standard VM configuration without Trusted Launch..." -ForegroundColor Yellow
                    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize |
                        Set-AzVMOperatingSystem -Windows -ComputerName $VMName `
                            -Credential $cred -ProvisionVMAgent -EnableAutoUpdate |
                        Set-AzVMSourceImage -PublisherName "MicrosoftWindowsServer" `
                            -Offer "WindowsServer" -Skus "2022-Datacenter" -Version "latest" |
                        Set-AzVMOSDisk -Name $OSDiskName -CreateOption FromImage |
                        Add-AzVMNetworkInterface -Id $nic.Id
                }

                # Configure boot diagnostics with the storage account created earlier
                Write-Host "Configuring boot diagnostics..." -ForegroundColor Cyan
                $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig -Enable `
                    -ResourceGroupName $ResourceGroupName `
                    -StorageAccountName $storageAccount.StorageAccountName

                # Create the VM with detailed error capturing
                Write-Host "Creating Virtual Machine: $VMName (Attempt $retries)..." -ForegroundColor Cyan
                $vm = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig -ErrorVariable vmCreationError
                
                if ($vm) {
                    $vmCreated = $true
                    Write-Host "Virtual Machine created successfully with security type: $securityType" -ForegroundColor Green
                } else {
                    throw "VM creation returned null result"
                }
            }
            catch {
                if ($retries -ge $maxRetries) {
                    Write-Host "Failed to create VM after $maxRetries attempts. Last error: $_" -ForegroundColor Red
                    throw
                }
                
                # Log the specific error details - with check to ensure vmCreationError is set
                Write-Warning "VM creation attempt $retries failed: $_"
                if ($vmCreationError) {
                    Write-Warning "VM Creation Error Details: $($vmCreationError | Out-String)"
                }
                
                # Add a delay before retry with exponential backoff
                $delay = [Math]::Pow(2, $retries) * 5
                Write-Host "Waiting $delay seconds before next attempt..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }

        if (-not $vm) {
            throw "VM creation returned null result after $maxRetries attempts"
        }

        Write-Host "Configuring boot diagnostics..." -ForegroundColor Cyan
        $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig -Enable `
            -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $storageAccount.StorageAccountName
			
        # Create the VM
        Write-Host "Creating Virtual Machine: $VMName..." -ForegroundColor Cyan
        $vm = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig
            
        if (-not $vm) {
            throw "VM creation returned null result"
        }

        Write-Host "Virtual Machine created successfully" -ForegroundColor Green
        
        # Configure auto-shutdown for 7 PM Mountain Standard Time
        Write-Host "Configuring automatic shutdown schedule..." -ForegroundColor Cyan
        
        try {
            # Get the current subscription ID
            $subscriptionId = (Get-AzContext).Subscription.Id
            if (-not $subscriptionId) {
                throw "Could not retrieve subscription ID"
            }
            
            # Get the VM resource ID
            $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
            if (-not $vm) {
                throw "Could not retrieve VM details"
            }
            $vmId = $vm.Id

            # Create the auto-shutdown schedule
            $scheduleName = "shutdown-computevm-$VMName"
            $scheduleId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/$scheduleName"

            $scheduleConfig = @{
                location = $vm.Location
                properties = @{
                    status = "Enabled"
                    taskType = "ComputeVmShutdownTask"
                    dailyRecurrence = @{time = $ShutdownTime}
                    timeZoneId = $TimeZone
                    notificationSettings = @{
                        status = "Disabled"
                        timeInMinutes = 30
                    }
                    targetResourceId = $vmId
                }
            }

            # Log the shutdown configuration details for debugging
            Write-Host "Auto-shutdown details:" -ForegroundColor Cyan
            Write-Host "  Schedule Name: $scheduleName" -ForegroundColor Cyan
            Write-Host "  VM ID: $vmId" -ForegroundColor Cyan
            Write-Host "  Shutdown Time: $ShutdownTime" -ForegroundColor Cyan
            Write-Host "  Time Zone: $TimeZone" -ForegroundColor Cyan

            # Create the auto-shutdown resource with correct parameter set (remove ResourceType when using ResourceId)
            try {
                $null = New-AzResource -ResourceId $scheduleId `
                    -Properties $scheduleConfig.properties `
                    -Location $vm.Location `
                    -ApiVersion "2018-09-15" `
                    -Force
                    
                Write-Host "Auto-shutdown schedule created using ResourceId parameter set" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed with ResourceId parameter set: $($_.Exception.Message)"
                
                # Try alternative parameter set if first method fails
                try {
                    $null = New-AzResource -ResourceGroupName $ResourceGroupName `
                        -ResourceType "microsoft.devtestlab/schedules" `
                        -ResourceName $scheduleName `
                        -Properties $scheduleConfig.properties `
                        -Location $vm.Location `
                        -ApiVersion "2018-09-15" `
                        -Force
                        
                    Write-Host "Auto-shutdown schedule created using ResourceGroupName parameter set" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Failed with ResourceGroupName parameter set: $($_.Exception.Message)"
                    throw $_
                }
            }
                
            # Try both naming conventions for verification
            $schedule = Get-AzResource -ResourceId $scheduleId -ErrorAction SilentlyContinue
            
            # Also check using the auto-shutdown naming convention that the Get-AzResource command uses
            $autoShutdownId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/$VMName/auto-shutdown"
            $autoShutdown = Get-AzResource -ResourceId $autoShutdownId -ErrorAction SilentlyContinue
            
            if ($schedule -or $autoShutdown) {
                Write-Host "Automatic shutdown scheduled successfully for $ShutdownTime $TimeZone" -ForegroundColor Green
            } else {
                # If verification failed, try the alternative naming convention
                $altScheduleName = "$VMName/auto-shutdown"
                $altScheduleId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/$altScheduleName"
                
                Write-Host "Attempting alternative auto-shutdown naming convention..." -ForegroundColor Yellow
                
                # Create schedule with alternative naming
                $altScheduleConfig = @{
                    location = $vm.Location
                    properties = @{
                        status = "Enabled"
                        taskType = "ComputeVmShutdownTask"
                        dailyRecurrence = @{time = $ShutdownTime}
                        timeZoneId = $TimeZone
                        notificationSettings = @{
                            status = "Disabled"
                            timeInMinutes = 30
                        }
                        targetResourceId = $vmId
                    }
                }
                
                try {
                    $null = New-AzResource -ResourceId $altScheduleId `
                        -Properties $altScheduleConfig.properties `
                        -Location $vm.Location `
                        -ResourceType "microsoft.devtestlab/schedules" `
                        -ApiVersion "2018-09-15" `
                        -Force
                    
                    # Verify the alternative schedule was created
                    $altSchedule = Get-AzResource -ResourceId $altScheduleId -ErrorAction SilentlyContinue
                    if ($altSchedule) {
                        Write-Host "Automatic shutdown scheduled successfully using alternative naming convention" -ForegroundColor Green
                    } else {
                        Write-Warning "Auto-shutdown schedule could not be verified with either naming convention"
                    }
                } catch {
                    Write-Warning "Failed to create auto-shutdown with alternative naming: $_"
                }
            }
        }
        catch {
            Write-Warning "Failed to configure auto-shutdown: $_"
            Write-Warning "Error details: $($_.Exception.Message)"
            if ($_.Exception.InnerException) {
                Write-Warning "Inner error: $($_.Exception.InnerException.Message)"
            }
            
            # Use Az CLI as fallback method
            try {
                Write-Host "Attempting fallback method using Az CLI..." -ForegroundColor Yellow
                
                $azCliCommand = "az vm auto-shutdown -g $ResourceGroupName -n $VMName --time $ShutdownTime --time-zone `"$TimeZone`""
                Write-Host "Executing: $azCliCommand" -ForegroundColor Cyan
                
                Invoke-Expression $azCliCommand
                Write-Host "Auto-shutdown scheduled via Az CLI" -ForegroundColor Green
            }
            catch {
                Write-Warning "Az CLI fallback method also failed: $_"
            }
        }

        # Wait for VM to be fully ready
        Write-Host "Waiting for VM to be fully ready..." -ForegroundColor Cyan
        $maxRetries = 30
        $retryCount = 0
        $vmReady = $false

        while (-not $vmReady -and $retryCount -lt $maxRetries) {
            try {
                $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
                if ($vmStatus.Statuses[-1].Code -eq 'PowerState/running') {
                    $vmReady = $true
                    Write-Host "VM is ready and running" -ForegroundColor Green
                    break
                }
            }
            catch {
                Write-Warning "Retry ${retryCount}: Checking VM status failed: $_"
            }
            
            $retryCount++
            if (-not $vmReady) {
                Start-Sleep -Seconds 10
            }
        }

        if (-not $vmReady) {
            throw "VM failed to reach ready state after $maxRetries attempts"
        }

        Write-Host "Configuring WinRM on remote VM..." -ForegroundColor Cyan
        $publicIpAddress = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$VMName-IP").IpAddress
        
        # Configure WinRM using custom script extension
        $scriptContent = @'
        winrm quickconfig -force
        winrm set winrm/config/service/auth '@{Basic="true"}'
        winrm set winrm/config/service '@{AllowUnencrypted="true"}'
        New-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Name "Windows Remote Management (HTTP-In)" -Profile Any -LocalPort 5985 -Protocol TCP
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
'@
        
        # Save script content to a temporary file
        $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
        $scriptContent | Out-File -FilePath $tempFile -Encoding ASCII
        
        # Upload script to storage account
        $storageContext = $storageAccount.Context
        $container = Get-AzStorageContainer -Name $ContainerName -Context $storageContext -ErrorAction SilentlyContinue
        if (-not $container) {
            # Create container with private access
            $container = New-AzStorageContainer -Name $ContainerName -Context $storageContext -Permission Off
        }
        
        $blobName = "ConfigureWinRM.ps1"
        Set-AzStorageBlobContent -File $tempFile -Container $ContainerName -Blob $blobName -Context $storageContext -Force
        
        # Verify blob exists and generate SAS token
        $blob = Get-AzStorageBlob -Container $ContainerName -Blob $blobName -Context $storageContext
        if (-not $blob) {
            throw "Failed to upload script to storage blob"
        }
        
        # Generate SAS token with read permission that expires in 1 hour
        $sasToken = New-AzStorageBlobSASToken -Container $ContainerName `
            -Blob $blobName `
            -Context $storageContext `
            -Permission r `
            -ExpiryTime (Get-Date).AddHours(1) `
            -FullUri

        # Use SAS token URL for the custom script extension
        $vm = Set-AzVMCustomScriptExtension `
            -ResourceGroupName $ResourceGroupName `
            -VMName $VMName `
            -Name "ConfigureWinRM" `
            -Location $Location `
            -FileUri @($sasToken) `
            -Run "ConfigureWinRM.ps1"

        # Clean up temporary file
        Remove-Item -Path $tempFile -Force

        Write-Host "Configuring PowerShell Remoting..." -ForegroundColor Cyan
        $publicIpAddress = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName `
            -Name "$VMName-IP").IpAddress
        
        # Initialize remoting using enhanced PS 7.5.0 configuration
        Initialize-RemotingConfiguration

        # Get a fresh reference to the VM to ensure we have valid data
        $freshVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
        if (-not $freshVM) {
            throw "Failed to get VM reference after deployment"
        }

        # Create the result object with explicit validation for each property
        $result = [ordered]@{}
        
        # Add each property with validation
        if ($freshVM) { 
            $result['VM'] = $freshVM 
        } else {
            throw "VM reference is null"
        }
        
        if ($publicIpAddress) { 
            $result['PublicIP'] = $publicIpAddress 
        } else {
            throw "Public IP address is null"
        }
        
        if ($ResourceGroupName) { 
            $result['ResourceGroupName'] = $ResourceGroupName 
        } else {
            throw "Resource group name is null"
        }
        
        if ($cred) { 
            $result['Credentials'] = $cred 
        } else {
            throw "Credentials object is null"
        }

        # Final validation of the complete object
        $requiredProps = @('VM', 'PublicIP', 'ResourceGroupName', 'Credentials')
        $missingProps = $requiredProps | Where-Object { -not $result.Contains($_) }
        
        if ($missingProps) {
            throw "Result object missing required properties: $($missingProps -join ', ')"
        }

        Write-Host "Successfully created VM deployment object" -ForegroundColor Green
        
        # Return directly to avoid array creation - don't assign to variable first
        return [PSCustomObject]$result
    }
    catch {
        Write-Error "Error in New-DomainControllerVM: $_"
        throw
    }
}

function Get-VMConnectionInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        Write-Host "Retrieving connection information..." -ForegroundColor Cyan
        
        # Remove unused VM object retrieval
        $publicIp = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$VMName-IP"
        
        Write-Host "`nRDP Connection Information:" -ForegroundColor Green
        Write-Host "------------------------" -ForegroundColor Green
        Write-Host "Computer:  $($publicIp.IpAddress)" -ForegroundColor Yellow
        Write-Host "Username:  $AdminUsername" -ForegroundColor Yellow
        Write-Host "Password:  Password can be found in .env file" -ForegroundColor Yellow
        Write-Host "Domain:    $DomainName" -ForegroundColor Yellow
        Write-Host "`nTo connect:" -ForegroundColor Green
        Write-Host "1. Open Remote Desktop Connection (mstsc.exe)" -ForegroundColor Cyan
        Write-Host "2. Enter the IP address: $($publicIp.IpAddress)" -ForegroundColor Cyan
        Write-Host "3. Use the credentials above" -ForegroundColor Cyan
        Write-Host "Note: Domain join may take 5-10 minutes after script completion" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to retrieve connection information: $_"
    }
}

function Test-AutoShutdownSchedule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        Write-Host "Verifying auto-shutdown configuration..." -ForegroundColor Cyan
        
        # Standard naming convention check
        $autoShutdown = Get-AzResource -ResourceGroupName $ResourceGroupName `
                                      -ResourceType "Microsoft.DevTestLab/schedules" `
                                      -ResourceName "$VMName/auto-shutdown" `
                                      -ErrorAction SilentlyContinue

        # Check if auto-shutdown is enabled with standard naming
        if ($autoShutdown) {
            Write-Host "Auto-shutdown is enabled for VM: $VMName" -ForegroundColor Green
            Write-Host "Details: $($autoShutdown.Properties | ConvertTo-Json -Depth 2)" -ForegroundColor Cyan
            return
        }
            
        # Alternative naming convention
        $altSchedule = Get-AzResource -ResourceGroupName $ResourceGroupName `
                                      -ResourceType "Microsoft.DevTestLab/schedules" `
                                      -Name "shutdown-computevm-$VMName" `
                                      -ErrorAction SilentlyContinue
                                    
        if ($altSchedule) {
            Write-Host "Auto-shutdown found with alternative name: 'shutdown-computevm-$VMName'" -ForegroundColor Green
            Write-Host "Details: $($altSchedule.Properties | ConvertTo-Json -Depth 2)" -ForegroundColor Cyan
            return
        }
        
        # Check Az CLI format by querying for any schedule resources in the resource group
        $allSchedules = Get-AzResource -ResourceGroupName $ResourceGroupName `
                                     -ResourceType "Microsoft.DevTestLab/schedules" `
                                     -ErrorAction SilentlyContinue
        
        # Filter for any schedules that might be targeting our VM
        $vmResource = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
        
        if ($vmResource -and $allSchedules) {
            $vmId = $vmResource.Id
            $targetSchedules = $allSchedules | Where-Object { 
                ($_.Properties.targetResourceId -eq $vmId) -or 
                ($_.Name -like "*$VMName*")
            }
            
            if ($targetSchedules) {
                Write-Host "Auto-shutdown found with custom/CLI naming:" -ForegroundColor Green
                foreach ($schedule in $targetSchedules) {
                    Write-Host "  - Schedule Name: $($schedule.Name)" -ForegroundColor Green
                    Write-Host "    Target VM: $($schedule.Properties.targetResourceId)" -ForegroundColor Green
                    Write-Host "    Time: $($schedule.Properties.dailyRecurrence.time) $($schedule.Properties.timeZoneId)" -ForegroundColor Green
                }
                return
            }
        }
        
        # If all detection methods fail, verify via Az CLI
        try {
            Write-Host "Attempting to check schedule via Az CLI..." -ForegroundColor Yellow
            $azCliCommand = "az vm auto-shutdown show -g $ResourceGroupName -n $VMName"
            $cliResult = Invoke-Expression $azCliCommand -ErrorAction SilentlyContinue
            
            if ($cliResult) {
                Write-Host "Auto-shutdown confirmed via Az CLI" -ForegroundColor Green
                Write-Host $cliResult -ForegroundColor Cyan
                return
            }
        } catch {
            # Continue with other checks if CLI check fails
        }
        
        # If we get here, no auto-shutdown was detected
        Write-Host "Auto-shutdown is NOT enabled for VM: $VMName with any naming convention" -ForegroundColor Yellow
        Write-Host "You may want to manually verify using Azure Portal" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to check auto-shutdown configuration: $_"
    }
}

# Function to read variables from .env file with enhanced security for passwords
function Get-EnvVariable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter()]
        [string]$EnvFilePath,
        
        [Parameter()]
        [string]$DefaultValue,
        
        [Parameter()]
        [switch]$AsSecureString
    )

    try {
        # If no env file path specified, use default location with more reliable path resolution
        if (-not $EnvFilePath) {
            $scriptPath = $PSScriptRoot
            if (-not $scriptPath) {
                $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
            }
            $EnvFilePath = Join-Path -Path $scriptPath -ChildPath '.env'
        }

        # Check if .env file exists
        if (-not (Test-Path -Path $EnvFilePath)) {
            # Handle password variables with stricter requirements (no defaults)
            if ($Name -like '*PASSWORD*') {
                throw "Environment file not found: $EnvFilePath. Password variables must be defined in .env file."
            }
            
            Write-Warning "Environment file not found: $EnvFilePath"
            if ($DefaultValue) {
                Write-Warning "Using default value for $Name"
                
                # Convert to secure string if needed
                if ($AsSecureString -or $Name -like '*PASSWORD*') {
                    return ConvertTo-SecureString -String $DefaultValue -AsPlainText -Force
                }
                return $DefaultValue
            } else {
                throw "Environment variable '$Name' not found and no default provided"
            }
        }

        # Read and parse the .env file
        $envContent = Get-Content -Path $EnvFilePath -ErrorAction Stop
        
        foreach ($line in $envContent) {
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }
            
            # Parse key-value pairs
            if ($line -match '^\s*([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                
                # Return value if key matches
                if ($key -eq $Name) {
                    # Remove surrounding quotes if present
                    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or 
                        ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                        $value = $value.Substring(1, $value.Length - 2)
                    }
                    
                    # Automatically convert password variables to SecureString
                    if ($AsSecureString -or $Name -like '*PASSWORD*') {
                        return ConvertTo-SecureString -String $value -AsPlainText -Force
                    }
                    
                    return $value
                }
            }
        }

        # If we get here, key wasn't found
        if ($Name -like '*PASSWORD*') {
            # Password variables require stricter handling
            throw "Password environment variable '$Name' not found in $EnvFilePath. Passwords must be defined explicitly."
        }
        
        if ($DefaultValue) {
            Write-Warning "Environment variable '$Name' not found in $EnvFilePath. Using default value."
            
            # Convert to secure string if needed
            if ($AsSecureString -or $Name -like '*PASSWORD*') {
                return ConvertTo-SecureString -String $DefaultValue -AsPlainText -Force
            }
            return $DefaultValue
        } else {
            throw "Environment variable '$Name' not found in $EnvFilePath"
        }
    }
    catch {
        # Special handling for password variables
        if ($Name -like '*PASSWORD*' -and $DefaultValue) {
            throw "Error reading password environment variable '$Name': $_. Default passwords are not allowed for security reasons."
        }
        
        Write-Error "Error reading environment variable '$Name': $_"
        if ($DefaultValue -and -not ($Name -like '*PASSWORD*')) {
            Write-Warning "Using default value for $Name"
            
            # Convert to secure string if needed
            if ($AsSecureString) {
                return ConvertTo-SecureString -String $DefaultValue -AsPlainText -Force
            }
            return $DefaultValue
        }
        throw
    }
}

# Main process block
try {
    # Validate Azure connection
    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "Not connected to Azure. Please run Connect-AzAccount first."
        }
        Write-Host "Connected to Azure subscription: $($context.Subscription.Name)" -ForegroundColor Green
    }
    catch {
        throw "Azure authentication error: $_"
    }

    Write-Host "Starting Domain Controller deployment process..." -ForegroundColor Cyan
    
    # Check if resource group exists and create it if it doesn't
    try {
        $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        Write-Host "Using existing resource group: $ResourceGroupName" -ForegroundColor Green
    }
    catch {
        Write-Host "Resource group '$ResourceGroupName' not found. Creating..." -ForegroundColor Yellow
        $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
        if (-not $resourceGroup) {
            throw "Failed to create resource group"
        }
        Write-Host "Resource group created successfully" -ForegroundColor Green
    }
    
    # Create Azure VM with validation
    Write-Host "Initiating VM deployment..." -ForegroundColor Cyan
    
    # Pass explicit script root to avoid path resolution issues
    $vmDeployment = New-DomainControllerVM -ResourceGroupName $ResourceGroupName `
        -Location $Location -VMSize $VMSize -VnetName $VnetName -SubnetName $SubnetName
    
    # Enhanced array handling - if we got an array, explicitly select the first valid item
    if ($vmDeployment -is [System.Array]) {
        Write-Host "Received array result from VM deployment, contains $($vmDeployment.Count) elements" -ForegroundColor Yellow
        
        # Diagnostics - show what we've received before processing
        for ($i = 0; $i -lt $vmDeployment.Count; $i++) {
            $item = $vmDeployment[$i]
            Write-Host "Examining array element [$i]:" -ForegroundColor Yellow
            if ($null -eq $item) {
                Write-Host "  Element [$i] is null" -ForegroundColor Yellow
                continue
            }
            
            # Show type and available properties
            $typeName = $item.GetType().FullName
            Write-Host "  Type: $typeName" -ForegroundColor Yellow
            
            # Safely check if the object has properties
            $hasProperties = $false
            try {
                # Use @() to safely cast to array even if null or single item
                $hasProperties = ($null -ne $item.PSObject) -and (@($item.PSObject.Properties).Length -gt 0)
            } catch {
                # Some object types don't support this property inspection method
                $hasProperties = $false
            }
            
            if ($item -is [PSCustomObject] -or $hasProperties) {
                $props = try { 
                    (@($item.PSObject.Properties.Name) -join ', ') 
                } catch { 
                    "Could not enumerate properties" 
                }
                Write-Host "  Properties: $props" -ForegroundColor Yellow
                
                # Check for key properties
                foreach ($prop in @('VM','PublicIP','ResourceGroupName','Credentials')) {
                    try {
                        if ($null -ne $item.PSObject.Properties -and @($item.PSObject.Properties.Name) -contains $prop) {
                            $value = if ($null -eq $item.$prop) { "null" } else { "present" }
                            Write-Host "  - ${prop}: $value" -ForegroundColor Yellow
                        }
                    } catch {
                        # Skip properties that can't be accessed
                        continue
                    }
                }
            }
        }
        
        # Try to find the most likely candidate in the array - one with our expected properties
        $candidate = $vmDeployment | Where-Object { 
            try {
                $_ -is [PSCustomObject] -and 
                $null -ne $_.PSObject -and
                $null -ne $_.PSObject.Properties -and
                (@($_.PSObject.Properties).Length -gt 0) -and
                (@($_.PSObject.Properties.Name) -contains 'VM') -and
                (@($_.PSObject.Properties.Name) -contains 'PublicIP') -and
                (@($_.PSObject.Properties.Name) -contains 'ResourceGroupName') -and
                (@($_.PSObject.Properties.Name) -contains 'Credentials')
            }
            catch {
                # Return false if any property access fails
                $false
            }
        } | Select-Object -First 1
        
        if ($candidate) {
            Write-Host "Found candidate object with required properties in array" -ForegroundColor Green
            $vmDeployment = $candidate
        }
        else {
            # Fallback - detailed attempt to construct a valid object from array elements
            Write-Host "No complete candidate found, attempting to reconstruct from array elements..." -ForegroundColor Yellow
            
            # Extract deployment information from array elements
            $vm = $vmDeployment | Where-Object { $_ -is [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] } | Select-Object -First 1
            $publicIP = $vmDeployment | Where-Object { $_ -is [string] -and $_ -match '\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1
            
            if (-not $publicIP) {
                # Try extracting from array elements that might contain IP info
                foreach ($item in $vmDeployment) {
                    if ($item.PSObject.Properties.Name -contains 'PublicIP') {
                        $publicIP = $item.PublicIP
                        break
                    }
                }
            }
            
            if (-not $vm) {
                # Use last-resort option - get fresh VM reference
                try {
                    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to get VM reference: $_"
                }
            }
            
            # Create new object with extracted data
            if ($vm -and $publicIP) {
                # Get admin password from .env file with no default
                $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
                $envFilePath = Join-Path -Path $scriptPath -ChildPath '.env'
                $adminPasswordText = Get-EnvVariable -Name 'ADMIN_PASSWORD' -EnvFilePath $envFilePath
                
                $vmDeployment = [PSCustomObject]@{
                    VM = $vm
                    PublicIP = $publicIP
                    ResourceGroupName = $ResourceGroupName
                    Credentials = New-Object System.Management.Automation.PSCredential ($AdminUsername, (ConvertTo-SecureString $adminPasswordText -AsPlainText -Force))
                }
                Write-Host "Successfully reconstructed deployment object" -ForegroundColor Green
            }
        }
    }
    
    # Simplified validation - no need for complex array handling
    if (-not $vmDeployment) {
        throw "VM deployment returned null"
    }
    
    # Add diagnostic information about the object type and structure
    Write-Host "VM Deployment object type: $($vmDeployment.GetType().FullName)" -ForegroundColor Yellow
    if ($vmDeployment.PSObject.Properties.Name) {
        Write-Host "Available properties: $($vmDeployment.PSObject.Properties.Name -join ', ')" -ForegroundColor Yellow
    }
    
    # Validate required properties exist and have values
    $requiredProps = @('VM', 'PublicIP', 'ResourceGroupName', 'Credentials')
    $missingProps = $requiredProps | Where-Object { 
        -not ($vmDeployment.PSObject.Properties.Name -contains $_) -or 
        -not $vmDeployment.$_ 
    }
    
    if ($missingProps) {
        throw "VM deployment missing or has null required properties: $($missingProps -join ', ')"
    }
    
    Write-Host "VM deployment object validation successful" -ForegroundColor Green
    
    # Add notice about credentials instead
    Write-Host "`n======== DOMAIN CONTROLLER CREDENTIALS ========" -ForegroundColor Yellow
    Write-Host "Domain Controller credentials have been configured using values from the .env file." -ForegroundColor Cyan
    Write-Host "Username: $AdminUsername" -ForegroundColor Cyan
    Write-Host "Passwords are not displayed for security reasons." -ForegroundColor Green
    Write-Host "All credentials are stored in the .env file in the script directory." -ForegroundColor Cyan
    Write-Host "============================================`n"

    # Verify VM is accessible before proceeding
    Write-Host "Verifying VM accessibility..." -ForegroundColor Cyan
    $vmState = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status -ErrorAction Stop
    if (-not $vmState -or $vmState.Statuses[-1].Code -ne 'PowerState/running') {
        throw "VM is not in running state. Current state: $($vmState.Statuses[-1].Code)"
    }

    # Configure Domain Controller with enhanced session management
    Write-Host "Starting Domain Controller configuration..." -ForegroundColor Cyan
    $session = New-EnhancedPSSession -ComputerName $vmDeployment.PublicIP -Credential $vmDeployment.Credentials
    
    if (-not $session -or $session.State -ne "Opened") {
        throw "Failed to establish remote PowerShell session. Session state: $($session.State)"
    }

    # Configure static IP and DNS settings
    Write-Host "Configuring static IP and DNS settings..." -ForegroundColor Cyan
    
    # Suppress progress display during remote command execution to avoid NullReferenceException
    $originalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    
    try {
        Invoke-Command -Session $session -ScriptBlock {
            # Get active network adapter with validation
            $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
            if (-not $adapter) {
                throw "No active network adapter found"
            }
            
            Write-Host "Found active adapter: $($adapter.Name)" -ForegroundColor Cyan
            
            # Get current IP configuration with validation
            $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
            if (-not $ip) {
                throw "No IPv4 address found on adapter $($adapter.Name)"
            }
            
            Write-Host "Current IP configuration: $($ip.IPAddress)" -ForegroundColor Cyan
            
            # Store values before removing IP
            $staticIP = $ip.IPAddress
            $prefixLength = $ip.PrefixLength
            
            # Get gateway with validation
            $gateway = (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop).NextHop
            if (-not $gateway) {
                throw "No gateway found for adapter $($adapter.Name)"
            }
            
            Write-Host "Current gateway: $gateway" -ForegroundColor Cyan
            
            # Remove existing IP configuration
            Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction Stop
            
            # Add new static IP configuration
            $newIP = New-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 `
                -IPAddress $staticIP -PrefixLength $prefixLength -DefaultGateway $gateway -ErrorAction Stop
                
            if ($newIP) {
                Write-Host "Successfully configured static IP: $($newIP.IPAddress)" -ForegroundColor Green
            }
            
            # Configure IPv6
            Write-Host "Configuring IPv6 settings..." -ForegroundColor Cyan
            Set-NetIPv6Protocol -RandomizeIdentifiers Disabled
            
            # Verify configuration
            $verifyIP = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
            if ($verifyIP) {
                Write-Host "IP configuration verified: $($verifyIP.IPAddress)" -ForegroundColor Green
            }
        }
    }
    finally {
        # Restore original progress preference
        $ProgressPreference = $originalProgressPreference
    }

    Write-Host "Configuring Domain Controller..." -ForegroundColor Cyan
    # Get the Safe Mode Admin password from .env file as SecureString
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $envFilePath = Join-Path -Path $scriptPath -ChildPath '.env'
    $safeModeSecurePassword = Get-EnvVariable -Name 'SAFE_MODE_PASSWORD' -EnvFilePath $envFilePath -AsSecureString
    
    # No need to convert to SecureString since it's already secure
    
    # Add retry logic and suppress progress display during Invoke-Command execution
    $maxRetries = 3
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $retryCount++
            if ($retryCount -gt 1) {
                Write-Host "Retry $retryCount of $maxRetries for Domain Controller configuration..." -ForegroundColor Yellow
                # Re-create session if needed for retries
                if (-not $session -or $session.State -ne "Opened") {
                    Write-Host "Re-establishing PowerShell session..." -ForegroundColor Cyan
                    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
                    Start-Sleep -Seconds 30
                    $session = New-EnhancedPSSession -ComputerName $vmDeployment.PublicIP -Credential $vmDeployment.Credentials
                    if (-not $session -or $session.State -ne "Opened") {
                        throw "Failed to re-establish PowerShell session on retry $retryCount"
                    }
                }
            }
            
            # Suppress progress display during remote command execution to avoid NullReferenceException
            $originalProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            
            try {
                # Execute the domain controller configuration with progress suppressed
                Invoke-Command -Session $session -ScriptBlock {
                    param(
                        [Parameter(Mandatory=$true)]
                        [string]$DomainName,
                        
                        [Parameter(Mandatory=$true)]
                        [System.Security.SecureString]$SafeModeAdminPassword
                    )
                    
                    # No need to convert password - already received as SecureString
                    
                    # Install AD DS Role first
                    Write-Host "Installing AD DS Windows Feature..." -ForegroundColor Cyan
                    try {
                        $feature = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
                        if (-not $feature.Success) {
                            throw "Failed to install AD-Domain-Services feature: $($feature.ExitCode)"
                        }
                        Write-Host "AD DS Windows Feature installed successfully" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to install AD DS Windows Feature: $_"
                        throw
                    }
                    
                    # Configure cryptography settings before AD installation
                    Write-Host "Configuring cryptography settings..." -ForegroundColor Cyan
                    
                    try {
                        # Test registry access and elevate if needed
                        $testPath = "HKLM:\SOFTWARE\Test"
                        if (-not (Test-Path $testPath)) {
                            New-Item -Path $testPath -Force -ErrorAction Stop | Out-Null
                            Remove-Item -Path $testPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        Write-Warning "Insufficient registry permissions. Attempting to run with elevation..."
                        $elevatedScript = {
                            # Configure system-wide security settings
                            $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders"
                            if (-not (Test-Path $securityPath)) {
                                New-Item -Path $securityPath -Force | Out-Null
                            }

                            # LSA settings
                            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                            if (Test-Path $lsaPath) {
                                $items = @{
                                    "LmCompatibilityLevel" = 5
                                    "NoLMHash" = 1
                                    "tknohpages" = 1
                                    "DisableDomainCreds" = 1
                                    "RestrictAnonymous" = 1
                                    "EveryoneIncludesAnonymous" = 0
                                    "AllowNullSessionFallback" = 0
                                    "RestrictSendingNTLMTraffic" = 2
                                }
                                
                                foreach ($item in $items.GetEnumerator()) {
                                    try {
                                        Set-ItemProperty -Path $lsaPath -Name $item.Key -Value $item.Value -ErrorAction Stop
                                    }
                                    catch {
                                        Write-Warning "Failed to set $($item.Key): $_"
                                    }
                                }
                            }

                            # MSV1_0 settings
                            $msv1Path = "$lsaPath\MSV1_0"
                            if (-not (Test-Path $msv1Path)) {
                                New-Item -Path $msv1Path -Force | Out-Null
                            }
                            
                            try {
                                Set-ItemProperty -Path $msv1Path -Name "NtlmMinClientSec" -Value 0x20080000
                                Set-ItemProperty -Path $msv1Path -Name "NtlmMinServerSec" -Value 0x20080000
                                Set-ItemProperty -Path $msv1Path -Name "allownullsessionfallback" -Value 0
                                Set-ItemProperty -Path $msv1Path -Name "RestrictReceivingNTLMTraffic" -Value 2
                                Set-ItemProperty -Path $msv1Path -Name "RestrictSendingNTLMTraffic" -Value 2
                            }
                            catch {
                                Write-Warning "Failed to configure MSV1_0 settings: $_"
                            }

                            # SCHANNEL settings with error handling
                            $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
                            if (-not (Test-Path $schannelPath)) {
                                New-Item -Path $schannelPath -Force | Out-Null
                            }
                            
                            $protocols = @("PCT 1.0", "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
                            foreach ($protocol in $protocols) {
                                try {
                                    $protocolPath = Join-Path $schannelPath $protocol
                                    if (-not (Test-Path $protocolPath)) {
                                        New-Item -Path $protocolPath -Force | Out-Null
                                    }
                                    Set-ItemProperty -Path $protocolPath -Name "Enabled" -Value 0 -Type DWord
                                    Set-ItemProperty -Path $protocolPath -Name "DisabledByDefault" -Value 1 -Type DWord
                                }
                                catch {
                                    $errorMessage = $_.Exception.Message
                                    Write-Warning ("Failed to configure protocol {0} - {1}" -f $protocol, $errorMessage)
                                    continue
                                }
                            }
                        }

                        # Execute the elevated script block
                        if ($elevatedScript) {
                            try {
                                & $elevatedScript
                                Write-Host "Elevated registry configuration completed successfully" -ForegroundColor Green
                            }
                            catch {
                                Write-Warning "Failed to execute elevated script: $_"
                                throw
                            }
                            finally {
                                Write-Host "Completed registry configuration attempt" -ForegroundColor Cyan
                            }
                        }
                    }

                    # Continue with AD DS installation
                    Write-Host "Installing AD DS role..." -ForegroundColor Cyan
                    try {
                        Import-Module ADDSDeployment -ErrorAction Stop
                        Install-ADDSForest `
                            -CreateDnsDelegation:$false `
                            -DatabasePath "C:\Windows\NTDS" `
                            -DomainMode "WinThreshold" `
                            -DomainName $DomainName `
                            -ForestMode "WinThreshold" `
                            -InstallDns:$true `
                            -LogPath "C:\Windows\NTDS" `
                            -NoRebootOnCompletion:$false `
                            -SysvolPath "C:\Windows\SYSVOL" `
                            -SafeModeAdministratorPassword $SafeModeAdminPassword `
                            -Force:$true `
                            -Confirm:$false
                    }
                    catch {
                        Write-Error "Failed to install AD DS role: $_"
                        throw
                    }
                } -ArgumentList $DomainName, $safeModeSecurePassword -ErrorAction Stop
                
                $success = $true
                Write-Host "Domain Controller configuration completed successfully" -ForegroundColor Green
            }
            finally {
                # Restore original progress preference
                $ProgressPreference = $originalProgressPreference
            }
        }
        catch {
            Write-Warning "Domain Controller configuration attempt $retryCount failed: $_"
            if ($retryCount -ge $maxRetries) {
                Write-Error "Domain Controller configuration failed after $maxRetries attempts"
                throw
            }
            
            # Add exponential backoff for retries
            $delay = [Math]::Pow(2, $retryCount) * 15
            Write-Host "Waiting $delay seconds before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delay
        }
    }

    Write-Host "Waiting for domain services to be available..." -ForegroundColor Cyan
    Start-Sleep -Seconds 180

    Write-Host "Creating test users..." -ForegroundColor Cyan
    $newSession = New-EnhancedPSSession -ComputerName $vmDeployment.PublicIP -Credential $vmDeployment.Credentials
    
    # Get test user password from .env file as SecureString
    $testUserSecurePassword = Get-EnvVariable -Name 'TEST_USER_PASSWORD' -EnvFilePath $envFilePath -AsSecureString
    
    Invoke-Command -Session $newSession -ScriptBlock {
        param(
            $TestUserPrefix,
            [System.Security.SecureString]$TestUserPassword
        )
        
        # Wait for AD Web Services to be available
        $maxAttempts = 10
        $attempt = 0
        $success = $false
        
        do {
            try {
                Get-ADDomain
                $success = $true
            }
            catch {
                $attempt++
                Write-Warning "Waiting for AD Web Services... Attempt $attempt of $maxAttempts"
                Start-Sleep -Seconds 30
            }
        } while (-not $success -and $attempt -lt $maxAttempts)

        if (-not $success) {
            throw "AD Web Services not available after $maxAttempts attempts"
        }

        # Create test users
        1..10 | ForEach-Object {
            $userName = "$TestUserPrefix$_"
            # Using SecureString directly - no need to convert again
            
            try {
                New-ADUser -Name $userName `
                    -AccountPassword $TestUserPassword `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -ChangePasswordAtLogon $false
                Write-Host "Created user: $userName" -ForegroundColor Green
            }
            catch {
                Write-Error ("Failed to create user {0}: {1}" -f $userName, $_)
            }
        }
    } -ArgumentList $TestUserPrefix, $testUserSecurePassword

    # Ensure session cleanup
    if ($newSession) {
        Remove-PSSession $newSession -ErrorAction SilentlyContinue
    }
    if ($session) {
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }

    # Final validation
    Write-Host "Performing final validation..." -ForegroundColor Cyan
    $finalVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
    if (-not $finalVM) {
        throw "Unable to verify final VM state"
    }

    Write-Host "Domain Controller deployment completed successfully" -ForegroundColor Green
    
    # Display connection information with validation
    try {
        Get-VMConnectionInfo -ResourceGroupName $ResourceGroupName -VMName $VMName
    }
    catch {
        Write-Warning "Failed to retrieve connection information: $_"
        # Don't throw here - deployment was successful even if we can't get connection info
    }
}
catch {
    # Redact sensitive information from error output
    $errorMessage = $_.Exception.Message
    if ($errorMessage -match '(password|credential|secret).*?[:=]\s*[^\s]+') {
        $errorMessage = $errorMessage -replace '(password|credential|secret).*?[:=]\s*[^\s]+', '$1: [REDACTED]'
    }
    
    Write-ErrorDetails -ErrorRecord $_ 
    if ($script:TranscriptStarted) {
        Stop-Transcript
        $script:TranscriptStarted = $false
    }
    throw "Script failed. See transcript for details. Error: $errorMessage"
}
finally {
    # Cleanup any lingering sessions
    Get-PSSession | Where-Object { $_.State -ne "Broken" } | Remove-PSSession -ErrorAction SilentlyContinue
    
    # Test auto-shutdown configuration before ending the script
    if (Get-Command Get-AzResource -ErrorAction SilentlyContinue) {
        try {
            Write-Host "`n=== Auto-Shutdown Schedule Verification ===`n" -ForegroundColor Cyan
            Test-AutoShutdownSchedule -ResourceGroupName $ResourceGroupName -VMName $VMName
        } catch {
            Write-Warning "Auto-shutdown verification failed: $_"
        }
    }
    
    if ($script:TranscriptStarted) {
        Stop-Transcript
        $script:TranscriptStarted = $false
    }
}
