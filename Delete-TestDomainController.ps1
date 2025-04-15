# =============================================================================
# Script: Delete-TestDomainController.ps1
# Created: 2025-03-04 22:13:21 UTC
# Author: maxdaylight
# Last Updated: 2025-03-04 22:31:45 UTC
# Updated By: maxdaylight
# Version: 1.2
# Additional Info: Fixed virtual network deletion by ensuring proper subnet cleanup
# =============================================================================

<#
.SYNOPSIS
    Deletes resources created by Create-TestDomainController.ps1 while preserving the Resource Group.

.DESCRIPTION
    This script removes Azure resources created by the Create-TestDomainController.ps1 script
    while maintaining the empty Resource Group. It performs cleanup operations in reverse order
    of resource creation to ensure proper dependency handling.
    
    Key actions:
    - Validates Azure connection and resource existence
    - Removes auto-shutdown schedules
    - Deletes VM and associated resources
    - Removes network resources (NSG, NIC, Public IP)
    - Deletes storage accounts used for diagnostics
    - Leaves the Resource Group intact for future use
    - Provides detailed logging and status reporting
    
    Dependencies:
    - Windows 11 Pro workstation
    - PowerShell 7.5.0
    - Az PowerShell modules
    - Active Azure subscription
    - Administrative privileges

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group containing resources to be deleted.
    Default value: "MD-TEST-RG2"

.PARAMETER VMName
    The name of the virtual machine to be deleted.
    Default value: "MD-TEST-DC01"

.PARAMETER VnetName
    The name of the Virtual Network to be deleted.
    Default value: "MD-TEST-VNET"

.PARAMETER StorageAccountName
    The name of the storage account for boot diagnostics and scripts.
    Default value: "MDteststorage0"

.PARAMETER OSDiskName
    The name of the OS disk resource for the virtual machine.
    Default value: "MD-TEST-DC01-OSDISK"

.EXAMPLE
    .\Delete-TestDomainController.ps1
    Deletes resources using default values

.EXAMPLE
    .\Delete-TestDomainController.ps1 -ResourceGroupName "MyRG" -VMName "MyVM"
    Deletes resources in the specified resource group with custom VM name

.NOTES
    Security Level: High
    Required Permissions: Azure Subscription Contributor
    Validation Requirements: 
    - Azure PowerShell modules
    - Network connectivity to Azure
    - Access to target resources
    - Resource existence verification
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [Parameter()]
    [string]$ResourceGroupName = "MD-TEST-RG2",

    [Parameter()]
    [string]$VMName = "MD-TEST-DC01",

    [Parameter()]
    [string]$VnetName = "MD-TEST-VNET",

    [Parameter()]
    [string]$StorageAccountName = "MDteststorage0",

    [Parameter()]
    [string]$OSDiskName = "MD-TEST-DC01-OSDISK"
)

# Set strict error handling
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
Set-StrictMode -Version Latest

# Enable extended error details
$FormatEnumerationLimit = -1
$InformationPreference = 'Continue'

# Start transcript logging
$script:TranscriptStarted = $false

# Start logging only if not already started
if (-not $script:TranscriptStarted) {
    $ScriptPath = $PSScriptRoot
    if (-not $ScriptPath) {
        $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }
    $LogDir = Join-Path $ScriptPath "Logs"
    $LogFile = Join-Path $LogDir "Delete-TestDomainController_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    try {
        # Create logs directory if it doesn't exist
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        
        # Start new transcript
        Start-Transcript -Path $LogFile -Force
        $script:TranscriptStarted = $true
    }
    catch {
        Write-Error "Failed to initialize logging: $_"
        throw
    }
}

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

function Remove-AutoShutdownSchedule {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        Write-Host "Checking for auto-shutdown schedules..." -ForegroundColor Cyan
        
        # Get current subscription ID
        $subscriptionId = (Get-AzContext).Subscription.Id
        if (-not $subscriptionId) {
            Write-Warning "Could not retrieve subscription ID"
            return $false
        }
        
        # Check standard naming convention
        $scheduleName = "shutdown-computevm-$VMName"
        $scheduleId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/$scheduleName"
        $schedule = Get-AzResource -ResourceId $scheduleId -ErrorAction SilentlyContinue
        
        # Check alternative naming convention
        $altScheduleName = "$VMName/auto-shutdown"
        $altScheduleId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/$altScheduleName"
        $altSchedule = Get-AzResource -ResourceId $altScheduleId -ErrorAction SilentlyContinue

        # Check general resources of this type
        $allSchedules = @(Get-AzResource -ResourceGroupName $ResourceGroupName `
                                      -ResourceType "Microsoft.DevTestLab/schedules" `
                                      -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Name -like "*$VMName*" -or $_.Name -like "*auto-shutdown*" })
                                     
        # Remove standard schedule if found
        if ($schedule) {
            if ($PSCmdlet.ShouldProcess("Auto-shutdown schedule $scheduleName", "Remove")) {
                Write-Host "Removing auto-shutdown schedule: $scheduleName" -ForegroundColor Yellow
                $null = Remove-AzResource -ResourceId $scheduleId -Force
                Write-Host "Auto-shutdown schedule removed successfully" -ForegroundColor Green
            }
        }
        
        # Remove alternative schedule if found
        if ($altSchedule) {
            if ($PSCmdlet.ShouldProcess("Auto-shutdown schedule $altScheduleName", "Remove")) {
                Write-Host "Removing auto-shutdown schedule (alt): $altScheduleName" -ForegroundColor Yellow
                $null = Remove-AzResource -ResourceId $altScheduleId -Force
                Write-Host "Alternative auto-shutdown schedule removed successfully" -ForegroundColor Green
            }
        }
        
        # Remove any other matching schedules
        if ($allSchedules.Count -gt 0) {
            foreach ($s in $allSchedules) {
                if ($PSCmdlet.ShouldProcess("Auto-shutdown schedule $($s.Name)", "Remove")) {
                    Write-Host "Removing additional auto-shutdown schedule: $($s.Name)" -ForegroundColor Yellow
                    $null = Remove-AzResource -ResourceId $s.Id -Force
                    Write-Host "Additional auto-shutdown schedule removed successfully" -ForegroundColor Green
                }
            }
        }
        
        # Check if we removed anything
        if (-not $schedule -and -not $altSchedule -and -not $allSchedules) {
            Write-Host "No auto-shutdown schedules found" -ForegroundColor Yellow
            return $true
        }
        
        return $true
    }
    catch {
        Write-Warning "Error removing auto-shutdown schedule: $_"
        return $false
    }
}

function Remove-VirtualMachine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        # Check if VM exists
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
        
        if (-not $vm) {
            Write-Host "VM '$VMName' not found in resource group '$ResourceGroupName'" -ForegroundColor Yellow
            return $true
        }
        
        if ($PSCmdlet.ShouldProcess("Virtual Machine $VMName", "Remove")) {
            Write-Host "Removing virtual machine: $VMName" -ForegroundColor Cyan
            
            # Force stop the VM if it's running
            $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status -ErrorAction SilentlyContinue
            if ($vmStatus -and $vmStatus.Statuses.DisplayStatus -contains "VM running") {
                Write-Host "Stopping VM before removal..." -ForegroundColor Yellow
                $null = Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force
                Write-Host "VM stopped successfully" -ForegroundColor Green
            }
            
            # Remove VM
            $result = Remove-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force
            
            if ($result -and $result.Status -eq "Succeeded") {
                Write-Host "Virtual machine removed successfully" -ForegroundColor Green
                return $true
            }
            else {
                Write-Warning "VM removal operation did not return success status"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-NetworkInterfaces {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        Write-Host "Searching for network interfaces..." -ForegroundColor Cyan
        
        # Get all NICs in the resource group - use @() to ensure array
        $nics = @(Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName | 
                Where-Object { $_.Name -like "*$VMName*" -or $_.Name -eq "$VMName-NIC" })
        
        if ($nics.Count -eq 0) {
            Write-Host "No network interfaces found for VM '$VMName'" -ForegroundColor Yellow
            return $true
        }

        $allNicsRemoved = $true
        
        foreach ($nic in $nics) {
            if ($PSCmdlet.ShouldProcess("Network Interface $($nic.Name)", "Remove")) {
                # Enhanced error handling with retry logic
                $maxRetries = 3
                $retryCount = 0
                $success = $false

                while (-not $success -and $retryCount -lt $maxRetries) {
                    try {
                        $retryCount++
                        if ($retryCount -gt 1) {
                            Write-Host "Retry $retryCount of $maxRetries to remove network interface..." -ForegroundColor Yellow
                            # Wait before retrying
                            Start-Sleep -Seconds ($retryCount * 5)
                        }

                        Write-Host "Removing network interface: $($nic.Name)" -ForegroundColor Yellow
                        
                        # First, remove any IP configurations from the NIC
                        if ($nic.IpConfigurations -and $nic.IpConfigurations.Count -gt 0) {
                            Write-Host "Removing IP configurations from network interface..." -ForegroundColor Yellow
                            # Disconnect the NIC from backend pools if connected
                            foreach ($ipConfig in $nic.IpConfigurations) {
                                if ($ipConfig.LoadBalancerBackendAddressPools) {
                                    $ipConfig.LoadBalancerBackendAddressPools = $null
                                }
                                if ($ipConfig.ApplicationGatewayBackendAddressPools) {
                                    $ipConfig.ApplicationGatewayBackendAddressPools = $null
                                }
                            }
                            
                            # Apply the changes to the NIC
                            Set-AzNetworkInterface -NetworkInterface $nic | Out-Null
                        }

                        # Then actually delete the NIC
                        $null = Remove-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nic.Name -Force
                        
                        # Verify the NIC is actually gone
                        $nicCheck = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nic.Name -ErrorAction SilentlyContinue
                        if (-not $nicCheck) {
                            $success = $true
                            Write-Host "Network interface removed successfully" -ForegroundColor Green
                        } else {
                            throw "Network interface still exists after removal attempt"
                        }
                    }
                    catch {
                        Write-Warning "Failed to remove network interface (attempt $retryCount): $_"
                        if ($retryCount -ge $maxRetries) {
                            Write-Error "Failed to remove network interface $($nic.Name) after $maxRetries attempts"
                            $allNicsRemoved = $false
                            break
                        }
                    }
                }
            }
        }
        
        return $allNicsRemoved
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-PublicIpAddresses {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )
    
    try {
        Write-Host "Searching for public IP addresses..." -ForegroundColor Cyan
        
        # Get all public IPs in the resource group - use @() to ensure array
        $publicIps = @(Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | 
                     Where-Object { $_.Name -like "*$VMName*" -or $_.Name -eq "$VMName-IP" })
        
        if ($publicIps.Count -eq 0) {
            Write-Host "No public IP addresses found for VM '$VMName'" -ForegroundColor Yellow
            return $true
        }
        
        foreach ($ip in $publicIps) {
            if ($PSCmdlet.ShouldProcess("Public IP $($ip.Name)", "Remove")) {
                Write-Host "Removing public IP address: $($ip.Name)" -ForegroundColor Yellow
                $null = Remove-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $ip.Name -Force
                Write-Host "Public IP address removed successfully" -ForegroundColor Green
            }
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-NetworkSecurityGroups {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName
    )
    
    try {
        Write-Host "Searching for network security groups..." -ForegroundColor Cyan
        
        # Get all NSGs in the resource group - use @() to ensure array
        $nsgs = @(Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName)
        
        if ($nsgs.Count -eq 0) {
            Write-Host "No network security groups found in resource group '$ResourceGroupName'" -ForegroundColor Yellow
            return $true
        }
        
        foreach ($nsg in $nsgs) {
            if ($PSCmdlet.ShouldProcess("Network Security Group $($nsg.Name)", "Remove")) {
                Write-Host "Removing network security group: $($nsg.Name)" -ForegroundColor Yellow
                $null = Remove-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $nsg.Name -Force
                Write-Host "Network security group removed successfully" -ForegroundColor Green
            }
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-DiskResources {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        
        [Parameter()]
        [string]$OSDiskName
    )
    
    try {
        Write-Host "Searching for disk resources..." -ForegroundColor Cyan
        
        # First check for the specific OS disk if provided
        if ($OSDiskName) {
            $osDisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $OSDiskName -ErrorAction SilentlyContinue
            
            if ($osDisk) {
                if ($PSCmdlet.ShouldProcess("OS Disk $OSDiskName", "Remove")) {
                    Write-Host "Removing OS disk: $OSDiskName" -ForegroundColor Yellow
                    $null = Remove-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $OSDiskName -Force
                    Write-Host "OS disk removed successfully" -ForegroundColor Green
                }
            }
        }
        
        # Then check for any disks related to the VM - use @() to ensure array
        $vmDisks = @(Get-AzDisk -ResourceGroupName $ResourceGroupName | 
                   Where-Object { $_.Name -like "*$VMName*" })
        
        if ($vmDisks.Count -gt 0) {
            foreach ($disk in $vmDisks) {
                # Skip if we already deleted this disk
                if ($disk.Name -eq $OSDiskName) {
                    continue
                }
                
                if ($PSCmdlet.ShouldProcess("Disk $($disk.Name)", "Remove")) {
                    Write-Host "Removing disk: $($disk.Name)" -ForegroundColor Yellow
                    $null = Remove-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $disk.Name -Force
                    Write-Host "Disk removed successfully" -ForegroundColor Green
                }
            }
        }
        elseif (-not $osDisk) {
            Write-Host "No disk resources found for VM '$VMName'" -ForegroundColor Yellow
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-StorageAccount {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter()]
        [string]$StorageAccountName
    )
    
    try {
        Write-Host "Checking for storage account..." -ForegroundColor Cyan
        
        if ($StorageAccountName) {
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
            
            if ($storageAccount) {
                if ($PSCmdlet.ShouldProcess("Storage Account $StorageAccountName", "Remove")) {
                    Write-Host "Removing storage account: $StorageAccountName" -ForegroundColor Yellow
                    $null = Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Force
                    Write-Host "Storage account removed successfully" -ForegroundColor Green
                }
            }
            else {
                Write-Host "Storage account '$StorageAccountName' not found" -ForegroundColor Yellow
            }
        }
        else {
            # No specific storage account provided, look for any in the resource group
            $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
            
            if ($storageAccounts.Count -gt 0) {
                foreach ($account in $storageAccounts) {
                    if ($PSCmdlet.ShouldProcess("Storage Account $($account.StorageAccountName)", "Remove")) {
                        Write-Host "Removing storage account: $($account.StorageAccountName)" -ForegroundColor Yellow
                        $null = Remove-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $account.StorageAccountName -Force
                        Write-Host "Storage account removed successfully" -ForegroundColor Green
                    }
                }
            }
            else {
                Write-Host "No storage accounts found in resource group '$ResourceGroupName'" -ForegroundColor Yellow
            }
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

function Remove-VirtualNetwork {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$VnetName
    )
    
    try {
        Write-Host "Checking for virtual network..." -ForegroundColor Cyan
        
        $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VnetName -ErrorAction SilentlyContinue
        
        if ($vnet) {
            # Before deleting, check if any subnets are still in use
            $subnetsInUse = $false
            $problemNics = @()
            
            foreach ($subnet in $vnet.Subnets) {
                # Check if any resources are using this subnet
                $nics = @(Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName | 
                        Where-Object { 
                            $_.IpConfigurations | Where-Object { 
                                $_.Subnet -and $_.Subnet.Id -eq $subnet.Id 
                            }
                        })
                
                if ($nics.Count -gt 0) {
                    $subnetsInUse = $true
                    $problemNics += $nics
                    Write-Warning "Subnet $($subnet.Name) is still in use by network interfaces: $($nics.Name -join ', ')"
                }
            }
            
            if ($subnetsInUse) {
                # Attempt to clean up the remaining NICs
                Write-Host "Attempting to clean up remaining network interfaces..." -ForegroundColor Yellow
                
                foreach ($nic in $problemNics) {
                    try {
                        Write-Host "Forcibly removing network interface: $($nic.Name)" -ForegroundColor Yellow
                        
                        # Dissociate from any VMs
                        if ($nic.VirtualMachine) {
                            $vmId = $nic.VirtualMachine.Id
                            if ($vmId) {
                                $vmName = $vmId.Split('/')[-1]
                                $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -ErrorAction SilentlyContinue
                                if ($vm) {
                                    Write-Warning "NIC is still attached to VM: $vmName. Attempting to stop and remove VM first."
                                    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -Force -ErrorAction SilentlyContinue
                                    Remove-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -Force -ErrorAction SilentlyContinue
                                }
                            }
                        }
                        
                        # Remove any IP configurations
                        $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nic.Name -ErrorAction SilentlyContinue
                        if ($nic) {
                            foreach ($ipConfig in $nic.IpConfigurations) {
                                $ipConfig.Subnet = $null
                                $ipConfig.PrivateIpAddress = $null
                                $ipConfig.PublicIpAddress = $null
                            }
                            
                            # Apply the changes
                            Set-AzNetworkInterface -NetworkInterface $nic -ErrorAction SilentlyContinue
                            
                            # Now try to delete it
                            Remove-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nic.Name -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        Write-Warning "Failed to clean up network interface $($nic.Name): $_"
                    }
                }
                
                # Refresh our VNet reference
                $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VnetName -ErrorAction SilentlyContinue
            }
            
            # Try to delete the VNet now
            if ($PSCmdlet.ShouldProcess("Virtual Network $VnetName", "Remove")) {
                try {
                    # Try emptying the subnets collection before deleting
                    if ($vnet -and $vnet.Subnets.Count -gt 0) {
                        Write-Host "Attempting to remove subnet associations before deleting virtual network..." -ForegroundColor Yellow
                        
                        # Get a fresh copy of the virtual network
                        $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VnetName
                        
                        # Remove all subnets - have to do this in a way that works with the way Azure manages subnets
                        # Create a new VNet configuration without any subnets
                        $vnetConfig = New-AzVirtualNetwork -Name $vnet.Name -ResourceGroupName $ResourceGroupName `
                            -Location $vnet.Location -AddressPrefix $vnet.AddressSpace.AddressPrefixes `
                            -Force
                        
                        if ($vnetConfig) {
                            Write-Host "Virtual network updated without subnets" -ForegroundColor Green
                        }
                    }
                    
                    # Now try to delete the VNet
                    Write-Host "Removing virtual network: $VnetName" -ForegroundColor Yellow
                    $null = Remove-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VnetName -Force
                    Write-Host "Virtual network removed successfully" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not delete virtual network: $_"
                    Write-Host "You may need to manually delete the virtual network from the Azure portal" -ForegroundColor Yellow
                    return $false
                }
            }
        }
        else {
            Write-Host "Virtual network '$VnetName' not found" -ForegroundColor Yellow
            
            # Check for any other VNets in the resource group - use @() to ensure array
            $vnets = @(Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
            
            if ($vnets.Count -gt 0) {
                foreach ($v in $vnets) {
                    if ($PSCmdlet.ShouldProcess("Virtual Network $($v.Name)", "Remove")) {
                        try {
                            Write-Host "Removing virtual network: $($v.Name)" -ForegroundColor Yellow
                            $null = Remove-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $v.Name -Force
                            Write-Host "Virtual network removed successfully" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Could not delete virtual network $($v.Name): $_"
                        }
                    }
                }
            }
        }
        
        return $true
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_
        return $false
    }
}

# Main execution block
try {
    Write-Host "Starting cleanup process for resources in '$ResourceGroupName'..." -ForegroundColor Cyan
    
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
    
    # Check if resource group exists
    try {
        # Remove variable assignment and directly verify resource group exists
        Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        Write-Host "Resource group '$ResourceGroupName' found" -ForegroundColor Green
    }
    catch {
        Write-Error "Resource group '$ResourceGroupName' not found. Cannot proceed with cleanup."
        throw
    }
    
    # Remove resources in reverse order of creation to handle dependencies
    
    # 1. Remove auto-shutdown schedule
    if (Remove-AutoShutdownSchedule -ResourceGroupName $ResourceGroupName -VMName $VMName) {
        Write-Host "Auto-shutdown schedule cleanup completed" -ForegroundColor Green
    }
    
    # 2. Remove the VM
    if (Remove-VirtualMachine -ResourceGroupName $ResourceGroupName -VMName $VMName) {
        Write-Host "Virtual machine cleanup completed" -ForegroundColor Green
    }
    
    # 3. Remove network interfaces
    $networkInterfacesRemoved = Remove-NetworkInterfaces -ResourceGroupName $ResourceGroupName -VMName $VMName
    if ($networkInterfacesRemoved) {
        Write-Host "Network interfaces cleanup completed" -ForegroundColor Green
    } else {
        Write-Warning "Some network interfaces could not be removed. This may affect other resource cleanup."
    }
    
    # 4. Remove public IP addresses
    if (Remove-PublicIpAddresses -ResourceGroupName $ResourceGroupName -VMName $VMName) {
        Write-Host "Public IP addresses cleanup completed" -ForegroundColor Green
    }
    
    # 5. Remove network security groups
    if (Remove-NetworkSecurityGroups -ResourceGroupName $ResourceGroupName) {
        Write-Host "Network security groups cleanup completed" -ForegroundColor Green
    }
    
    # 6. Remove disk resources
    if (Remove-DiskResources -ResourceGroupName $ResourceGroupName -VMName $VMName -OSDiskName $OSDiskName) {
        Write-Host "Disk resources cleanup completed" -ForegroundColor Green
    }
    
    # 7. Remove storage account
    if (Remove-StorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName) {
        Write-Host "Storage account cleanup completed" -ForegroundColor Green
    }
    
    # 8. Remove virtual network - attempt this last after all other cleanups
    if (Remove-VirtualNetwork -ResourceGroupName $ResourceGroupName -VnetName $VnetName) {
        Write-Host "Virtual network cleanup completed" -ForegroundColor Green
    } else {
        Write-Host "Virtual network could not be fully cleaned up - manual intervention may be required" -ForegroundColor Yellow
    }
    
    # Final verification
    Write-Host "Verifying resource cleanup..." -ForegroundColor Cyan
    $remainingResources = @(Get-AzResource -ResourceGroupName $ResourceGroupName)
    
    if ($remainingResources.Count -gt 0) {
        Write-Host "Remaining resources in resource group:" -ForegroundColor Yellow
        $remainingResources | ForEach-Object {
            Write-Host "  - $($_.ResourceType): $($_.Name)" -ForegroundColor Yellow
        }
        Write-Host "Some resources still exist in the resource group. You may need to manually delete them." -ForegroundColor Yellow
    }
    else {
        Write-Host "All resources successfully removed from resource group '$ResourceGroupName'" -ForegroundColor Green
        Write-Host "Resource group has been preserved as requested" -ForegroundColor Green
    }
    
    Write-Host "Cleanup process completed successfully" -ForegroundColor Green
}
catch {
    Write-ErrorDetails -ErrorRecord $_
    throw "Script failed. See transcript for details."
}
finally {
    if ($script:TranscriptStarted) {
        Stop-Transcript
        $script:TranscriptStarted = $false
    }
}
