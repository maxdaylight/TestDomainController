# Create-TestDomainController

A PowerShell automation solution for creating and managing an Azure-based Domain Controller VM that automatically shuts down at 9pm MST to minimize costs.nimize costs.

## Overview

This repository contains scripts that automate the deployment, configuration, and cleanup of a fully functional Windows Server 2022 Domain Controller in Azure. It's designed specifically for test environments and includes cost-saving features like automatic shutdown.

### Scripts

- **Create-TestDomainController.ps1**: Deploys and configures a Domain Controller in Azure
- **Delete-TestDomainController.ps1**: Removes the Domain Controller and associated Azure resources

### Key Features

- **One-click deployment**: Creates all necessary Azure resources automatically
- **Auto-shutdown**: VM automatically shuts down at 9pm Mountain Standard Time
- **Test accounts**: Automatically creates test user accounts in Active Directory
- **Hardened security**: Implements recommended security settings for Domain Controllers
- **PowerShell 7.5.0 compatible**: Runs natively on Windows 11 Pro workstations
- **No server dependencies**: Can be executed from any client workstation with proper modules
- **Error resilience**: Includes robust error handling and diagnostic logging
- **Trusted Launch**: Enables Azure security features including vTPM and Secure Boot
- **Full cleanup**: Ability to remove all created resources while preserving the resource group

## Prerequisites

- Windows 11 Pro workstation
- PowerShell 7.5.0 or later
- Azure PowerShell modules (`Az` module)
- Active Azure subscription with contributor access
- Administrative privileges on local workstation

## Installation

1. Clone this repository to your local machine:
   ```
   git clone https://github.com/your-username/TestDomainController.git
   ```

2. Navigate to the repository directory:
   ```
   cd TestDomainController
   ```

3. Install required PowerShell modules (if not already installed):
   ```powershell
   Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force
   ```

4. Connect to your Azure account:
   ```powershell
   Connect-AzAccount
   ```

5. Create an `.env` file in the repository directory with the following credentials:
   ```
   ADMIN_PASSWORD=YourSecurePassword123!
   SAFE_MODE_PASSWORD=YourSafeModePassword123!
   TEST_USER_PASSWORD=YourTestUserPassword123!
   ```

## Usage

### Creating a Domain Controller

Run the script with default parameters:

```powershell
.\Create-TestDomainController.ps1
```

This will create a domain controller with these default settings:
- Resource Group: MD-TEST-RG2
- VM Name: MD-TEST-DC01
- Location: westus2
- Domain: MDtest.local
- VM Size: Standard_D2s_v3
- Admin Username: MDadmin

#### Create-TestDomainController Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| ResourceGroupName | Azure resource group name | MD-TEST-RG2 |
| Location | Azure region | westus2 |
| VMSize | VM size/SKU | Standard_D2s_v3 |
| VMName | Name of VM | MD-TEST-DC01 |
| VnetName | Virtual network name | MD-TEST-VNET |
| SubnetName | Subnet name | MD-TEST-SUBNET |
| StorageAccountName | Storage account name | MDteststorage0 |
| ContainerName | Storage container name | scripts |
| DomainName | AD domain name | MDtest.local |
| AdminUsername | Administrator username | MDadmin |
| TestUserPrefix | Prefix for test user accounts | TestUser |
| ShutdownTime | Auto-shutdown time (24hr format) | 2100 |
| TimeZone | Time zone for auto-shutdown | Mountain Standard Time |

### Custom Configuration Example

```powershell
.\Create-TestDomainController.ps1 `
    -ResourceGroupName "MyTestRG" `
    -Location "eastus" `
    -VMName "MyTestDC" `
    -VMSize "Standard_B2s" `
    -DomainName "mytest.local" `
    -AdminUsername "myadmin" `
    -ShutdownTime "2000"
```

### Deleting a Domain Controller

To remove all resources created by the deployment script:

```powershell
.\Delete-TestDomainController.ps1
```

This will remove the VM, disks, network interfaces, public IPs, NSG, virtual network, and storage accounts.

#### Delete-TestDomainController Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| ResourceGroupName | Azure resource group name | MD-TEST-RG2 |
| VMName | Name of VM to delete | MD-TEST-DC01 |
| VnetName | Virtual network name | MD-TEST-VNET |
| StorageAccountName | Storage account name | MDteststorage0 |
| OSDiskName | OS disk resource name | MD-TEST-DC01-OSDISK |

### Custom Deletion Example

```powershell
.\Delete-TestDomainController.ps1 `
    -ResourceGroupName "MyTestRG" `
    -VMName "MyTestDC" `
    -VnetName "MyTestVNET"
```

## Security Notes

- Environment variables in `.env` file store sensitive credentials
- Domain security is hardened with recommended settings for testing purposes
- Trusted Launch is enabled with vTPM and Secure Boot
- Network security group allows specific ports for domain services
- Static IP configuration for network stability
- Not recommended for production use without additional security measures

## Logging

Logs are stored in the `Logs` directory with a timestamp. Each run creates a new log file with detailed output for troubleshooting:
- Create-TestDomainController_YYYYMMDD_HHMMSS.log
- Delete-TestDomainController_YYYYMMDD_HHMMSS.log

## Auto-Shutdown

The VM is scheduled to automatically shut down at the specified time (default: 9:00 PM Mountain Standard Time) to save costs. You can modify this by setting the `-ShutdownTime` parameter (24-hour format) and `-TimeZone` parameter.

## Connect to the VM

After deployment, the script displays connection information:
- RDP to the public IP address
- Username: admin (or custom admin username)

This project is licensed under the UnLicense - see the LICENSE file for details.