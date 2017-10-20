# Azure - Upload NSG flow logs to OMS

This is a script that will connect to an Azure Storage Account to export the Network Security Group flow logs, process them and upload them to OMS. This allows for greatly reduced firewall log troubleshooting times. Currently this script only supports using the storage account key, future versions may add SAS token support.

Please set the following variables for the script to function properly:

``` javascript
// Storage Account Connection String
const connectionString = "DefaultEndpointsProtocol=https;AccountName=;AccountKey=;EndpointSuffix=core.windows.net";

// Enter ID of OMS Workspace that you want to upload flow logs to.
const workspaceId = "00000000-0000-0000-0000-000000000000";

// Enter shared key of OMS Workspace
const sharedKey = "";

// Name of the LogType in OMS
// Note suffix of "_CL" will be added in OMS, example is "NsgFlowLogs_CL"
const omsLogType = "NsgFlowLogs";
```

Inspiration for this Node.js based version of the script came from a Powershell version created by a MS Cloud Solution Architect. Please see Jason's blog entry for more information on that one:  
https://blogs.msdn.microsoft.com/cloud_solution_architect/2017/04/03/uploading-azure-nsg-flow-logs-to-oms/