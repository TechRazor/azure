const azure = require("azure-storage");
const crypto = require("crypto");
const request = require("request");

/**
 * Storage Account Parameters
 */

// Storage Account Connection String
const connectionString = "DefaultEndpointsProtocol=https;AccountName=;AccountKey=;EndpointSuffix=core.windows.net";
// Container name of where NSG logs are located.
// The default value here should not need to be changed.
const containerName = "insights-logs-networksecuritygroupflowevent";

/**
 * OMS Parameters
 */

// Enter ID of OMS Workspace that you want to upload flow logs to.
const workspaceId = "00000000-0000-0000-0000-000000000000";
// Enter shared key of OMS Workspace
const sharedKey = "";
// OMS Log Upload API Version
const apiVersion = "2016-04-01";
// Name of the LogType in OMS
// Note suffix of "_CL" will be added in OMS, example is "NsgFlowLogs_CL"
const omsLogType = "NsgFlowLogs";

// Global variable
let blobs = [];

/**
 * Blob Service initialization
 */

const retryOperations = new azure.ExponentialRetryPolicyFilter();
const blobService = azure
  .createBlobService(connectionString)
  .withFilter(retryOperations);

/**
 * Function to get list of blobs from Storage Account
 */

const listBlobsAsync = () => {
  return new Promise((resolve, reject) => {
    let options = {
      maxResults: 5000,
      include: "metadata",
      locationMode: azure.StorageUtilities.LocationMode.PRIMARY_THEN_SECONDARY
    };
    listBlobs(options, null, callback => {
      resolve(blobs);
    });
  });
};

/**
 * Function to return all blobs except for the ones currently being written to.
 * @param {Array} blobs - Array of blob objects from storage account
 */

const filterBlobs = blobs => {
  return new Promise((resolve, reject) => {
    const date = new Date();
    const blobList = [];
    blobs.map(blob => {
      if (
        !(
          blob.name.split("/")[9].split("=")[1] == date.getUTCFullYear() &&
          blob.name.split("/")[10].split("=")[1] == date.getUTCMonth() + 1 &&
          blob.name.split("/")[11].split("=")[1] == date.getUTCDate() &&
          blob.name.split("/")[12].split("=")[1] == date.getUTCHours()
        )
      ) {
        // node module azure-storage lowercases all metadata keys
        if (blob.metadata["omslogtype"] != omsLogType) {
          blobList.push(blob);
        }
      }
    });
    console.log("Unprocessed Blobs: " + blobList.length);
    resolve(blobList);
  });
};

/**
 * Function to get the body content of the blob
 * @param {Object} blob - Blob object from Storage Account
 */

const getBlobContent = blob => {
  return new Promise((resolve, reject) => {
    return blobService.getBlobToText(
      containerName,
      blob.name,
      (err, blobContent, blob) => {
        if (err) reject(err);
        try {
          JSON.parse(blobContent);
        } catch (e) {
          console.log("Failed - " + blob.name);
          return resolve({ name: blob.name, body: { records: [] } });
        }
        resolve({ name: blob.name, body: JSON.parse(blobContent) });
      }
    );
  });
};

/**
 * Function to parse the blob into the format that OMS needs
 * @param {Array} blobContent - Parsed body content from blob
 * @param {String} blobName - Name of the blob for logging success or failure
 */

const parseBlobFlows = blob => {
  return new Promise((resolve, reject) => {
    let array = blob.body.records;
    let farray = [];
    for (let record of array) {
      let subscription = record.resourceId.split("/")[2];
      let resourceGroup = record.resourceId.split("/")[4];
      let nsg = record.resourceId.split("/")[8];
      let props = record.properties.flows;
      for (let prop of props) {
        if (prop.rule && prop.flows.length > 0) {
          for (let p of prop.flows) {
            let mac = p.mac;
            for (let i of p.flowTuples) {
              let flow = i.split(",");
              farray.push({
                SubscriptionId: subscription,
                ResourceGroup: resourceGroup,
                NSG: nsg,
                Rule: prop.rule,
                MAC: mac,
                DateTime: new Date(flow[0] * 1000).toISOString(),
                SourceIp: flow[1],
                DestinationIp: flow[2],
                SourcePort: Number(flow[3]),
                DestinationPort: Number(flow[4]),
                Protocol:
                  flow[5] === "T" ? "TCP" : flow[5] === "U" ? "UDP" : flow[5],
                Direction:
                  flow[6] === "I"
                    ? "Inbound"
                    : flow[6] === "O" ? "Outbound" : flow[6],
                Action:
                  flow[7] === "A" ? "Allow" : flow[7] === "D" ? "Deny" : flow[7]
              });
            }
          }
        }
      }
    }
    console.log("Successful - " + blob.name);
    resolve({ name: blob.name, body: farray });
  }).catch(error => {
    console.log("Failed - " + blob.name);
    reject(error);
  });
};

/**
 * OMS has a file size upload limit so we make smaller arrays to stay below the limit
 * @param {Array} blob - Blob contents from storage account
 */
const resizeArray = blob => {
  let resizedArray = [];
  return new Promise((resolve, reject) => {
    do {
      let body = blob.body.splice(0, 40000);
      resizedArray.push({ name: blob.name, body: body });
    } while (blob.body.length > 40000);
    if (blob.body.length > 0)
      resizedArray.push({ name: blob.name, body: blob.body });
    resolve(resizedArray);
  });
};

/**
 * Credit to the following sites for OMS upload script
 * https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
 * https://github.com/sportsmgmt-labs/Azure-Log-Analytics-Node-Function
 * @param {Object} blob - Parsed nsg flow logs array to upload to OMS
 */

const uploadBlobToOMS = blob => {
  const body = JSON.stringify(blob.body);

  const contentLength = Buffer.byteLength(body, "utf8");
  const processingDate = new Date().toUTCString();

  const stringToSign =
    "POST\n" +
    contentLength +
    "\napplication/json\nx-ms-date:" +
    processingDate +
    "\n/api/logs";
  const signature = crypto
    .createHmac("sha256", new Buffer(sharedKey, "base64"))
    .update(stringToSign, "utf-8")
    .digest("base64");
  const authorization = "SharedKey " + workspaceId + ":" + signature;

  const headers = {
    "Content-Type": "application/json",
    Authorization: authorization,
    "Log-Type": omsLogType,
    "x-ms-date": processingDate,
    "time-generated-field": "DateTime"
  };

  const url = `https://${workspaceId}.ods.opinsights.azure.com/api/logs?api-version=${apiVersion}`;

  return new Promise((resolve, reject) => {
    request.post(
      { url: url, headers: headers, body: body },
      (error, response, body) => {
        console.log("OMS Upload Status Code:", response && response.statusCode);
        if (error) reject(error);
        resolve({ error, response, body });
      }
    );
  });
};

/**
 * Function to upload the resized parsed blob content arrays
 * @param {Array} data - Array of parsed blob arrays
 */
const uploadToOMS = data => {
  let sequence = Promise.resolve();
  data.map(blobContent => {
    sequence = sequence.then(() => {
      return uploadBlobToOMS(blobContent).catch(err => console.log(err));
    });
  });
  return sequence;
};

/**
 * Azure Storage Helper Function - List Blobs in Container
 * @param {Array} options - options like fetching metadata with list
 * @param {azurestorage.common.ContinuationToken} token - token to fetch paged results
 * @callback callback - callback once function is completed
 */

function listBlobs(options, token, callback) {
  blobService.listBlobsSegmented(
    containerName,
    token,
    options,
    (error, result) => {
      if (error) console.log(error);
      blobs.push(...result.entries);
      let token = result.continuationToken;
      if (token) {
        console.log(" Page count: " + result.entries.length + " blobs.");
        listBlobs(options, token, callback);
      } else {
        console.log(" Total count: " + blobs.length + " blobs.");
        callback();
      }
    }
  );
}

/**
 * Main function
 */

const main = () => {
  listBlobsAsync()
    .then(blobs => filterBlobs(blobs))
    .then(blobs => processBlob(blobs))
    .catch(err => console.log("Error occured: ", err));
};

main();

/**
 * Function to process the blobs and upload them to OMS
 * @param {Array} blobs - Array of blobs from storage account
 */

const processBlob = blobs => {
  // Create a new empty promise
  let sequence = Promise.resolve();

  // Loop over each item, and add on a promise to the
  // end of the 'sequence' promise.
  blobs.map(blob => {
    sequence = sequence.then(() => {
      // Stream blob body contents to a variable for processing
      return (
        getBlobContent(blob)
          // Parse blob into format for OMS intake
          .then(content => parseBlobFlows(content))
          .then(parsedContent => resizeArray(parsedContent))
          .then(parsedArray => uploadToOMS(parsedArray))
          .then(omsResult => setBlobMetadata(blob.name))
          .then(status =>
            console.log(
              "Set Metadata Status Code: " + status.response.statusCode
            )
          )
          .then(() => wait(.5))
          .catch(err => console.log("Error occured: ", err))
      );
    });
  });
  return sequence;
};

/**
 * Azure Storage Helper Function - Set Metadata on Blobs
 * Currently we overwrite metadata with "OmsLogType" and "CompressionType" fields
 * @param {String} blobName - Name of the blob
 * @callback callback - A callback to return result of setting blob metadata
 */

const setBlobMetadata = blobName => {
  return new Promise((resolve, reject) => {
    blobService.setBlobMetadata(
      containerName,
      blobName,
      { OmsLogType: omsLogType, CompressionType: "none" },
      (error, result, response) => {
        if (error) reject(error);
        resolve({ error, result, response });
      }
    );
  });
};

/**
 * Function to add a delay between processing blobs to avoid rate limits of the OMS upload API if needed
 * @param {Integer} seconds - Number of seconds to wait
 */

const wait = seconds => {
  return new Promise((resolve, reject) => {
    console.log("waiting " + seconds + " seconds...");
    seconds = seconds * 1000;
    setTimeout(() => {
      console.log("proceeding to next item...");
      resolve();
    }, seconds);
  });
};
