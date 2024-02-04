const { BlobServiceClient } = require("@azure/storage-blob");

const azureStorageConnectionString =
    process.env.AZURE_STORAGE_CONNECTION_STRING;
const containerName = "qlmsfile"; // Assume container name is 'images'

const blobServiceClient = BlobServiceClient.fromConnectionString(
    azureStorageConnectionString
);
const containerClient = blobServiceClient.getContainerClient(containerName);

module.exports = { containerClient };
