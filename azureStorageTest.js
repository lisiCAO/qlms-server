const { BlobServiceClient } = require("@azure/storage-blob");
require("dotenv").config();

async function listBlobs() {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(
            process.env.AZURE_STORAGE_CONNECTION_STRING
        );
        const containerClient =
            blobServiceClient.getContainerClient("qlmsfile"); // container name

        // 列出容器中的blobs
        for await (const blob of containerClient.listBlobsFlat()) {
            console.log(`- ${blob.name}`);
        }
    } catch (error) {
        console.error("Error listing blobs:", error.message);
        throw error;
    }
}

listBlobs();
