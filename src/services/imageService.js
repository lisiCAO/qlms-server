const { BlobServiceClient } = require("@azure/storage-blob");
const { image } = require("../models");

// Initialize Azure Blob Storage client
const blobServiceClient = BlobServiceClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING
);
const containerName = "qlmsfile"; // Assume container name is 'images'
const containerClient = blobServiceClient.getContainerClient(containerName); // Initialize container client

exports.saveImages = async (imagesData, propertyId, transaction) => {
    try {
        const uploadPromises = imagesData.map(async (file) => {
            const blobName = `property_images/${Date.now()}_${
                file.originalname
            }`; // Create a unique name for each image
            const blockBlobClient =
                containerClient.getBlockBlobClient(blobName);

            // Upload image to Azure Blob Storage
            await blockBlobClient.uploadData(file.buffer, {
                blobHTTPHeaders: { blobContentType: file.mimetype }, // Set blob content type
            });

            // Get image URL from Azure Blob Storage
            const imageUrl = blockBlobClient.url;

            // Return image data to save to database
            return {
                property_id: propertyId,
                image_url: imageUrl,
                description: file.originalname, // Consider allowing user input for description
                uploaded_at: new Date(),
                is_primary: false, // Consider logic for setting primary image
            };
        });

        // Parallelly save images to database and return the result
        const images = await Promise.all(uploadPromises);

        return await image.bulkCreate(images, { transaction });
    } catch (error) {
        throw error; // Throw error to the caller
    }
};
