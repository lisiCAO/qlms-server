const { property, user, image } = require("../models"); // Import property model
const { sequelize, Sequelize } = require("../models/index");
const imageService = require("./imageService");

// Service to create a new property
/* In service layer, all errors should be thrown only , and handled in controller */
exports.createProperty = async (propertyData, userId, transaction) => {
    if (!propertyData.address || propertyData.address.length < 5) {
        throw new Error(
            "Property address is required and should be at least 5 characters."
        );
    }
    // Validate user role
    const User = await user.findByPk(userId);
    if (!User) {
        throw new Error("User not found.");
    }
    if (User.role !== "landlord") {
        throw new Error("Only landlords can create properties.");
    }
    // Trim address
    propertyData.address = propertyData.address.trim();
    // Check if property with the same address already exists
    const existingProperty = await property.findOne({
        where: { address: propertyData.address },
    });
    if (existingProperty) {
        throw new Error("A property with the same address already exists.");
    }
    // Create property
    try {
        const newProperty = await property.create(
            {
                ...propertyData,
                owner_user_id: userId,
            },
            { transaction }
        );

        return newProperty;
    } catch (error) {
        // Rollback transaction if any errors were encountered
        // If any operation fails, rollback the transaction
        if (transaction.rollback) {
            await transaction.rollback();
        }
        throw error; // Throw error to controller
    }
};

exports.createPropertyWithImages = async (propertyData, imagesData, userId) => {
    const transaction = await sequelize.transaction();

    try {
        // Step 1: Create the property
        const newProperty = await this.createProperty(
            propertyData,
            userId,
            transaction
        );
        // Step 2: Process images with imageService
        // Ensure imageService.saveImages is adapted to accept a transaction
        const processedImages = await imageService.saveImages(
            imagesData,
            newProperty.id,
            transaction
        );

        // If all operations are successful, commit the transaction
        await transaction.commit();

        return { property: newProperty, images: processedImages };
    } catch (error) {
        // If any operation fails, rollback the transaction
        if (transaction.rollback) {
            await transaction.rollback();
        }

        throw error;
    }
};

exports.getAllProperties = async () => {
    const sql = `SELECT * FROM property;`; // get all properties

    const propertiesResult = await sequelize.query(sql, {
        type: Sequelize.QueryTypes.SELECT,
    });

    //for each property, get all images
    for (const property of propertiesResult) {
        const imageSql = `SELECT property_id, image_url, description, uploaded_at, is_primary FROM image WHERE property_id = ${property.id};`;
        const imagesResult = await sequelize.query(imageSql, {
            type: Sequelize.QueryTypes.SELECT,
        });
        property.image_urls = imagesResult.map((image) => image.image_url);
    }

    return propertiesResult;
};

exports.getSingleProperty = async (propertyId) => {
    const sql = `SELECT * FROM property where id = ${propertyId};`; // get single property by id

    let properyResult = await sequelize.query(sql, {
        type: Sequelize.QueryTypes.SELECT,
    });

    //for each property, get all images
    const imageSql = `SELECT property_id, image_url, description, uploaded_at, is_primary FROM image WHERE property_id = ${properyResult[0].id};`;
    const imagesResult = await sequelize.query(imageSql, {
        type: Sequelize.QueryTypes.SELECT,
    });
    properyResult[0].image_urls = imagesResult.map((image) => image.image_url);

    return properyResult;
};

exports.updateProperty = async (propertyId, propertyData) => {
    const propertyToUpdate = await property.findByPk(propertyId);

    if (!propertyToUpdate) {
        return null; // Property not found
    }

    // update property
    await propertyToUpdate.update(propertyData);
    return propertyToUpdate;
};

exports.deleteProperty = async (propertyId) => {
    const propertyToDelete = await property.findByPk(propertyId);

    if (!propertyToDelete) {
        return false; // Property not found
    }

    await propertyToDelete.destroy();
    return true;
};

exports.getAvailableProperties = async () => {
    const sql = `SELECT * FROM property where status = 'available';`; // get all properties where status is 'available'

    const propertiesResult = await sequelize.query(sql, {
        type: Sequelize.QueryTypes.SELECT,
    });

    //for each property, get all images
    for (const property of propertiesResult) {
        const imageSql = `SELECT property_id, image_url, description, uploaded_at, is_primary FROM image WHERE property_id = ${property.id};`;
        const imagesResult = await sequelize.query(imageSql, {
            type: Sequelize.QueryTypes.SELECT,
        });
        property.image_urls = imagesResult.map((image) => image.image_url);
    }

    return propertiesResult;
};
