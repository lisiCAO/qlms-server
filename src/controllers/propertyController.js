const { body, validationResult } = require("express-validator");
const propertyService = require("../services/propertyService");
const { user, property, lease } = require("../models/index");
const { sequelize, Sequelize } = require("../models");

// Validate and sanitize fields using express-validator
exports.propertyValidationRules = [
    /* TODO: adjust validation according to business logic */
    // body('owner_user_id').isInt().withMessage('Owner user ID must be an integer'),
    body("address").isLength({ min: 1 }).withMessage("Address is required"),
    body("number_of_units")
        .isInt({ min: 1 })
        .withMessage("Number of units must be at least 1"),
    body("property_type")
        .isIn(["apartment", "house", "condo"])
        .withMessage("Invalid property type"),
    body("size_in_sq_ft")
        .isInt({ min: 1 })
        .withMessage("Size in square feet must be a positive integer"),
    body("year_built")
        .isInt({ min: 1900, max: new Date().getFullYear() })
        .withMessage("Invalid year built"),
    body("rental_price")
        .isDecimal()
        .withMessage("Rental price must be a decimal"),
    body("status")
        .isIn(["available", "rented", "under_maintenance"])
        .withMessage("Invalid status"),
    // ...
];

// Create a new property
exports.createProperty = async (req, res) => {
    // Check if there are validation errors
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.sendError(
            "Create a new property failed: " +
                errors
                    .array()
                    .map((err) => err.msg)
                    .join(", "),
            422
        );
    }

    try {
        // Create property, body is property, req.user.id is owner_user_id, req.files is images
        const result = await propertyService.createPropertyWithImages(
            req.body,
            req.files,
            req.user.userId
        );
        // Send success response
        res.sendSuccess(result, "Property created successfully");
    } catch (error) {
        // TODO: Log error
        res.sendError("Failed to create property: " + error.message, 500);
    }
};

exports.getAllProperties = async (req, res) => {
    try {
        const properties = await propertyService.getAllProperties();
        res.sendSuccess(properties, "Properties retrieved successfully");
    } catch (error) {
        res.sendError("Failed to retrieve properties: " + error.message, 500);
    }
};

exports.getSingleProperty = async (req, res) => {
    try {
        const prop = await propertyService.getSingleProperty(req.params.id);
        if (prop) {
            res.sendSuccess(prop, "Property retrieved successfully");
        } else {
            res.sendError("Property not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to retrieve property: " + error.message, 500);
    }
};

exports.updateProperty = async (req, res) => {
    const propertyId = req.params.id;
    const propertyData = req.body;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.sendError(
            "Update a property failed: " +
                errors
                    .array()
                    .map((err) => err.msg)
                    .join(", "),
            422
        );
    }

    try {
        const updatedProperty = await propertyService.updateProperty(
            propertyId,
            propertyData
        );
        if (updatedProperty) {
            res.sendSuccess(updatedProperty, "Property updated successfully");
        } else {
            res.sendError("Property not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to update property: " + error.message, 500);
    }
};

exports.deleteProperty = async (req, res) => {
    const propertyId = req.params.id;

    try {
        const deleted = await propertyService.deleteProperty(propertyId);
        if (deleted) {
            res.sendSuccess(null, "Property deleted successfully");
        } else {
            res.sendError("Property not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to delete property: " + error.message, 500);
    }
};

exports.getUserPropertiesInfo = async (req, res) => {
    try {
        const userId = req.user.userId; // get the user ID from the token

        // get all properties owned by the user
        let sql = `SELECT u.id AS tenant_id, u.username AS tenant_name, p.id AS property_id, p.address, p.property_type as type, l.id AS lease_id, l.start_date AS lease_startDate, l.end_date AS lease_endDate, l.rent_amount AS monthly_rent
                   FROM lease l JOIN property p ON l.property_id = p.id JOIN user u ON l.tenant_user_id = u.id
                   WHERE
                   p.owner_user_id = ${userId}
                   ORDER BY l.end_date ASC;`;

        const propertiesResult = await sequelize.query(sql, {
            type: Sequelize.QueryTypes.SELECT,
        });

        //for each property, get all images
        for (const property of propertiesResult) {
            const imageSql = `SELECT image_url FROM image WHERE property_id = ${property.property_id};`;
            const imagesResult = await sequelize.query(imageSql, {
                type: Sequelize.QueryTypes.SELECT,
            });
            property.image_urls = imagesResult.map((image) => image.image_url);
        }

        sql = `select count(*) as propertiesCount from property where property.owner_user_id = ${userId};`;

        const propertiesCount = await sequelize.query(sql, {
            type: Sequelize.QueryTypes.SELECT,
        });

        const responseData = { propertiesCount, propertiesResult };

        res.sendSuccess(responseData, "Property select successfully");
    } catch (error) {
        res.sendError(
            "Error retrieving property and lease information: " + error.message,
            500
        );
    }
};

exports.getAvailableProperties = async (req, res) => {
    try {
        const properties = await propertyService.getAvailableProperties();
        res.sendSuccess(
            properties,
            "Available properties retrieved successfully"
        );
    } catch (error) {
        res.sendError(
            "Failed to retrieve available properties: " + error.message,
            500
        );
    }
};

exports.getTenantPropertiesInfo = async (req, res) => {
    try {
        const userId = req.user.userId; // get the user ID from the token

        // get all properties rented by the user
        let sql = `SELECT p.id AS property_id, p.address, p.number_of_units, p.property_type as type, p.size_in_sq_ft, 
                   p.year_built, p.rental_price, p.amenities,p.lease_terms,p.description
                   FROM lease l JOIN property p ON l.property_id = p.id
                   WHERE
                   l.tenant_user_id = ${userId}
                   ORDER BY l.end_date ASC;`;

        const propertiesResult = await sequelize.query(sql, {
            type: Sequelize.QueryTypes.SELECT,
        });

        //for each property, get all images
        for (const property of propertiesResult) {
            const imageSql = `SELECT image_url FROM image WHERE property_id = ${property.property_id};`;
            const imagesResult = await sequelize.query(imageSql, {
                type: Sequelize.QueryTypes.SELECT,
            });
            property.image_urls = imagesResult.map((image) => image.image_url);
        }

        const responseData = { propertiesResult };

        res.sendSuccess(responseData, "Tenant property retrieved successfully");
    } catch (error) {
        res.sendError(
            "Error retrieving tenant property: " + error.message,
            500
        );
    }
};
