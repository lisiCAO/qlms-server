const { body, validationResult } = require("express-validator");
const leaseService = require("../services/leaseService");

// Validate and sanitize fields using express-validator
exports.createLeaseValidationRules = [
    /* TODO: adjust validation according to business logic */
    body("property_id").isInt().withMessage("Property ID must be an integer"),
    body("tenant_user_id")
        .isInt()
        .withMessage("Tenant user ID must be an integer"),
    body("start_date").isISO8601().withMessage("Invalid start date format"),
    body("end_date").isISO8601().withMessage("Invalid end date format"),
    body("rent_amount")
        .isDecimal()
        .withMessage("Rent amount must be a decimal number"),
    body("payment_due_day")
        .isInt({ min: 1, max: 31 })
        .withMessage("Payment due day must be between 1 and 31"),
    // ...
];

exports.updateLeaseValidationRules = [
    body("property_id")
        .optional()
        .isInt()
        .withMessage("Property ID must be an integer"),
    body("tenant_user_id")
        .optional()
        .isInt()
        .withMessage("Tenant user ID must be an integer"),
    body("start_date")
        .optional()
        .isISO8601()
        .withMessage("Invalid start date format"),
    body("end_date")
        .optional()
        .isISO8601()
        .withMessage("Invalid end date format"),
    body("rent_amount")
        .optional()
        .isDecimal()
        .withMessage("Rent amount must be a decimal number"),
    body("payment_due_day")
        .optional()
        .isInt({ min: 1, max: 31 })
        .withMessage("Payment due day must be between 1 and 31"),
    //
];

const handleValidationErrors = (req, res, message) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        res.sendError(
            message +
                errors
                    .array()
                    .map((err) => err.msg)
                    .join(", "),
            422
        );

        return false; // validation failed
    }

    return true; // validation passed
};

exports.getAllLeases = async (req, res) => {
    try {
        const leases = await leaseService.getAllLeases();
        if (leases) {
            res.sendSuccess(leases, "Leases retrieved successfully");
        } else {
            res.sendError("Leases not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to retrieve leases: " + error.message, 500);
    }
};

exports.getSingleLease = async (req, res) => {
    try {
        const lease = await leaseService.getSingleLease(req.params.id);
        if (lease) {
            res.sendSuccess(lease, "Lease retrieved successfully");
        } else {
            res.sendError("Lease not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to retrieve lease: " + error.message, 500);
    }
};

exports.createLease = async (req, res) => {
    // Check if there are validation errors

    const isValid = handleValidationErrors(
        req,
        res,
        "Create lease validation failed: "
    );
    if (!isValid) {
        // validation failed
        return;
    }


    try {
        const newLease = await leaseService.createLease(req.body);
        res.sendSuccess(newLease, "Lease created successfully");
    } catch (error) {
        res.sendError("Failed to create lease: " + error.message, 500);
    }
};

exports.updateLease = async (req, res) => {
    // Check if there are validation errors
    const isvalid = handleValidationErrors(
        req,
        res,
        "Update lease validation failed: "
    );
    if (!isValid) {
        // validation failed
        return;
    }

    try {
        const updatedLease = await leaseService.updateLease(
            req.params.id,
            req.body
        );
        if (updatedLease) {
            res.sendSuccess(updatedLease, "Lease updated successfully");
        } else {
            res.sendError("Lease not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to update lease: " + error.message, 500);
    }
};

exports.deleteLease = async (req, res) => {
    try {
        const deleted = await leaseService.deleteLease(req.params.id);
        if (deleted) {
            res.sendSuccess(deleted, "Lease deleted successfully");
        } else {
            res.sendError("Lease not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to delete lease: " + error.message, 500);
    }
};

exports.getLeasesByLandlord = async (req, res) => {
    try {
        const userId = req.user.userId; // get the user ID from the token

        const leases = await leaseService.getLeasesByLandlord(userId);
        if (leases) {
            res.sendSuccess(
                leases,
                "Current landlord leases retrieved successfully"
            );
        } else {
            res.sendError("Current landlord leases error", 404);
        }
    } catch (error) {
        res.sendError(
            "Failed to current landlord leases: " + error.message,
            500
        );
    }
};

exports.getLeasesByTenant = async (req, res) => {
    try {
        const userId = req.user.userId; // get the user ID from the token

        const leases = await leaseService.getLeasesByTenant(userId);
        if (leases) {
            res.sendSuccess(
                leases,
                "Current tenant leases retrieved successfully"
            );
        } else {
            res.sendError("Current tenant leases error", 404);
        }
    } catch (error) {
        res.sendError("Failed to current tenant leases: " + error.message, 500);
    }
};
