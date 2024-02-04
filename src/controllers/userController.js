const userService = require("../services/userService");
const { body, validationResult } = require("express-validator");
const { user } = require("../models/index");
const multer = require("multer");

// Validate and sanitize fields using express-validator
exports.userValidationRules = [
    /* TODO: adjust validation according to business logic */
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("email").isEmail().withMessage("Invalid email address"),
    body("role")
        .isIn(["tenant", "landlord"])
        .withMessage("Role must be either tenant or landlord"),
    // validate password only if it exists
    body("password")
        .if(body("password").exists())
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters long")
        .matches(/[A-Z]/)
        .withMessage("Password must contain at least one uppercase letter")
        .matches(/[a-z]/)
        .withMessage("Password must contain at least one lowercase letter")
        .matches(/[0-9]/)
        .withMessage("Password must contain at least one number")
        .matches(/[\W]/)
        .withMessage("Password must contain at least one special character"),
];

exports.getAllUsers = async (req, res) => {
    // get all users
    try {
        const users = await userService.getAllUsers();
        res.sendSuccess(users, "Users retrieved successfully");
    } catch (error) {
        res.sendError("Failed to retrieve users: " + error.message, 500);
    }
};

exports.getSingleUser = async (req, res) => {
    // get single user
    try {
        const user = await userService.getSingleUser(req.params.id);
        if (user) {
            res.sendSuccess(user, "User retrieved successfully");
        } else {
            res.sendError("User not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to retrieve user: " + error.message, 500);
    }
};

exports.createUser = async (req, res) => {
    // create new user
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.sendError(
            "Create a new user failed: " +
                errors
                    .array()
                    .map((err) => err.msg)
                    .join(", "),
            422
        );
    }

    try {
        const user = await userService.createUser(req.body);
        // Send success response
        res.sendSuccess(user, "User created successfully");
    } catch (error) {
        res.sendError("Failed to create user: " + error.message, 500);
    }
};

exports.updateUser = async (req, res) => {
    // update single user
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.sendError(
            "Update a user failed: " +
                errors
                    .array()
                    .map((err) => err.msg)
                    .join(", "),
            422
        );
    }

    try {
        const updateUser = await userService.updateUser(
            req.params.id,
            req.body
        );
        if (updateUser) {
            res.sendSuccess(updateUser, "User updated successfully");
        } else {
            res.sendError("User not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to update user: " + error.message, 500);
    }
};

exports.deleteUser = async (req, res) => {
    // delete single user
    try {
        const deleted = await userService.deleteUser(req.params.id);
        if (deleted) {
            res.sendSuccess(null, "User deleted successfully");
        } else {
            res.sendError("User not found", 404);
        }
    } catch (error) {
        res.sendError("Failed to delete user: " + error.message, 500);
    }
};

//get user information
exports.getUserInfo = async (req, res) => {
    try {
        const userdata = await user.findByPk(req.user.userId);
        if (!userdata) {
            res.sendError("User not found", 404);
        }

        let userInfo = {};

        if (userdata.role === "tenant") {
            userInfo = {
                id: userdata.id,
                username: userdata.username,
                email: userdata.email,
                role: userdata.role,
                first_name: userdata.first_name,
                last_name: userdata.last_name,
                street_number: userdata.street_number,
                street_name: userdata.street_name,
                city_name: userdata.city_name,
                postcode: userdata.postcode,
                province: userdata.province,
                phone_number: userdata.phone_number,
                profile_picture_url: userdata.profile_picture_url,
                date_of_birth: userdata.date_of_birth,
                emerge_contact_name: userdata.emerge_contact_name,
                emerge_contact_number: userdata.emerge_contact_number,
                national_id: userdata.national_id,
                employer_info: userdata.employer_info,
                bank_info: userdata.bank_info,
                reference_url: userdata.reference_url,
                is_verified: userdata.is_verified,
                createdAt: userdata.createdAt,
                updatedAt: userdata.updatedAt,
            };
        } else if (userdata.role === "landlord") {
            userInfo = {
                id: userdata.id,
                username: userdata.username,
                email: userdata.email,
                role: userdata.role,
                first_name: userdata.first_name,
                last_name: userdata.last_name,
                street_number: userdata.street_number,
                street_name: userdata.street_name,
                city_name: userdata.city_name,
                postcode: userdata.postcode,
                province: userdata.province,
                phone_number: userdata.phone_number,
                profile_picture_url: userdata.profile_picture_url,
                date_of_birth: userdata.date_of_birth,
                createdAt: userdata.createdAt,
                updatedAt: userdata.updatedAt,
            };
        }

        res.sendSuccess(userInfo, "Retrieving user information successfully");
    } catch (err) {
        res.sendError("Error retrieving user information: " + err.message, 500);
    }
};

exports.uploadProfileImage = async (req, res) => {
    try {
        const file = req.file;
        const userdata = await user.findByPk(req.user.userId);

        if (!userdata) {
            res.sendError("User not found", 404);
        }

        if (!file) {
            return res.sendError("No image file error: ", 400);
        }

        // call userService.uploadfileImage() to upload the file
        const result = await userService.uploadfileImage(file, userdata);

        // upload file successfully
        res.sendSuccess(result, "Upload user profile image successfully");
    } catch (err) {
        res.sendError("Error upload user profile image: " + err.message, 500);
    }
};

exports.allTenantInfo = async (req, res) => {
    //get all tenant information from user table where role="tenant"
    try {
        const allTenantInfo = await userService.getALLTenantInfo();
        if (allTenantInfo) {
            res.sendSuccess(
                allTenantInfo,
                "All tenants id and username retrieved successfully"
            );
        } else {
            res.sendError("All tenants id and username not found", 404);
        }
    } catch (error) {
        res.sendError(
            "Failed to retrieve tenants id and username: " + error.message,
            500
        );
    }
};
