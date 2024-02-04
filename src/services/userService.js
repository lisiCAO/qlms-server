// services/userService.js
const { user } = require("../models"); // import user mddel
const { sequelize } = require("../models/index");
const bcrypt = require("bcryptjs");
const { containerClient } = require("./userImageService");

exports.getAllUsers = async () => {
    const userInstances = await user.findAll();
    const results = userInstances.map((instance) => {
        const user = instance.get({ plain: true });

        delete user.password_hash;

        return user;
    });

    return results;
};

exports.getSingleUser = async (userId) => {
    const userData = await user.findByPk(userId);
    if (userData) {
        const result = userData.get({ plain: true });

        //delete sensitive data
        delete result.password_hash;
        return result;
    }
};

exports.createUser = async (userData) => {
    try {
        // hash password
        if (userData.password) {
            userData.password_hash = await bcrypt.hash(userData.password, 10);
            delete userData.password;
        }

        const newUser = await user.create(userData);

        return newUser;
    } catch (error) {
        throw error;
    }
};

exports.updateUser = async (userId, userData) => {
    const userToUpdate = await user.findByPk(userId);

    if (!userToUpdate) {
        return null; // user not found
    }

    // if password is being updated, hash the new password
    if (userData.password) {
        userData.password_hash = await bcrypt.hash(userData.password, 10);
        delete userData.password; // remove originalpassword from userData object
    }

    // update user
    await userToUpdate.update(userData);
    return userToUpdate;
};

exports.deleteUser = async (userId) => {
    const userToDelete = await user.findByPk(userId);

    if (!userToDelete) {
        return false; //user not found
    }

    await userToDelete.destroy();
    return true;
};

exports.uploadfileImage = async (file, userdata) => {
    const blobName = `user_image/${Date.now()}_${file.originalname}`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);

    await blockBlobClient.uploadData(file.buffer, {
        blobHTTPHeaders: { blobContentType: file.mimetype },
    });

    // file upolad successfully,
    const fileUrl = blockBlobClient.url;
    const updatedUser = await user.update(
        { profile_picture_url: fileUrl },
        { where: { id: userdata.id } }
    );

    return { fileUrl };
};

exports.getALLTenantInfo = async () => {
    const allTenantInfo = await user.findAll({
        where: { role: "tenant" },
        attributes: ["id", "username"],
    });

    if (allTenantInfo) {
        return allTenantInfo;
    }
};
