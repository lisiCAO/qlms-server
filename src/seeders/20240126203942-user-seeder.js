"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.bulkInsert(
            "user",
            [
                {
                    username: "Tom",
                    password_hash: "password123!",
                    email: "Tom@qlms.com",
                    role: "tenant",
                    is_verified: false,
                    created_at: new Date(),
                    updated_at: new Date(),
                },
                {
                    username: "Jerry",
                    password_hash: "password123!",
                    email: "Jerry@qlms.com",
                    role: "landlord",
                    is_verified: false,
                    created_at: new Date(),
                    updated_at: new Date(),
                },
            ],
            {}
        );
    },

    async down(queryInterface, Sequelize) {
        await queryInterface.bulkDelete("user", null, {});
    },
};
