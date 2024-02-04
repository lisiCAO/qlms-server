"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
    async up(queryInterface, Sequelize) {
        /**
         * Add seed commands here.
         *
         * Example:
         * await queryInterface.bulkInsert('People', [{
         *   name: 'John Doe',
         *   isBetaMember: false
         * }], {});
         */
        await queryInterface.bulkInsert(
            "property",
            [
                {
                    owner_user_id: 4, //mock id
                    address: "123 Main St",
                    number_of_units: 2,
                    property_type: "apartment",
                    size_in_sq_ft: 1200,
                    year_built: 1990,
                    rental_price: 1500.0,
                    amenities: "Pool, Gym, Wi-Fi",
                    status: "available",
                    lease_terms: "12 months lease, no pets",
                    photos_url: "https://example.com/properties/1/photos",
                    description: "Spacious two-bedroom apartment...",
                    created_at: new Date(),
                    updated_at: new Date(),
                },
                {
                    owner_user_id: 4, // mock id
                    address: "456 Elm St",
                    number_of_units: 2,
                    property_type: "house",
                    size_in_sq_ft: 1500,
                    year_built: 2005,
                    rental_price: 2500.0,
                    amenities: "Garage, Garden",
                    status: "rented",
                    lease_terms: "6 months lease",
                    photos_url: "https://example.com/properties/2/photos",
                    description: "Cozy house with a beautiful garden...",
                    created_at: new Date(),
                    updated_at: new Date(),
                },
                {
                    owner_user_id: 4, // mock owner_user_id
                    address: "789 Oak St",
                    number_of_units: 3,
                    property_type: "condo",
                    size_in_sq_ft: 1000,
                    year_built: 2010,
                    rental_price: 1800.0,
                    amenities: "Balcony, Parking, Washer/Dryer",
                    status: "available",
                    lease_terms: "1 year lease",
                    photos_url: "https://example.com/properties/3/photos",
                    description: "Modern condo with updated appliances...",
                    created_at: new Date(),
                    updated_at: new Date(),
                },
            ],
            {}
        );
    },

    async down(queryInterface, Sequelize) {
        /**
         * Add commands to revert seed here.
         *
         * Example:
         * await queryInterface.bulkDelete('People', null, {});
         */
        await queryInterface.bulkDelete("property", null, {});
    },
};
