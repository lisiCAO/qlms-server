// generateMockData.js
const { property, image } = require("../models"); // 更改为您的模型路径
const faker = require("faker");

const generateMockData = async () => {
    for (let i = 0; i < 2; i++) {
        const newProperty = await property.create({
            owner_user_id: 4, // owner_user_id = 4 role= "landlord"
            address: faker.address.streetAddress(),
            number_of_units: faker.datatype.number({ min: 1, max: 5 }),
            property_type: faker.random.arrayElement([
                "apartment",
                "house",
                "condo",
            ]),
            size_in_sq_ft: faker.datatype.number({ min: 500, max: 2000 }),
            year_built: faker.datatype.number({ min: 1900, max: 2020 }),
            rental_price: faker.commerce.price(500, 2000, 2),
            status: faker.random.arrayElement([
                "available",
                "rented",
                "under_maintenance",
            ]),
            lease_terms: faker.lorem.paragraph(),
        });

        // create mock images for each property
        for (let j = 0; j < 3; j++) {
            // 假设为每个 property 创建 3 张图片
            await image.create({
                property_id: newProperty.id,
                image_url: faker.image.imageUrl(),
                description: faker.lorem.sentence(),
                uploaded_at: new Date(),
                is_primary: j === 0, // 假设第一张图片为主图片
            });
        }
    }
};

generateMockData()
    .then(() => {
        console.log("Mock data generated successfully");
    })
    .catch((err) => {
        console.error("Failed to generate mock data:", err);
    });
