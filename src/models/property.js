const { Model, DataTypes } = require("sequelize");

class property extends Model {}

module.exports = (sequelize) => {
    property.init(
        {
            owner_user_id: {
                type: DataTypes.INTEGER,
                allowNull: false,
                references: {
                    model: "user", // reference user model
                    key: "id", // id of user model
                },
            },
            address: {
                type: DataTypes.STRING(255),
                allowNull: false,
            },
            number_of_units: {
                type: DataTypes.INTEGER,
                allowNull: false,
                defaultValue: 1,
            },
            property_type: {
                type: DataTypes.ENUM("apartment", "house", "condo"),
                allowNull: false,
                defaultValue: "condo",
            },
            size_in_sq_ft: {
                type: DataTypes.INTEGER,
                allowNull: false,
                defaultValue: 500,
            },
            year_built: {
                type: DataTypes.INTEGER,
                allowNull: true,
            },
            rental_price: {
                type: DataTypes.DECIMAL(10, 2),
                allowNull: false,
                defaultValue: 1000.0,
            },
            amenities: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            status: {
                type: DataTypes.ENUM(
                    "available",
                    "rented",
                    "under_maintenance"
                ),
                allowNull: false,
                defaultValue: "available",
            },
            lease_terms: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            photos_url: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            description: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
        },
        {
            sequelize,
            modelName: "property",
            tableName: "property",
            timestamps: true, // Sequelize manages createdAt and updatedAt automatically
            underscored: true, // use snake_case instead of camelCase
        }
    );

    return property;
};

property.associate = function (models) {
    property.belongsTo(models.user, {
        foreignKey: "owner_user_id",
    });
};

property.associate = function (models) {
    property.hasMany(models.image, {
        foreignKey: "property_id",
        onDelete: "CASCADE",
    });
};

property.associate = function (models) {
    property.hasMany(models.lease, {
        foreignKey: "property_id",
    });
};
