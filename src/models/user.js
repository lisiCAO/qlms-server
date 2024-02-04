const { Model, DataTypes } = require("sequelize");

class user extends Model {}

module.exports = (sequelize) => {
    user.init(
        {
            username: {
                type: DataTypes.STRING(50),
                allowNull: false,
            },
            password_hash: {
                type: DataTypes.STRING(550),
                allowNull: true,
            },
            email: {
                type: DataTypes.STRING(100),
                allowNull: false,
                unique: true,
            },
            role: {
                type: DataTypes.ENUM("tenant", "landlord"),
                allowNull: false,
            },
            first_name: {
                type: DataTypes.STRING(50),
                allowNull: true,
            },
            last_name: {
                type: DataTypes.STRING(50),
                allowNull: true,
            },
            street_number: {
                type: DataTypes.STRING(10),
                allowNull: true,
            },
            street_name: {
                type: DataTypes.STRING(200),
                allowNull: true,
            },
            city_name: {
                type: DataTypes.STRING(50),
                allowNull: true,
            },
            postcode: {
                type: DataTypes.STRING(10),
                allowNull: true,
            },
            province: {
                type: DataTypes.STRING(20),
                allowNull: true,
            },
            phone_number: {
                type: DataTypes.STRING(15),
                allowNull: true,
            },
            profile_picture_url: {
                type: DataTypes.STRING(500),
                allowNull: true,
            },
            date_of_birth: {
                type: DataTypes.DATEONLY,
                allowNull: true,
            },
            emerge_contact_name: {
                type: DataTypes.STRING(100),
                allowNull: true,
            },
            emerge_contact_number: {
                type: DataTypes.STRING(15),
                allowNull: true,
            },
            national_id: {
                type: DataTypes.STRING(20),
                allowNull: true,
            },
            employer_info: {
                type: DataTypes.STRING(100),
                allowNull: true,
            },
            bank_info: {
                type: DataTypes.STRING(100),
                allowNull: true,
            },
            reference_url: {
                type: DataTypes.STRING(100),
                allowNull: true,
            },
            is_verified: {
                type: DataTypes.BOOLEAN,
                allowNull: false,
                defaultValue: false,
            },
            oauth_provider: {
                type: DataTypes.STRING(50),
                allowNull: true,
            },
            oauth_provider_user_id: {
                type: DataTypes.STRING(100),
                allowNull: true,
            },
        },
        {
            sequelize,
            modelName: "user",
            tableName: "user",
            timestamps: true, // Sequelize manages createdAt and updatedAt automatically
            underscored: true, // use snake_case instead of camelCase
        }
    );
    return user;
};

//add associations with property model
user.associate = function (models) {
    user.hasMany(models.property, {
        foreignKey: "owner_user_id",
    });
};

user.associate = function (models) {
    user.hasMany(models.oauth_token, {
        foreignKey: "user_id",
    });
};

user.associate = function (models) {
    user.hasMany(models.lease, {
        foreignKey: "tenant_user_id",
    });
};
