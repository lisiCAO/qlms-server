const { Model, DataTypes } = require("sequelize");

class image extends Model {}

module.exports = (sequelize) => {
    image.init(
        {
            id: {
                type: DataTypes.INTEGER,
                primaryKey: true,
                autoIncrement: true,
                allowNull: false,
            },
            property_id: {
                type: DataTypes.INTEGER,
                allowNull: false,
                references: {
                    model: "property",
                    key: "id",
                },
            },
            image_url: {
                type: DataTypes.STRING(255),
                allowNull: false,
            },
            description: {
                type: DataTypes.STRING(255),
                allowNull: true,
            },
            uploaded_at: {
                type: DataTypes.DATE,
                allowNull: false,
                defaultValue: DataTypes.NOW,
            },
            is_primary: {
                type: DataTypes.BOOLEAN,
                allowNull: false,
                defaultValue: false,
            },
        },
        {
            sequelize,
            modelName: "image",
            tableName: "image",
            timestamps: false,
            underscored: true,
        }
    );

    return image;
};

image.associate = (models) => {
    image.belongsTo(models.property, {
        foreignKey: "property_id",
        onDelete: "CASCADE",
    });
};
