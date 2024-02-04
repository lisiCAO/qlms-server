const { Model, DataTypes } = require("sequelize");

class lease extends Model {}

module.exports = (sequelize) => {
    lease.init(
        {
            property_id: {
                type: DataTypes.INTEGER,
                allowNull: false,
                references: {
                    model: "property",
                    key: "id",
                },
            },
            tenant_user_id: {
                type: DataTypes.INTEGER,
                allowNull: false,
                references: {
                    model: "user",
                    key: "id",
                },
            },
            start_date: {
                type: DataTypes.DATE,
                allowNull: false,
            },
            end_date: {
                type: DataTypes.DATE,
                allowNull: false,
            },
            rent_amount: {
                type: DataTypes.DECIMAL(10, 2),
                allowNull: false,
            },
            lease_clauses: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            payment_due_day: {
                type: DataTypes.INTEGER,
                allowNull: false,
            },
            utility_by_owner: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            utility_by_tenant: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            renewal_term: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
            early_terminate_con: {
                type: DataTypes.TEXT,
                allowNull: true,
            },
        },
        {
            sequelize,
            modelName: "lease",
            tableName: "lease",
            timestamps: true, // Sequelize manages createdAt and updatedAt automatically
            underscored: true, // use snake_case instead of camelCase
        }
    );

    return lease;
};

lease.associate = function (models) {
    lease.belongsTo(models.user, {
        foreignKey: "tenant_user_id",
    });
};

lease.associate = function (models) {
    lease.belongsTo(models.property, {
        foreignKey: "property_id",
    });
};
