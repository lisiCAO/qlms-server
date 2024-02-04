const { lease } = require("../models");
const { sequelize, Sequelize } = require("../models/index");
const { property } = require("../models/index");

exports.getAllLeases = async () => {
    try {
        return await lease.findAll();
    } catch (error) {
        throw error;
    }
};

exports.getSingleLease = async (leaseId) => {
    try {
        return await lease.findByPk(leaseId);
    } catch (error) {
        throw error;
    }
};

exports.createLease = async (leaseData) => {
    try {
        return await lease.create(leaseData);
    } catch (error) {
        throw error;
    }
};

exports.updateLease = async (leaseId, leaseData) => {
    try {
        const leaseToUpdate = await lease.findByPk(leaseId);
        if (leaseToUpdate) {
            return await leaseToUpdate.update(leaseData);
        }
        return null;
    } catch (error) {
        throw error;
    }
};

exports.deleteLease = async (leaseId) => {
    try {
        const leaseToDelete = await lease.findByPk(leaseId);
        if (leaseToDelete) {
            await leaseToDelete.destroy();
            return true;
        }
        return false;
    } catch (error) {
        throw error;
    }
};

exports.getLeasesByLandlord = async (userId) => {
    try {
        // get all properties owned by the user
        let sql = `SELECT l.* FROM lease l JOIN property p ON l.property_id = p.id WHERE p.owner_user_id = ${userId} ORDER BY l.end_date;`;

        const leasesResult = await sequelize.query(sql, {
            type: Sequelize.QueryTypes.SELECT,
        });
        return leasesResult;
    } catch (error) {
        throw error;
    }
};

exports.getLeasesByTenant = async (userId) => {
    try {
        // get the lease of one tenant
        let sql = `SELECT l.* FROM lease l WHERE l.tenant_user_id = ${userId}`;

        const leasesResult = await sequelize.query(sql, {
            type: Sequelize.QueryTypes.SELECT,
        });
        return leasesResult;
    } catch (error) {
        throw error;
    }
};
