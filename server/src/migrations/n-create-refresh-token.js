'use strict';
module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.createTable
        ('RefreshTokens', {
            id: {
                allowNull: false,
                autoIncrement: true,
                primaryKey: true,
                type: Sequelize.INTEGER
            },
            userId: {
                type: Sequelize.INTEGER,
                references: {
                    model: 'User',
                    key: 'id'
                }
            },
            value: {
                type: Sequelize.TEXT,
                allowNull: false,
            },
            userAgent: {
                type: Sequelize.STRING,
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE
            }
        });
    },
    async down(queryInterface, Sequelize) {
        await queryInterface.dropTable('RefreshTokens');
    }
};