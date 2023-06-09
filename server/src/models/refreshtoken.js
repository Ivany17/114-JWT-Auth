'use strict';
const { Model } = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class RefreshToken extends Model {
        static associate({User}) {
            RefreshToken.belongsTo(User, {
                foreignKey: 'userId'
            })
        }
    }
    RefreshToken.init({
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        value: {
            type: DataTypes.TEXT,
            allowNull: false
        },
        userAgent: {
            type: DataTypes.STRING,
        }
    }, {
        sequelize,
        modelName: 'RefreshToken',
    });
    return RefreshToken;
}