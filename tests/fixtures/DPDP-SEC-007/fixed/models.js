const { DataTypes, Sequelize } = require('sequelize')
const sequelize = new Sequelize('sqlite::memory:')
const Member = sequelize.define('Member', { name: DataTypes.STRING, phone: DataTypes.STRING })
module.exports = { Member }
