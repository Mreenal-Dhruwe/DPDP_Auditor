const { DataTypes, Model, Sequelize } = require('sequelize')
const bcrypt = require('bcrypt')
const config = require('./config')

const sequelize = new Sequelize({ dialect: 'sqlite', storage: config.dbStorage })

const User = sequelize.define('User', {
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  phone: DataTypes.STRING,
  pan: DataTypes.STRING,
  password: {
    type: DataTypes.STRING,
    set (value) {
      this.setDataValue('password', bcrypt.hashSync(value, 12))
    }
  }
}, { tableName: 'users' })

class Lead extends Model {}
Lead.init({
  name: DataTypes.STRING,
  email: DataTypes.STRING,
  mobile: DataTypes.STRING,
  source: DataTypes.STRING
}, { sequelize, tableName: 'leads' })

module.exports = { sequelize, User, Lead }
