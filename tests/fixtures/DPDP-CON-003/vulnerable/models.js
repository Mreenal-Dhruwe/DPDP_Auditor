const { DataTypes, Sequelize } = require('sequelize')

const sequelize = new Sequelize('sqlite::memory:')

const CookieConsent = sequelize.define('CookieConsent', {
  visitorId: DataTypes.STRING,
  analytics: DataTypes.BOOLEAN
}, { timestamps: false })

module.exports = { CookieConsent }
