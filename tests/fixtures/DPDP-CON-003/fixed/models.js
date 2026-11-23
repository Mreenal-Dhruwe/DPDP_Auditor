const { DataTypes, Sequelize } = require('sequelize')

const sequelize = new Sequelize('sqlite::memory:')

// Sequelize adds createdAt / updatedAt: the time each choice was recorded
const CookieConsent = sequelize.define('CookieConsent', {
  visitorId: DataTypes.STRING,
  analytics: DataTypes.BOOLEAN,
  noticeVersion: DataTypes.STRING
})

module.exports = { CookieConsent }
