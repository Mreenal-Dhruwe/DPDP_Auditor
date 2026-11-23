const winston = require('winston')
const DailyRotateFile = require('winston-daily-rotate-file')

module.exports = winston.createLogger({
  transports: [new DailyRotateFile({ filename: 'app-%DATE%.log', maxFiles: 14 })]
})
