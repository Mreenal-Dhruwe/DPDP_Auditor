import winston from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'

export const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console(),
    // one file per day, deleted after two weeks
    new DailyRotateFile({ filename: 'logs/app-%DATE%.log', datePattern: 'YYYY-MM-DD', maxFiles: '14d' })
  ]
})
