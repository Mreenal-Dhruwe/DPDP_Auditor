const express = require('express')
const winston = require('winston')
const { Member } = require('./models')

const logger = winston.createLogger({ transports: [new winston.transports.Console()] })
const app = express()

app.get('/members/:id', async (req, res) => {
  const member = await Member.findByPk(req.params.id)
  res.json({ name: member.name })
})

app.listen(3000, () => logger.info('up'))
