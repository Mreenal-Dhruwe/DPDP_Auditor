// Club members, stored with the raw MongoDB driver (no ORM). Answer key: ../../ground_truth_js.yml
const express = require('express')
const bcrypt = require('bcrypt')
const { db } = require('../mongo')
const { logger } = require('../logger')

const router = express.Router()
const members = db.collection('members')

function requireAuth (req, res, next) {
  if (!req.headers.authorization) return res.status(401).json({ error: 'login required' })
  next()
}

// The passport number is stored as typed; the password is hashed before it is saved.
router.post('/members', requireAuth, async (req, res) => {
  const { name, passport, password } = req.body
  await members.insertOne({ name, passport, password: bcrypt.hashSync(password, 12) })
  res.status(201).end()
})

router.delete('/members/:id', requireAuth, async (req, res) => {
  await members.deleteOne({ id: req.params.id })
  res.status(204).end()
})

// Sends the whole member record, passport number and password hash included.
router.get('/members/:id', requireAuth, (req, res) => {
  logger.info(`member ${req.params.id} read`)
  members.findOne({ id: req.params.id }, (err, member) => res.json(member))
})

// Picks the fields it needs with a projection.
router.get('/members/:id/card', requireAuth, (req, res) => {
  logger.info(`member card ${req.params.id} read`)
  members.findOne({ id: req.params.id }, { projection: { name: 1 } }, (err, member) => res.json(member))
})

module.exports = router
