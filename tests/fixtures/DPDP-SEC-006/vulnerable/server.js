const express = require('express')
const { DataTypes, Sequelize } = require('sequelize')

const sequelize = new Sequelize('sqlite::memory:')
const Member = sequelize.define('Member', {
  name: DataTypes.STRING,
  aadhaar: DataTypes.STRING
})

const app = express()

app.get('/members/:id', async (req, res) => {
  const member = await Member.findByPk(req.params.id)
  res.json({ member })
})

app.get('/members', (req, res) => {
  Member.findAll().then(members => res.json(members))
})
