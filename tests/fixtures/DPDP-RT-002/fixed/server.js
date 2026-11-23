const express = require('express')
const app = express()

app.post('/signup', (req, res) => res.status(201).end())
app.get('/profile', (req, res) => res.json({ email: req.user.email }))
app.post('/profile/password', (req, res) => res.end())
app.patch('/profile', (req, res) => res.end())
app.post('/account/erasure-request', (req, res) => res.status(202).end())
