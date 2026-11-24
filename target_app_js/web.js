// Session and listener setup. Answer key: ../ground_truth_js.yml
const fs = require('fs')
const http = require('http')
const https = require('https')
const express = require('express')
const session = require('express-session')

const app = express()
const admin = express()

// No cookie options: the session cookie has no `secure` flag and also travels over plain HTTP.
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))

// Secure, script-proof cookie that expires.
admin.use(session({
  secret: process.env.ADMIN_SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, maxAge: 3600000 }
}))

// The https server exists, so this one can only redirect.
http.createServer((req, res) => { res.writeHead(301, { Location: 'https://shop.example' }); res.end() }).listen(8080)
https.createServer({ key: fs.readFileSync('tls.key'), cert: fs.readFileSync('tls.crt') }, admin).listen(8443)

module.exports = { app, admin }
