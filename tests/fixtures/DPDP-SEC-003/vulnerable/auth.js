const crypto = require('crypto')
const md5 = require('md5')

const hash = (data) => crypto.createHash('md5').update(data).digest('hex')

function storeUser (user, password) {
  user.passwordHash = hash(password)
  user.legacy = crypto.createHash('sha1').update(password).digest('hex')
  user.old = md5(user.password)
}

module.exports = { hash, storeUser }
