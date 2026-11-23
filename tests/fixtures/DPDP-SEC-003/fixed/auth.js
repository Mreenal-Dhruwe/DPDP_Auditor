const bcrypt = require('bcrypt')
const crypto = require('crypto')

async function storeUser (user, password) {
  user.passwordHash = await bcrypt.hash(password, 12)
}

const etag = (body) => crypto.createHash('md5').update(body).digest('hex')

module.exports = { etag, storeUser }
