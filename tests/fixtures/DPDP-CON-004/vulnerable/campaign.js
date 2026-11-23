const transporter = require('./mail')

async function weeklyCampaign (user) {
  await transporter.sendMail({ to: user.email, subject: 'This week only' })
}

module.exports = { weeklyCampaign }
