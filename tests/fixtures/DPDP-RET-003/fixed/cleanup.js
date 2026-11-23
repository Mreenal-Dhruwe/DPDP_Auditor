const anonymiseIdleCustomers = async (Customer, notifyUser) => {
  const cutoff = Date.now() - 1095 * 864e5
  const idle = await Customer.findAll({ where: { lastSeen: { lt: cutoff }, noticeSentAt: { lt: Date.now() - 48 * 36e5 } } })
  await Customer.update({ email: null, phone: null }, { where: { id: idle.map(c => c.id) } })
  return 'anonymised'
}

module.exports = { anonymiseIdleCustomers }
