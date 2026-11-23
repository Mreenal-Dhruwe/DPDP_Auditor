const anonymiseIdleCustomers = async (Customer) => {
  const cutoff = Date.now() - 1095 * 864e5
  await Customer.update({ email: null, phone: null }, { where: { lastSeen: { lt: cutoff } } })
  return 'anonymised'
}

module.exports = { anonymiseIdleCustomers }
