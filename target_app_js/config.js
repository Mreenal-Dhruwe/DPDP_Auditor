// Demo target for the DPDP Compliance Auditor. Answer key: ../ground_truth_js.yml
module.exports = {
  port: 3000,
  jwtSecret: 'shop-demo-91b7e3c04d2a46f8a1c5e9d7b3f20c68',
  dbPassword: process.env.DB_PASSWORD,
  dbStorage: process.env.DB_STORAGE || 'shop.sqlite'
}
