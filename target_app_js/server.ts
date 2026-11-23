// Demo target for the DPDP Compliance Auditor (Express + Sequelize, TypeScript).
// Deliberately insecure: never deploy it. Answer key: ../ground_truth_js.yml
import express, { NextFunction, Request, Response } from 'express'
import { Lead, User } from './models'
import { logger } from './logger'

const app = express()
app.use(express.json())

function requireAuth (req: Request, res: Response, next: NextFunction) {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'login required' })
  }
  next()
}

app.use('/admin', requireAuth)

app.post('/signup', async (req: Request, res: Response) => {
  const user = await User.create(req.body)
  console.log('New signup', req.body.email, req.body.phone)
  logger.info(`user ${user.id} created`)
  res.status(201).json({ id: user.id })
})

app.post('/leads', async (req: Request, res: Response) => {
  await Lead.create(req.body)
  res.status(201).end()
})

app.get('/api/users/:id', async (req: Request, res: Response) => {
  const user = await User.findByPk(req.params.id)
  res.json(user)
})

app.get('/api/leads/:id', requireAuth, async (req: Request, res: Response) => {
  const lead = await Lead.findByPk(req.params.id)
  res.json({ name: lead?.name, source: lead?.source })
})

app.get('/admin/users', async (req: Request, res: Response) => {
  res.json(await User.findAll())
})

app.post('/consent', requireAuth, (req: Request, res: Response) => {
  res.json({ ok: true, purpose: req.body.purpose })
})

app.delete('/api/me', requireAuth, async (req: Request, res: Response) => {
  await User.destroy({ where: { id: String(req.headers['x-user-id']) } })
  res.status(204).end()
})

// Handlers defined in routes/customers.ts, wired here
const { getCustomer } = require('./routes/customers')
const customers = require('./routes/customers')
const asyncHandler = (fn: any) => fn

app.get('/api/customers/:id', asyncHandler(getCustomer()))
app.get('/admin/customers', customers.listCustomers())

// Marketing handlers in routes/marketing.ts
const marketing = require('./routes/marketing')
app.post('/admin/users/:id/offers', marketing.sendOffers())
app.post('/admin/users/:id/newsletter', marketing.sendNewsletter())

app.listen(3000, () => logger.info('listening on 3000'))
