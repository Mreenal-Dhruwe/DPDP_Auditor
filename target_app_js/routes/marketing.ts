// Marketing handlers wired in ../server.ts. Answer key: ../../ground_truth_js.yml
import { Request, Response } from 'express'
import { Consent, User } from '../models'
import { mailer } from '../mailer'
import { logger } from '../logger'

// Sends offers to anyone, whether or not they agreed to marketing.
export const sendOffers = () => async (req: Request, res: Response) => {
  const user = await User.findByPk(req.params.id)
  logger.info(`offers sent to user ${user?.id}`)
  mailer.sendPromo(user?.email, 'Festive offers for you')
  res.status(202).end()
}

// Checks the user's marketing consent first.
export const sendNewsletter = () => async (req: Request, res: Response) => {
  const user = await User.findByPk(req.params.id)
  const consent = await Consent.findOne({ where: { userId: user?.id, marketing: true } })
  if (!consent) {
    return res.status(409).json({ error: 'no marketing consent' })
  }
  logger.info(`newsletter sent to user ${user?.id}`)
  mailer.sendNewsletter(user?.email)
  res.status(202).end()
}
