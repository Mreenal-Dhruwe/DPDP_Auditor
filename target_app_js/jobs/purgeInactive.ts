// Nightly job: deletes accounts nobody has used for three years. Answer key: ../../ground_truth_js.yml
import { Op } from 'sequelize'
import { User } from '../models'
import { logger } from '../logger'

const THREE_YEARS_MS = 3 * 365 * 24 * 60 * 60 * 1000

export async function purgeInactiveUsers () {
  const cutoff = new Date(Date.now() - THREE_YEARS_MS)
  const removed = await User.destroy({ where: { lastLoginAt: { [Op.lt]: cutoff } } })
  logger.info(`purged ${removed} inactive accounts`)
}
