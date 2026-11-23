// Handlers wired in ../server.ts (like Juice Shop's routes/ folder). Answer key: ../../ground_truth_js.yml
import { Request, Response } from 'express'
import { User } from '../models'

export function getCustomer () {
  return async (req: Request, res: Response) => {
    const customer = await User.findByPk(req.params.id)
    res.json({ email: customer?.email, phone: customer?.phone })
  }
}

export const listCustomers = () => async (req: Request, res: Response) => {
  res.json(await User.findAll())
}
