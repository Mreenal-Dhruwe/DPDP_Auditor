// Email helper for the demo target. Answer key: ../ground_truth_js.yml
type Mail = { to: string | undefined, subject: string }

const outbox: Mail[] = []

export const mailer = {
  sendPromo (to: string | undefined, subject: string) { outbox.push({ to, subject }) },
  sendNewsletter (to: string | undefined) { outbox.push({ to, subject: 'Our monthly newsletter' }) }
}
