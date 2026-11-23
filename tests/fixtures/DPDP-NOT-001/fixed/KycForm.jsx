export function KycForm () {
  return (
    <form onSubmit={submit}>
      <p>We use your Aadhaar number only to verify your identity (purpose: KYC).</p>
      <input name="aadhaar" />
      <input type="email" name="email" />
    </form>
  )
}
