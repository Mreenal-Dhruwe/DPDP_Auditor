export function KycForm () {
  return (
    <form onSubmit={submit}>
      <input name="aadhaar" />
      <input type="email" name="email" />
    </form>
  )
}
