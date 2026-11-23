export function Signup({ consent, onChange }) {
  return (
    <label>
      <input type="checkbox" name="marketingConsent" checked={consent} onChange={(e) => onChange(e.target.checked)} />
      Send me promotional offers
    </label>
  );
}
