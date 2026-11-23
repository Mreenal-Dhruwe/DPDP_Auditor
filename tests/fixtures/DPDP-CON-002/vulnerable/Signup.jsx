export function Signup({ onChange }) {
  return (
    <label>
      <input type="checkbox" name="marketingConsent" defaultChecked onChange={(e) => onChange(e.target.checked)} />
      Send me promotional offers
    </label>
  );
}
