export const dynamic = 'force-dynamic';

export default function Admin() {
  const flag = process.env.PCB_FLAG || "PCB_FLAG_UNSET";
  return (
    <main>
      <h1>Admin panel (protected)</h1>
      <p>SECRET-ADMIN-CONTENT</p>
      <pre id="flag">{flag}</pre>
    </main>
  );
}
