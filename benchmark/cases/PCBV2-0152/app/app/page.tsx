export default function Home() {
  return (
    <main>
      <h1>Public home</h1>
      <p>The /admin page is protected by middleware.ts (auth cookie required).</p>
    </main>
  );
}
