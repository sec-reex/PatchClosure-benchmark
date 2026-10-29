export const metadata = {
  title: "PCB Next.js Middleware Bypass Case",
  description: "Benign benchmark app",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
