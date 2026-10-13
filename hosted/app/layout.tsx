import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Relay Trust — The Agent That Earns Trust",
  description: "An isolated trust laboratory with real signed evidence and revocable delegated authority.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
