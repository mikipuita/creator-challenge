import type { Metadata } from "next";

import "@/app/globals.css";

export const metadata: Metadata = {
  title: "DomainVitals",
  description:
    "DomainVitals scans your business domain and translates attack surface findings into plain-English guidance."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="font-[family-name:var(--font-heading)] text-textPrimary antialiased">
        {children}
      </body>
    </html>
  );
}
