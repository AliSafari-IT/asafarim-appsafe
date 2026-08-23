import type { Metadata } from "next";
import "@asafarim/shared-tokens/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "AppSafe — private browser encryption",
  description:
    "Encrypt files, folders, and text locally in your browser with AppSafe.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
