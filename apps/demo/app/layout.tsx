import type { Metadata } from "next";
import "@asafarim/shared-tokens/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "AppSafe package playground",
  description:
    "A live, browser-local example of the @asafarim/appsafe npm package.",
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
