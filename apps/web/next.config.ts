import type { NextConfig } from "next";

const apiUrl = (process.env.API_URL ?? "http://localhost:4000").replace(/\/$/, "");

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@asafarim/appsafe"],
  async rewrites() {
    return [
      {
        source: "/api/gate/:path*",
        destination: `${apiUrl}/api/gate/:path*`,
      },
    ];
  },
};

export default nextConfig;
