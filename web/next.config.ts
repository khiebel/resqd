import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  // The app is static — all three routes are client components that
  // fetch the Lambda API at runtime. No server functions.
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
