import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',
  allowedDevOrigins: ['*.ngrok-free.app', '*.ngrok.io'],
  experimental: {
    browserDebugInfoInTerminal: true,
  },
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'statici.icloud.com',
        pathname: '/fmipmobile/**',
      },
      {
        protocol: 'https',
        hostname: 'km.support.apple.com',
        pathname: '/kb/**',
      },
    ],
  },
  rewrites() {
    const backend = process.env.BACKEND_URL || 'http://localhost:8000'
    return [
      {
        source: '/api/:path*',
        destination: `${backend}/api/:path*`,
      },
      {
        source: '/repo/:path*',
        destination: `${backend}/repo/:path*`,
      },
      // After `public/icons/*` misses, serve uploaded PNGs from the API (same path as upload target).
      {
        source: '/icons/:path*',
        destination: `${backend}/api/v1/icons/:path*`,
      },
    ]
  },
}

export default nextConfig
