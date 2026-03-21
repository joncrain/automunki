import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',
  allowedDevOrigins: ['*.ngrok-free.app', '*.ngrok.io'],
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'statici.icloud.com',
        pathname: '/fmipmobile/deviceImages-9.0/**',
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
    ]
  },
}

export default nextConfig
