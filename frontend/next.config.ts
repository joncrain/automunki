import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',
  rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.BACKEND_URL || 'http://localhost:8000'}/api/:path*`,
      },
    ]
  },
}

export default nextConfig
