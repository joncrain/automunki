import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',
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
