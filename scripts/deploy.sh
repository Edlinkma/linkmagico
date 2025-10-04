#!/bin/bash
# LinkMágico Commercial Deployment Script

echo "🚀 LinkMágico Commercial Deployment"
echo "================================="

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found"
    echo "   Run 'npm run setup' first"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm ci --only=production

# Create necessary directories
mkdir -p data logs logs/consent logs/deletion

# Start the server
echo "🎯 Starting server..."
npm start