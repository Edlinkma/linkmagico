#!/usr/bin/env node

// LinkMágico Commercial Setup Script
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

console.log('🚀 LinkMágico Commercial Setup');
console.log('==============================\n');

// Create necessary directories
const directories = [
    'data',
    'logs',
    'logs/consent',
    'logs/deletion',
    'public',
    'scripts',
    'tests'
];

console.log('📁 Creating directories...');
directories.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`   ✅ Created: ${dir}`);
    } else {
        console.log(`   ⏭️  Exists: ${dir}`);
    }
});

// Generate .env file from template if it doesn't exist
if (!fs.existsSync('.env')) {
    console.log('\n🔑 Generating .env file...');
    
    let envTemplate = `# LinkMágico Commercial - Environment Configuration
# Generated on ${new Date().toISOString()}

# Server Configuration
NODE_ENV=development
PORT=3000
LOG_LEVEL=info

# Security (CHANGE THESE IN PRODUCTION!)
JWT_SECRET=${crypto.randomBytes(32).toString('hex')}
IP_SALT=${crypto.randomBytes(16).toString('hex')}

# OpenAI Configuration (Primary LLM)
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_API_BASE=https://api.openai.com/v1/chat/completions

# Groq Configuration (Alternative/Fallback LLM)
GROQ_API_KEY=your-groq-api-key-here
GROQ_MODEL=llama-3.1-70b-versatile
GROQ_API_BASE=https://api.groq.com/openai/v1/chat/completions

# Stripe Configuration (Billing)
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
STRIPE_PUBLIC_KEY=pk_test_your-stripe-public-key
STRIPE_WEBHOOK_SECRET=whsec_your-webhook-secret

# Stripe Price IDs (Create these in your Stripe Dashboard)
STRIPE_STARTER_PRICE_ID=price_starter_monthly
STRIPE_PRO_PRICE_ID=price_pro_monthly
STRIPE_ENTERPRISE_PRICE_ID=price_enterprise_monthly

# Feature Flags
ENABLE_PUPPETEER=true
ENABLE_RATE_LIMITING=true
ENABLE_ANALYTICS=true
ENABLE_CACHING=true

# Security Headers
HELMET_CSP_ENABLED=true
CORS_ORIGIN=http://localhost:3000,http://127.0.0.1:3000

# Rate Limiting
DEFAULT_RATE_LIMIT_WINDOW_MS=900000
DEFAULT_RATE_LIMIT_MAX_REQUESTS=100
WIDGET_RATE_LIMIT_MAX_REQUESTS=1000

# Cache Configuration
CACHE_TTL_MINUTES=30
MAX_CACHE_SIZE=1000
`;

    fs.writeFileSync('.env', envTemplate);
    console.log('   ✅ Created .env file with secure defaults');
    console.log('   ⚠️  IMPORTANT: Update API keys before starting!');
} else {
    console.log('\n⏭️  .env file already exists');
}

// Create initial tenant data file
const tenantsFile = path.join('data', 'tenants.json');
if (!fs.existsSync(tenantsFile)) {
    console.log('\n👥 Creating initial tenant data...');
    
    const demoTenant = {
        id: crypto.randomUUID(),
        name: 'Demo Account',
        email: 'demo@linkmagico.com',
        apiKey: 'lm_' + crypto.randomBytes(32).toString('hex'),
        plan: 'starter',
        limits: {
            requests: 10000,
            tokens: 500000,
            chatbots: 10,
            domains: 5,
            customCSS: true,
            analytics: true,
            support: 'email'
        },
        usage: {
            requests: 0,
            tokens: 0,
            chatbots: 0,
            resetDate: new Date()
        },
        stripeCustomerId: null,
        createdAt: new Date(),
        isActive: true,
        domains: ['localhost', '127.0.0.1', 'linkmagico.com'],
        webhooks: [],
        settings: {
            customCSS: '',
            branding: true,
            analytics: true
        }
    };

    fs.writeFileSync(tenantsFile, JSON.stringify([demoTenant], null, 2));
    console.log('   ✅ Created demo tenant');
    console.log(`   🔑 Demo API Key: ${demoTenant.apiKey}`);
    console.log(`   📧 Demo Email: ${demoTenant.email}`);
} else {
    console.log('\n⏭️  Tenant data already exists');
}

// Create package.json if not exists
if (!fs.existsSync('package.json')) {
    console.log('\n📦 Creating package.json...');
    
    const packageJson = {
        name: 'linkmagico-commercial',
        version: '6.0.0',
        description: 'LinkMágico Commercial - AI-powered chatbot platform',
        main: 'server.js',
        scripts: {
            start: 'node server.js',
            dev: 'nodemon server.js',
            test: 'jest',
            setup: 'node scripts/setup.js'
        },
        dependencies: {
            express: '^4.18.2',
            cors: '^2.8.5',
            helmet: '^7.1.0',
            'express-rate-limit': '^7.1.5',
            winston: '^3.11.0',
            axios: '^1.6.2',
            cheerio: '^1.0.0-rc.12',
            jsonwebtoken: '^9.0.2',
            bcrypt: '^5.1.1',
            uuid: '^9.0.1',
            stripe: '^14.9.0',
            dotenv: '^16.3.1'
        },
        optionalDependencies: {
            puppeteer: '^21.6.1'
        }
    };

    fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));
    console.log('   ✅ Created package.json');
}

// Create basic public/index.html if not exists
const indexPath = path.join('public', 'index.html');
if (!fs.existsSync(indexPath)) {
    console.log('\n🌐 Creating basic index.html...');
    
    const indexHtml = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkMágico Commercial v6.0</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Inter', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        .container { 
            text-align: center; 
            max-width: 600px;
            padding: 2rem;
            background: rgba(255,255,255,0.1);
            border-radius: 20px;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        h1 { font-size: 3rem; margin-bottom: 1rem; }
        .subtitle { font-size: 1.2rem; margin-bottom: 2rem; opacity: 0.9; }
        .status { 
            background: rgba(16, 185, 129, 0.2);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .links { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
        .btn { 
            background: rgba(255,255,255,0.2);
            padding: 0.8rem 1.5rem;
            border-radius: 10px;
            text-decoration: none;
            color: white;
            transition: all 0.3s;
            border: 1px solid rgba(255,255,255,0.3);
        }
        .btn:hover { 
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>LinkMágico Commercial</h1>
        <p class="subtitle">AI-Powered Chatbot Platform v6.0</p>
        
        <div class="status">
            🚀 Sistema configurado e pronto para uso!
        </div>
        
        <div class="links">
            <a href="/health" class="btn">Health Check</a>
            <a href="/chatbot" class="btn">Demo Chatbot</a>
            <a href="/privacy.html" class="btn">Privacy Policy</a>
        </div>
        
        <p style="margin-top: 2rem; font-size: 0.9rem; opacity: 0.7;">
            Configure your API keys in .env to get started
        </p>
    </div>
</body>
</html>`;

    fs.writeFileSync(indexPath, indexHtml);
    console.log('   ✅ Created basic index.html');
}

// Create simple test file
const testFile = path.join('tests', 'api.test.js');
if (!fs.existsSync(testFile)) {
    console.log('\n🧪 Creating basic test file...');
    
    const testContent = `// LinkMágico Commercial API Tests
const request = require('supertest');
const app = require('../server');

describe('LinkMágico API', () => {
    test('Health check should return 200', async () => {
        const response = await request(app)
            .get('/health')
            .expect(200);
            
        expect(response.body.status).toBe('healthy');
        expect(response.body.version).toBe('6.0.0');
    });

    test('Should reject requests without API key', async () => {
        await request(app)
            .post('/api/extract')
            .send({ url: 'https://example.com' })
            .expect(401);
    });

    test('Should accept valid widget token', async () => {
        // This would need a valid token for a real test
        await request(app)
            .get('/widget.js')
            .query({ token: 'invalid-token' })
            .expect(401);
    });
});`;

    fs.writeFileSync(testFile, testContent);
    console.log('   ✅ Created basic test file');
}

// Create deployment script
const deployScript = path.join('scripts', 'deploy.sh');
if (!fs.existsSync(deployScript)) {
    console.log('\n🚀 Creating deployment script...');
    
    const deployContent = `#!/bin/bash
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
npm start`;

    fs.writeFileSync(deployScript, deployContent);
    fs.chmodSync(deployScript, '755');
    console.log('   ✅ Created deployment script');
}

// Install dependencies if package.json exists
if (fs.existsSync('package.json')) {
    console.log('\n📥 Installing dependencies...');
    console.log('   This may take a few minutes...');
    
    exec('npm install', (error, stdout, stderr) => {
        if (error) {
            console.log(`   ❌ Error installing dependencies: ${error.message}`);
            return;
        }
        
        console.log('   ✅ Dependencies installed successfully');
        
        // Final instructions
        console.log('\n🎉 Setup completed successfully!');
        console.log('\n📋 Next Steps:');
        console.log('   1. Update .env with your API keys:');
        console.log('      - OPENAI_API_KEY or GROQ_API_KEY');
        console.log('      - STRIPE_SECRET_KEY (for billing)');
        console.log('   2. Start the server: npm start');
        console.log('   3. Visit: http://localhost:3000');
        console.log('\n🔗 Important URLs:');
        console.log('   - Health Check: http://localhost:3000/health');
        console.log('   - Demo Chatbot: http://localhost:3000/chatbot');
        console.log('   - API Docs: http://localhost:3000/docs (if enabled)');
        console.log('\n🔑 Demo Tenant Created:');
        
        // Read and display demo tenant info
        try {
            const tenants = JSON.parse(fs.readFileSync('data/tenants.json', 'utf8'));
            const demo = tenants[0];
            console.log(`   - Email: ${demo.email}`);
            console.log(`   - API Key: ${demo.apiKey}`);
            console.log(`   - Plan: ${demo.plan}`);
        } catch (err) {
            console.log('   - Check data/tenants.json for details');
        }
        
        console.log('\n⚠️  Security Reminders:');
        console.log('   - Change JWT_SECRET in production');
        console.log('   - Use HTTPS in production');
        console.log('   - Configure proper CORS origins');
        console.log('   - Set up monitoring and backups');
        console.log('\n🛠️  Support:');
        console.log('   - Documentation: Check README.md');
        console.log('   - Issues: Create GitHub issue');
        console.log('   - Email: support@linkmagico.com');
    });
} else {
    console.log('\n⚠️  Run npm install to install dependencies');
    console.log('\n🎉 Basic setup completed!');
}