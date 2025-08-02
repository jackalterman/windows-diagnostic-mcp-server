# Windows Diagnostics MCP Server Installation Script
# Run this script as Administrator for best results

param(
    [string]$InstallPath = "D:\Scripts and Code\windows-diagnostic-mcp-server",
    [switch]$ConfigureClaudeDesktop
)

Write-Host "=== Windows Diagnostics MCP Server Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "✅ Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Node.js not found. Please install Node.js 18+ from https://nodejs.org" -ForegroundColor Red
    exit 1
}

# Check if npm is available
try {
    $npmVersion = npm --version
    Write-Host "✅ npm found: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ npm not found. Please ensure npm is installed with Node.js" -ForegroundColor Red
    exit 1
}

# Create installation directory
Write-Host "Creating installation directory: $InstallPath" -ForegroundColor Yellow
if (!(Test-Path $InstallPath)) {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
}

Set-Location $InstallPath

# Create directory structure
New-Item -Path "src" -ItemType Directory -Force | Out-Null

Write-Host "✅ Directory structure created" -ForegroundColor Green

# Create package.json
$packageJson = @'
{
  "name": "windows-diagnostics-mcp-server",
  "version": "1.0.0",
  "description": "MCP server for Windows system diagnostics and crash analysis",
  "main": "build/index.js",
  "type": "module",
  "scripts": {
    "build": "tsc",
    "start": "node build/index.js",
    "dev": "tsc && node build/index.js"
  },
  "keywords": [
    "mcp",
    "windows",
    "diagnostics",
    "system-monitoring",
    "crash-analysis"
  ],
  "author": "Windows Diagnostics MCP",
  "license": "MIT",
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "typescript": "^5.0.0"
  },
  "bin": {
    "windows-diagnostics-mcp": "./build/index.js"
  },
  "files": [
    "build/**/*",
    "README.md"
  ]
}
'@

$packageJson | Out-File -FilePath "package.json" -Encoding UTF8

Write-Host "✅ package.json created" -ForegroundColor Green

# Create tsconfig.json
$tsConfig = @'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Node",
    "outDir": "./build",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "resolveJsonModule": true,
    "allowSyntheticDefaultImports": true
  },
  "include": [
    "src/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "build"
  ]
}
'@

$tsConfig | Out-File -FilePath "tsconfig.json" -Encoding UTF8

Write-Host "✅ tsconfig.json created" -ForegroundColor Green

Write-Host ""
Write-Host "Installing npm dependencies..." -ForegroundColor Yellow
try {
    npm install
    Write-Host "✅ Dependencies installed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to install dependencies: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "⚠️  IMPORTANT: You still need to:" -ForegroundColor Yellow
Write-Host "1. Copy the TypeScript server code to src/index.ts" -ForegroundColor White
Write-Host "2. Run 'npm run build' to compile the server" -ForegroundColor White
Write-Host "3. Configure your MCP client to use the server" -ForegroundColor White

if ($ConfigureClaudeDesktop) {
    Write-Host ""
    Write-Host "Configuring Claude Desktop..." -ForegroundColor Yellow
    
    $claudeConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"
    $claudeConfigDir = Split-Path $claudeConfigPath -Parent
    
    if (!(Test-Path $claudeConfigDir)) {
        New-Item -Path $claudeConfigDir -ItemType Directory -Force | Out-Null
    }
    
    $serverPath = Join-Path $InstallPath "build\index.js"
    
    $claudeConfig = @{
        mcpServers = @{
            "windows-diagnostics" = @{
                command = "node"
                args = @($serverPath)
                env = @{
                    NODE_ENV = "production"
                }
            }
        }
    } | ConvertTo-Json -Depth 10
    
    if (Test-Path $claudeConfigPath) {
        Write-Host "⚠️  Claude Desktop config already exists. Backup created." -ForegroundColor Yellow
        Copy-Item $claudeConfigPath "$claudeConfigPath.backup"
    }
    
    $claudeConfig | Out-File -FilePath $claudeConfigPath -Encoding UTF8
    Write-Host "✅ Claude Desktop configured" -ForegroundColor Green
    Write-Host "   Config file: $claudeConfigPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "🎉 Installation completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Copy the server code to: $InstallPath\src\index.ts" -ForegroundColor White
Write-Host "2. Build the server: cd '$InstallPath' && npm run build" -ForegroundColor White
Write-Host "3. Test the server: npm start" -ForegroundColor White

if (!$ConfigureClaudeDesktop) {
    Write-Host "4. Configure your MCP client to use: $InstallPath\build\index.js" -ForegroundColor White
}

Write-Host ""
Write-Host "Installation directory: $InstallPath" -ForegroundColor Gray