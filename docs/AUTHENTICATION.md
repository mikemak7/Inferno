# Authentication Guide

Inferno supports multiple authentication methods for Claude API access. Choose the one that best fits your needs.

## Table of Contents

- [Authentication Options](#authentication-options)
- [Option 1: Claude Code OAuth (Recommended for macOS)](#option-1-claude-code-oauth-recommended-for-macos)
- [Option 2: API Key](#option-2-api-key)
- [Option 3: Inferno OAuth](#option-3-inferno-oauth)
- [Option 4: Credentials File](#option-4-credentials-file)
- [Authentication Priority](#authentication-priority)
- [Troubleshooting](#troubleshooting)

## Authentication Options

| Method | Platform | Cost | Best For |
|--------|----------|------|----------|
| Claude Code OAuth (Keychain) | macOS only | Uses subscription | Claude Pro/Max users on Mac |
| OAuth Token (ENV variable) | Windows/Linux/Docker | Uses subscription | Windows users, Docker, CI/CD |
| API Key | All platforms | Pay per token | Developers, pay-per-use |
| Inferno OAuth Flow | All platforms | Uses subscription | Browser-based auth |
| Credentials File | All platforms | Pay per token | Shared environments |

## Option 1: Claude Code OAuth (Recommended for macOS)

If you have Claude Code CLI installed and are logged in, Inferno can **automatically reuse your Claude subscription** - no additional API costs!

### Prerequisites

- macOS (uses Keychain)
- Claude Code CLI installed
- Active Claude Pro, Max, or Team subscription

### Setup

**Step 1: Install Claude Code CLI (if not already installed)**
```bash
# Using npm
npm install -g @anthropic-ai/claude-code

# Or using Homebrew
brew install claude-code
```

**Step 2: Login to Claude Code**
```bash
claude login
```

This opens your browser to authenticate with your Anthropic account.

**Step 3: Verify Login**
```bash
claude status
# Should show: Logged in as: your@email.com
```

**Step 4: Use Inferno**
```bash
inferno shell
# Inferno automatically detects and uses your Claude Code credentials
```

### How It Works

Claude Code stores OAuth tokens in macOS Keychain:
- **Service**: `Claude Code-credentials`
- **Account**: Your username

Inferno reads these tokens automatically - no configuration needed.

### Verify OAuth is Working

```bash
inferno shell
# Look for: "Using OAuth token from macOS Keychain"
```

Or check manually:
```bash
security find-generic-password -s "Claude Code-credentials" -a "$USER" -w 2>/dev/null && echo "Token found"
```

## Option 2: OAuth Token via Environment Variable (Windows/Linux/Docker)

For users on **Windows, Linux, or Docker** who don't have macOS Keychain, you can set OAuth tokens directly via environment variables. This uses your Claude subscription - **no additional API costs!**

### When to Use This

- Windows users (no macOS Keychain)
- Linux users
- Docker containers
- CI/CD pipelines
- WSL2 environments

### Setup

**Step 1: Get your OAuth token**

If you have Claude Code CLI installed, you may be able to export the token:
```bash
# Check if Claude Code stores a token you can export
claude auth status
```

Or use Inferno's OAuth flow to get a token:
```bash
inferno auth login
# After authentication, the token is saved to ~/.inferno/oauth_token.json
# You can extract it and set as environment variable
```

**Step 2: Set the environment variable**

**Windows (PowerShell):**
```powershell
# Set for current session
$env:CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat01-your-token-here"

# Or set permanently (User level)
[Environment]::SetEnvironmentVariable("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-your-token-here", "User")
```

**Windows (Command Prompt):**
```cmd
# Set for current session
set CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-your-token-here

# Set permanently
setx CLAUDE_CODE_OAUTH_TOKEN "sk-ant-oat01-your-token-here"
```

**Linux/WSL:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-your-token-here

# Apply immediately
source ~/.bashrc
```

**Docker:**
```bash
# Pass via docker run
docker run -e CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-... inferno-ai

# Or in docker-compose.yml
environment:
  - CLAUDE_CODE_OAUTH_TOKEN=${CLAUDE_CODE_OAUTH_TOKEN}
```

**Using .env file:**
```bash
# Create .env file in project root
echo "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-your-token" >> .env
```

### Supported Environment Variables

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | OAuth token from Claude Code CLI (recommended) |
| `INFERNO_OAUTH_TOKEN` | Alternative variable name (same functionality) |

Both variables work identically - use whichever you prefer.

### Verify OAuth is Working

```bash
inferno auth status
# Should show: Method: env:CLAUDE_CODE_OAUTH_TOKEN
```

## Option 3: API Key

Use a direct Anthropic API key for pay-per-token billing.

### Get Your API Key

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Navigate to **API Keys**
3. Click **Create Key**
4. Copy the key (starts with `sk-ant-`)

### Setup

**Method A: Environment Variable (Recommended)**
```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Or set for current session only
export ANTHROPIC_API_KEY=sk-ant-api03-...
inferno shell
```

**Method B: .env File**
```bash
# Create .env in the inferno-ai directory
echo "ANTHROPIC_API_KEY=sk-ant-api03-..." > .env
```

**Method C: Inline**
```bash
ANTHROPIC_API_KEY=sk-ant-api03-... inferno shell
```

### Security Best Practices

- Never commit API keys to git
- Use environment variables, not hardcoded values
- Rotate keys periodically
- Set usage limits in the Anthropic console

## Option 4: Inferno OAuth Flow

For Claude subscribers who prefer browser-based authentication, Inferno provides its own OAuth flow.

### Setup

```bash
# Start the OAuth flow
inferno auth login
```

This will:
1. Open your browser to Anthropic's consent page
2. Ask you to approve Inferno's access
3. Redirect back and save the token locally

### Token Storage

Tokens are saved to: `~/.inferno/oauth_token.json`

### Logout

```bash
inferno auth logout
```

### Token Refresh

Tokens refresh automatically when they expire. If you encounter authentication errors:
```bash
inferno auth login  # Re-authenticate
```

## Option 5: Credentials File

Store credentials in a JSON file for shared or automated environments.

### Setup

**Create the credentials file:**
```bash
mkdir -p ~/.inferno
cat > ~/.inferno/credentials.json << 'EOF'
{
  "api_key": "sk-ant-api03-your-key-here"
}
EOF

# Secure the file
chmod 600 ~/.inferno/credentials.json
```

### File Format

```json
{
  "api_key": "sk-ant-api03-...",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

The `expires_at` field is optional - useful for rotating credentials.

## Authentication Priority

Inferno checks credentials in this order:

1. **Keychain (macOS)** - Claude Code OAuth tokens from macOS Keychain
2. **Environment OAuth** - `CLAUDE_CODE_OAUTH_TOKEN` or `INFERNO_OAUTH_TOKEN`
3. **OAuth Token File** - Inferno's own OAuth (`~/.inferno/oauth_token.json`)
4. **Environment API Key** - `ANTHROPIC_API_KEY`
5. **Credentials File** - `~/.inferno/credentials.json`

The first successful method is used.

### Platform-Specific Behavior

| Platform | Primary Method | Fallback |
|----------|---------------|----------|
| macOS | Keychain (automatic) | ENV var, API key |
| Windows | ENV OAuth token | API key, credentials file |
| Linux | ENV OAuth token | API key, credentials file |
| Docker | ENV OAuth token | API key (via -e flag) |

### Force Specific Method

To skip certain methods:

```bash
# Force API key only (skip OAuth)
INFERNO_PREFER_OAUTH=false inferno shell

# Or in .env
INFERNO_PREFER_OAUTH=false
```

## External API Keys (Optional)

Inferno can use additional APIs for enhanced reconnaissance:

| Service | Environment Variable | Purpose | Free Tier |
|---------|---------------------|---------|-----------|
| Shodan | `SHODAN_API_KEY` | Internet-wide scanning data | Limited |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Host/cert search | Yes |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Malware/URL analysis | Yes |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | DNS intelligence | Limited |
| NVD | `NVD_API_KEY` | CVE lookups | Yes (recommended) |
| GitHub | `GITHUB_TOKEN` | Repository recon | Yes |

### NVD API Key (Recommended)

Get a free NVD API key for faster CVE lookups:

1. Go to [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form (instant approval)
3. Add to your environment:
   ```bash
   export NVD_API_KEY=your-nvd-key
   ```

**Rate limits:**
- With key: 50 requests per 30 seconds
- Without key: 5 requests per 30 seconds

## Troubleshooting

### "No credentials found"

```bash
# Check what's available
inferno auth status

# Force re-authentication
inferno auth login
```

### "OAuth token expired"

```bash
# For Claude Code
claude login

# For Inferno OAuth
inferno auth login
```

### "Invalid API key"

- Verify the key is correct (starts with `sk-ant-`)
- Check the key hasn't been revoked in Anthropic console
- Ensure no extra whitespace in environment variable

### "Keychain access denied" (macOS)

macOS may prompt for Keychain access. Click "Allow" or "Always Allow".

If issues persist:
```bash
# Check Keychain Access.app for "Claude Code-credentials"
# Ensure your user has access to the item
```

### Rate Limiting

If you hit rate limits:
- API keys have per-minute/per-day limits
- OAuth (subscription) has fair-use limits
- Consider upgrading your plan or using multiple keys

### Check Current Auth Status

```bash
inferno auth status
```

Example output:
```
Authentication Status:
  Method: keychain:claude-code
  Type: OAuth Token
  Status: Valid
  Loaded: 2024-01-15 10:30:00 UTC
```

## Security Considerations

### API Key Security

- Store keys in environment variables, not code
- Never commit keys to version control
- Use `.env` files (add to `.gitignore`)
- Rotate keys regularly

### OAuth Security

- Tokens are stored with restrictive permissions (600)
- Refresh tokens enable long-term access
- Logout removes stored tokens

### Keychain Security (macOS)

- Credentials protected by macOS Keychain
- Requires user authentication to access
- App-specific access controls

## Next Steps

- [Configure Settings](CONFIGURATION.md)
- [Install Security Tools](TOOLS.md)
- [Start Using Inferno](USAGE.md)
