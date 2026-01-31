# Malware Analysis Platform Documentation

Welcome to the documentation for the Malware Analysis Platform.

## Getting Started

| Guide | Description |
|-------|-------------|
| [Quick Start](QUICKSTART.md) | Get running in 5 minutes |
| [Installation](INSTALLATION.md) | Detailed installation guide |
| [Configuration](CONFIGURATION.md) | Environment variables and API keys |

## Using the Platform

| Guide | Description |
|-------|-------------|
| [User Guide](USER_GUIDE.md) | How to submit samples and interpret results |
| [API Reference](API.md) | Complete REST API documentation |

## Technical Reference

| Guide | Description |
|-------|-------------|
| [Architecture](ARCHITECTURE.md) | System design and data flow |
| [Deployment](DEPLOYMENT.md) | Production deployment guide |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and solutions |

## Quick Links

### Submit a Sample

```bash
# File
curl -X POST http://localhost:8000/api/submissions/file -F "file=@sample.ps1"

# URL
curl -X POST http://localhost:8000/api/submissions/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Check Analysis Status

```bash
curl http://localhost:8000/api/analysis/{id}/status
```

### Get Results

```bash
curl http://localhost:8000/api/analysis/{id}/results
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/reports/{id}/generate \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/malware-analysis-platform/issues)
- **Troubleshooting**: [Troubleshooting Guide](TROUBLESHOOTING.md)

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

MIT License - see LICENSE file for details.
