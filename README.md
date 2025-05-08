# AWS MCP Security Inspector

AWS Security MCP is a Model Context Protocol server that provides a MCP Client like Claude to interact to AWS security services, allowing AI assistants to autonomously inspect and analyze your AWS infrastructure for security issues.

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <project-directory>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env-sample .env
```
Edit the `.env` file with your configuration values.


## License

This project is licensed under the MIT License - see the LICENSE file for details. 
