# A-Project

Intended and specified scanning tools for [Vulnerable API](https://github.com/michealkeines/Vulnerable-API/tree/main).

## Installing Tools
To perform your first scan, make sure you have ostorlab on your machine.
```shell
pip install -U ostorlab
```

This command will download and install ostorlab core.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)

and make sure you have `docker` and `docker compose` installed on your machine.

# Installing Target
Make sure you installed the target and it's up
```shell
cd target && docker compose up -d
```
then visit `http://localhost:13000`

# Getting Started
First, build your agent using this command
```shell
oxo agent build -f solver/agent-vuln-api/oxo.yaml -o dev
```
Agents are shipped as standard docker images.

# How to Use
First, build your agent using this command
```shell
oxo agent scan --agent agent/dev/vuln-api link --url <YOUR_TARGET_URL> --method POST
```

To check the scan status, run:

```shell
oxo scan list
```

Once the scan has completed, to access the scan results, run:

```shell
oxo vulnz list --scan-id <scan-id>
oxo vulnz describe --vuln-id <vuln-id>
```

## Credits

* [OXO](https://github.com/Ostorlab/oxo)
* [DeepSeek](https://chat.deepseek.com/)
* [GPT](https://chatgpt.com/)




