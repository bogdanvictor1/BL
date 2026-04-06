import os
import sys
import re
import json
import threading
import subprocess
import ctypes
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

KEY_REGEX = re.compile(r"\b\d{6}(?:-\d{6}){7}\b")

def is_windows() -> bool:
    return os.name == "nt"

def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_as_admin():
    """Reinicia o script com privilégios elevados (UAC)."""
    if not is_windows():
        messagebox.showwarning("Somente Windows", "Elevação disponível apenas no Windows.")
        return
    try:
        params = ""
        # Preserve argumentos, se houver
        if len(sys.argv) > 1:
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        script = os.path.abspath(sys.argv[0])
        if params:
            params = f'"{script}" {params}'
        else:
            params = f'"{script}"'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Erro ao elevar", f"Não foi possível reiniciar como administrador.\n\n{e}")

def get_logical_drives():
    """Retorna lista de letras de unidades existentes, ex.: ['C:', 'D:']"""
    drives = []
    if not is_windows():
        return drives
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drives.append(f"{chr(65 + i)}:")
    except Exception:
        # Fallback simples
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            path = f"{letter}:\\"
            if os.path.exists(path):
                drives.append(f"{letter}:")
    return drives

def run_subprocess(cmd_list):
    """Executa comando e retorna (stdout, stderr, returncode)."""
    try:
        # No Windows moderno, UTF-8 costuma funcionar; usamos ignore p/ robustez
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except FileNotFoundError as e:
        return "", str(e), 1
    except Exception as e:
        return "", str(e), 1

def ps_get_recovery_keys(drive_letter: str):
    """Tenta obter chaves via PowerShell Get-BitLockerVolume."""
    ps = r"""
$kp = (Get-BitLockerVolume -MountPoint '{drive}').KeyProtector | Where-Object {{$_.KeyProtectorType -eq 'RecoveryPassword'}};
$kp | ForEach-Object {{ $_.RecoveryPassword }}
""".strip().format(drive=drive_letter)

    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
    out, err, rc = run_subprocess(cmd)
    keys = set(KEY_REGEX.findall(out))
    return list(keys), out, err, rc

def mde_get_recovery_keys(drive_letter: str):
    """Fallback: obtém chaves via manage-bde -protectors -get."""
    cmd = ["manage-bde", "-protectors", "-get", drive_letter]
    out, err, rc = run_subprocess(cmd)
    keys = set(KEY_REGEX.findall(out))
    return list(keys), out, err, rc

def get_recovery_keys(drive_letter: str):
    """
    Retorna dicionário com:
      { "drive": 'C:',
        "keys": [ '123456-...' ],
        "method": "PowerShell" | "manage-bde" | "none",
        "raw": "texto do comando",
        "errors": "stderr, se houver",
        "returncode": int
      }
    """
    # 1) Tenta PowerShell
    keys, out, err, rc = ps_get_recovery_keys(drive_letter)
    if keys:
        return {
            "drive": drive_letter,
            "keys": sorted(keys),
            "method": "PowerShell",
            "raw": out,
            "errors": err,
            "returncode": rc,
        }

    # 2) Fallback para manage-bde
    keys, out, err, rc = mde_get_recovery_keys(drive_letter)
    if keys:
        return {
            "drive": drive_letter,
            "keys": sorted(keys),
            "method": "manage-bde",
            "raw": out,
            "errors": err,
            "returncode": rc,
        }

    # 3) Nada encontrado
    return {
        "drive": drive_letter,
        "keys": [],
        "method": "none",
        "raw": out,
        "errors": err,
        "returncode": rc,
    }

class BitLockerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Recuperação de Chave BitLocker by Bogdan")
        self.geometry("800x520")
        self.minsize(720, 480)

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.create_widgets()
        self.populate_drives()
        self.update_admin_badge()

    def create_widgets(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=12, pady=10)

        lbl = ttk.Label(top_frame, text="Unidade:")
        lbl.pack(side="left")

        self.drive_cmb = ttk.Combobox(top_frame, state="readonly", width=8)
        self.drive_cmb.pack(side="left", padx=(6, 12))

        self.refresh_btn = ttk.Button(top_frame, text="Atualizar unidades", command=self.populate_drives)
        self.refresh_btn.pack(side="left")

        self.get_btn = ttk.Button(top_frame, text="Obter chave de recuperação", command=self.on_get_keys)
        self.get_btn.pack(side="left", padx=(12, 0))

        self.scan_btn = ttk.Button(top_frame, text="Varredura (todas as unidades)", command=self.on_scan_all)
        self.scan_btn.pack(side="left", padx=(12, 0))

        # Admin status and elevation
        admin_frame = ttk.Frame(self)
        admin_frame.pack(fill="x", padx=12, pady=(0, 8))

        self.admin_label_var = tk.StringVar(value="Privilégios: verificando…")
        self.admin_label = ttk.Label(admin_frame, textvariable=self.admin_label_var)
        self.admin_label.pack(side="left")

        self.elevate_btn = ttk.Button(admin_frame, text="Reabrir como Administrador", command=relaunch_as_admin)
        self.elevate_btn.pack(side="left", padx=(12, 0))

        # Output text box
        mid_frame = ttk.Frame(self)
        mid_frame.pack(fill="both", expand=True, padx=12, pady=6)

        self.output = tk.Text(mid_frame, wrap="word", height=16)
        self.output.pack(side="left", fill="both", expand=True)

        yscroll = ttk.Scrollbar(mid_frame, orient="vertical", command=self.output.yview)
        yscroll.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=yscroll.set)

        # Bottom actions
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=10)

        self.copy_btn = ttk.Button(bottom, text="Copiar chaves", command=self.copy_keys)
        self.copy_btn.pack(side="left")

        self.export_btn = ttk.Button(bottom, text="Exportar…", command=self.export_results)
        self.export_btn.pack(side="left", padx=(12, 0))

        self.clear_btn = ttk.Button(bottom, text="Limpar", command=lambda: self.output.delete("1.0", "end"))
        self.clear_btn.pack(side="left", padx=(12, 0))

        self.status_var = tk.StringVar(value="Pronto")
        self.status = ttk.Label(self, relief="sunken", anchor="w", textvariable=self.status_var)
        self.status.pack(fill="x", side="bottom")

    def populate_drives(self):
        drives = get_logical_drives()
        self.drive_cmb["values"] = drives
        if drives:
            self.drive_cmb.set(drives[0])
        else:
            self.drive_cmb.set("")
        self.log(f"Unidades detectadas: {', '.join(drives) if drives else '(nenhuma)'}")

    def update_admin_badge(self):
        self.admin_label_var.set("Privilégios: Administrador" if is_admin() else "Privilégios: Usuário (eleve para acesso completo)")
        # Sinal visual
        if is_admin():
            self.admin_label.configure(foreground="#0A730A")
        else:
            self.admin_label.configure(foreground="#B74900")

    def set_busy(self, busy=True, msg="Processando…"):
        widgets = [self.get_btn, self.scan_btn, self.refresh_btn, self.elevate_btn, self.copy_btn, self.export_btn]
        for w in widgets:
            try:
                w.configure(state="disabled" if busy else "normal")
            except Exception:
                pass
        self.status_var.set(msg if busy else "Pronto")
        self.update()

    def log(self, text: str, newline=True):
        if newline and not text.endswith("\n"):
            text += "\n"
        self.output.insert("end", text)
        self.output.see("end")

    def on_get_keys(self):
        drive = self.drive_cmb.get()
        if not drive:
            messagebox.showinfo("Seleção necessária", "Selecione uma unidade (ex.: C:).")
            return
        if not is_windows():
            messagebox.showwarning("Somente Windows", "Este recurso está disponível apenas no Windows.")
            return

        def worker():
            self.set_busy(True, f"Lendo protetores de {drive}…")
            try:
                result = get_recovery_keys(drive)
                self.show_result(result)
            finally:
                self.set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def on_scan_all(self):
        drives = self.drive_cmb["values"]
        if not drives:
            self.populate_drives()
            drives = self.drive_cmb["values"]
        if not drives:
            messagebox.showinfo("Sem unidades", "Nenhuma unidade foi detectada.")
            return
        if not is_windows():
            messagebox.showwarning("Somente Windows", "Este recurso está disponível apenas no Windows.")
            return

        def worker():
            self.set_busy(True, "Varredura de todas as unidades…")
            try:
                self.log("\n=== Varredura BitLocker ===")
                any_found = False
                for d in drives:
                    r = get_recovery_keys(d)
                    self.show_result(r)
                    if r["keys"]:
                        any_found = True
                if not any_found:
                    self.log("Nenhuma chave de recuperação encontrada nas unidades verificadas.")
            finally:
                self.set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def show_result(self, result: dict):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log(f"\n[{ts}] Unidade {result['drive']} — Método: {result['method']}")
        if result["keys"]:
            for i, k in enumerate(result["keys"], 1):
                self.log(f"Chave {i}: {k}")
        else:
            self.log("Nenhuma chave de recuperação encontrada ou acesso negado.")
        # Detalhes técnicos mínimos
        if result["errors"]:
            self.log("(stderr) " + result["errors"].strip())

    def extract_keys_from_output(self) -> list:
        text = self.output.get("1.0", "end")
        return sorted(set(KEY_REGEX.findall(text)))

    def copy_keys(self):
        keys = self.extract_keys_from_output()
        if not keys:
            messagebox.showinfo("Nada para copiar", "Nenhuma chave de recuperação no painel de saída.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(keys))
        messagebox.showinfo("Copiado", f"{len(keys)} chave(s) copiada(s) para a área de transferência.")

    def export_results(self):
        keys = self.extract_keys_from_output()
        content = self.output.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Sem conteúdo", "Nada para exportar.")
            return

        filetypes = [
            ("Arquivo de texto", "*.txt"),
            ("JSON", "*.json"),
        ]
        path = filedialog.asksaveasfilename(
            title="Salvar resultados",
            defaultextension=".txt",
            filetypes=filetypes
        )
        if not path:
            return

        try:
            if path.lower().endswith(".json"):
                data = {
                    "exported_at": datetime.now().isoformat(timespec="seconds"),
                    "keys": keys,
                    "raw_output": content,
                }
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content + "\n")
            messagebox.showinfo("Exportado", f"Arquivo salvo em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro ao exportar", f"Falha ao salvar o arquivo.\n\n{e}")

if __name__ == "__main__":
    if not is_windows():
        print("Este aplicativo funciona apenas no Windows (BitLocker).")
        sys.exit(1)
    app = BitLockerGUI()
    app.mainloop()