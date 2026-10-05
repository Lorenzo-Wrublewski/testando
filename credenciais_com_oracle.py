import os

import sys

import json

import csv

import ctypes

import shutil

from ctypes import wintypes

import tkinter as tk

from tkinter import ttk, messagebox, filedialog



APP_TITLE = "Credenciais"

DEFAULT_DOMAIN = "BR"



# Mantém o target antigo do VS Code para continuar usando a credencial

# que já possa estar salva no Windows Credential Manager.

VSCODE_CREDENTIAL_TARGET = "CredenciaisVSCodeLauncher"

SSMS_CREDENTIAL_TARGET = "CredenciaisSSMSLauncher"



LOGON_WITH_PROFILE = 0x00000001

CREATE_UNICODE_ENVIRONMENT = 0x00000400



CRED_TYPE_GENERIC = 1

CRED_PERSIST_LOCAL_MACHINE = 2

ERROR_NOT_FOUND = 1168



kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)





class STARTUPINFOW(ctypes.Structure):

    _fields_ = [

        ("cb", wintypes.DWORD),

        ("lpReserved", wintypes.LPWSTR),

        ("lpDesktop", wintypes.LPWSTR),

        ("lpTitle", wintypes.LPWSTR),

        ("dwX", wintypes.DWORD),

        ("dwY", wintypes.DWORD),

        ("dwXSize", wintypes.DWORD),

        ("dwYSize", wintypes.DWORD),

        ("dwXCountChars", wintypes.DWORD),

        ("dwYCountChars", wintypes.DWORD),

        ("dwFillAttribute", wintypes.DWORD),

        ("dwFlags", wintypes.DWORD),

        ("wShowWindow", wintypes.WORD),

        ("cbReserved2", wintypes.WORD),

        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),

        ("hStdInput", wintypes.HANDLE),

        ("hStdOutput", wintypes.HANDLE),

        ("hStdError", wintypes.HANDLE),

    ]





class PROCESS_INFORMATION(ctypes.Structure):

    _fields_ = [

        ("hProcess", wintypes.HANDLE),

        ("hThread", wintypes.HANDLE),

        ("dwProcessId", wintypes.DWORD),

        ("dwThreadId", wintypes.DWORD),

    ]





class CREDENTIALW(ctypes.Structure):

    _fields_ = [

        ("Flags", wintypes.DWORD),

        ("Type", wintypes.DWORD),

        ("TargetName", wintypes.LPWSTR),

        ("Comment", wintypes.LPWSTR),

        ("LastWritten", wintypes.FILETIME),

        ("CredentialBlobSize", wintypes.DWORD),

        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),

        ("Persist", wintypes.DWORD),

        ("AttributeCount", wintypes.DWORD),

        ("Attributes", wintypes.LPVOID),

        ("TargetAlias", wintypes.LPWSTR),

        ("UserName", wintypes.LPWSTR),

    ]





PCREDENTIALW = ctypes.POINTER(CREDENTIALW)





advapi32.CreateProcessWithLogonW.argtypes = [

    wintypes.LPCWSTR,

    wintypes.LPCWSTR,

    wintypes.LPCWSTR,

    wintypes.DWORD,

    wintypes.LPCWSTR,

    wintypes.LPWSTR,

    wintypes.DWORD,

    wintypes.LPVOID,

    wintypes.LPCWSTR,

    ctypes.POINTER(STARTUPINFOW),

    ctypes.POINTER(PROCESS_INFORMATION),

]

advapi32.CreateProcessWithLogonW.restype = wintypes.BOOL



advapi32.CredWriteW.argtypes = [

    ctypes.POINTER(CREDENTIALW),

    wintypes.DWORD,

]

advapi32.CredWriteW.restype = wintypes.BOOL



advapi32.CredReadW.argtypes = [

    wintypes.LPCWSTR,

    wintypes.DWORD,

    wintypes.DWORD,

    ctypes.POINTER(PCREDENTIALW),

]

advapi32.CredReadW.restype = wintypes.BOOL



advapi32.CredDeleteW.argtypes = [

    wintypes.LPCWSTR,

    wintypes.DWORD,

    wintypes.DWORD,

]

advapi32.CredDeleteW.restype = wintypes.BOOL



advapi32.CredFree.argtypes = [wintypes.LPVOID]

advapi32.CredFree.restype = None



kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.CloseHandle.restype = wintypes.BOOL





def get_config_path():

    base = os.environ.get("APPDATA") or os.path.expanduser("~")

    folder = os.path.join(base, "CredenciaisVSCode")

    os.makedirs(folder, exist_ok=True)

    return os.path.join(folder, "config.json")





def load_config():

    path = get_config_path()

    if not os.path.isfile(path):

        return {}



    try:

        with open(path, "r", encoding="utf-8") as f:

            data = json.load(f)

        return data if isinstance(data, dict) else {}

    except Exception:

        return {}





def save_config(**updates):

    """Atualiza o config sem apagar os caminhos já salvos."""

    path = get_config_path()

    data = load_config()

    data.update(updates)



    with open(path, "w", encoding="utf-8") as f:

        json.dump(data, f, ensure_ascii=False, indent=2)





def save_windows_credential(target, raw_user, password, comment):

    """

    Salva usuário/senha no Windows Credential Manager.

    A senha não vai para .env, JSON nem arquivo de texto puro.

    """

    password_bytes = password.encode("utf-16-le")

    blob_buffer = ctypes.create_string_buffer(password_bytes)



    credential = CREDENTIALW()

    credential.Flags = 0

    credential.Type = CRED_TYPE_GENERIC

    credential.TargetName = target

    credential.Comment = comment

    credential.CredentialBlobSize = len(password_bytes)

    credential.CredentialBlob = ctypes.cast(

        blob_buffer, ctypes.POINTER(ctypes.c_ubyte)

    )

    credential.Persist = CRED_PERSIST_LOCAL_MACHINE

    credential.AttributeCount = 0

    credential.Attributes = None

    credential.TargetAlias = None

    credential.UserName = raw_user



    if not advapi32.CredWriteW(ctypes.byref(credential), 0):

        error_code = ctypes.get_last_error()

        raise OSError(error_code, ctypes.FormatError(error_code))





def load_windows_credential(target):

    """Retorna (usuario, senha) ou None se ainda não houver nada salvo."""

    credential_ptr = PCREDENTIALW()



    ok = advapi32.CredReadW(

        target,

        CRED_TYPE_GENERIC,

        0,

        ctypes.byref(credential_ptr),

    )



    if not ok:

        error_code = ctypes.get_last_error()

        if error_code == ERROR_NOT_FOUND:

            return None

        raise OSError(error_code, ctypes.FormatError(error_code))



    try:

        credential = credential_ptr.contents

        raw_user = credential.UserName or ""



        if credential.CredentialBlob and credential.CredentialBlobSize:

            password_bytes = ctypes.string_at(

                credential.CredentialBlob,

                credential.CredentialBlobSize,

            )

            password = password_bytes.decode("utf-16-le")

        else:

            password = ""



        return raw_user, password

    finally:

        advapi32.CredFree(credential_ptr)





def delete_windows_credential(target):

    ok = advapi32.CredDeleteW(

        target,

        CRED_TYPE_GENERIC,

        0,

    )



    if not ok:

        error_code = ctypes.get_last_error()

        if error_code != ERROR_NOT_FOUND:

            raise OSError(error_code, ctypes.FormatError(error_code))





def first_existing_path(candidates):

    seen = set()



    for path in candidates:

        if not path:

            continue



        path = os.path.abspath(path)

        key = path.lower()



        if key in seen:

            continue



        seen.add(key)



        if os.path.isfile(path):

            return path



    return ""





def find_vscode():

    candidates = []



    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    program_files_x86 = os.environ.get(

        "ProgramFiles(x86)", r"C:\Program Files (x86)"

    )



    candidates += [

        os.path.join(program_files, "Microsoft VS Code", "Code.exe"),

        os.path.join(program_files_x86, "Microsoft VS Code", "Code.exe"),

    ]



    localappdata = os.environ.get("LOCALAPPDATA")

    if localappdata:

        candidates.append(

            os.path.join(

                localappdata,

                "Programs",

                "Microsoft VS Code",

                "Code.exe",

            )

        )



    code_in_path = shutil.which("Code.exe") or shutil.which("code")

    if code_in_path:

        candidates.append(code_in_path)



    path_dirs = os.environ.get("PATH", "").split(os.pathsep)

    for folder in path_dirs:

        folder = folder.strip('"')

        if not folder:

            continue



        candidates += [

            os.path.join(folder, "Code.exe"),

            os.path.normpath(os.path.join(folder, "..", "Code.exe")),

        ]



    return first_existing_path(candidates)





def find_ssms():

    """Tenta localizar o Ssms.exe, incluindo o SSMS 20 da imagem enviada."""

    candidates = []



    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    program_files_x86 = os.environ.get(

        "ProgramFiles(x86)", r"C:\Program Files (x86)"

    )



    # O SSMS normalmente fica em Program Files (x86), mas verificamos ambos.

    # Colocamos 20 primeiro porque é a versão mostrada pelo usuário.

    for version in ("20", "21", "19", "18"):

        for base in (program_files_x86, program_files):

            candidates += [

                os.path.join(

                    base,

                    f"SQL Server {version}",

                    "Common7",

                    "IDE",

                    "Ssms.exe",

                ),

                os.path.join(

                    base,

                    f"SQL Server {version}",

                    "Release",

                    "Common7",

                    "IDE",

                    "Ssms.exe",

                ),

            ]



    ssms_in_path = shutil.which("Ssms.exe") or shutil.which("ssms")

    if ssms_in_path:

        candidates.append(ssms_in_path)



    return first_existing_path(candidates)





def split_user(value):

    value = value.strip()



    if "\\\\" in value:

        domain, username = value.split("\\\\", 1)

        return domain.strip() or DEFAULT_DOMAIN, username.strip()



    if "@" in value:

        return None, value



    return DEFAULT_DOMAIN, value





def launch_as_user(username, domain, password, executable, args=""):

    if not executable or not os.path.isfile(executable):

        raise FileNotFoundError("O executável selecionado não foi encontrado.")



    si = STARTUPINFOW()

    si.cb = ctypes.sizeof(si)



    pi = PROCESS_INFORMATION()



    command = f'"{executable}"'

    if args:

        command += f" {args}"



    command_buffer = ctypes.create_unicode_buffer(command)

    workdir = os.path.dirname(executable)



    ok = advapi32.CreateProcessWithLogonW(

        username,

        domain,

        password,

        LOGON_WITH_PROFILE,

        executable,

        command_buffer,

        CREATE_UNICODE_ENVIRONMENT,

        None,

        workdir,

        ctypes.byref(si),

        ctypes.byref(pi),

    )



    if not ok:

        error_code = ctypes.get_last_error()

        raise OSError(error_code, ctypes.FormatError(error_code))



    try:

        return pi.dwProcessId

    finally:

        if pi.hThread:

            kernel32.CloseHandle(pi.hThread)

        if pi.hProcess:

            kernel32.CloseHandle(pi.hProcess)





def error_message_for_logon(exc, app_name):

    code = getattr(exc, "winerror", None) or (

        exc.args[0] if exc.args else None

    )



    if code == 1326:

        return "Usuário ou senha incorretos."

    if code == 1385:

        return (

            "O usuário não possui o tipo de logon necessário "

            "para iniciar esse processo."

        )

    if code == 1314:

        return "O Windows recusou a operação por falta de privilégio."



    return f"Não foi possível abrir o {app_name}.\n\n{exc}"






def get_app_folder():
    """
    Retorna a pasta onde o programa está rodando.

    - Executável gerado pelo PyInstaller: pasta do .exe
    - Script .py: pasta do próprio script
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)

    return os.path.dirname(os.path.abspath(__file__))


def get_sdl_path():
    return os.path.join(get_app_folder(), "sdl.csv")


def append_oracle_credentials(username, password):
    """
    Acrescenta uma nova linha ao sdl.csv sem apagar as anteriores.

    Formato gravado:
        usuario,senha
    """
    path = get_sdl_path()

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([username, password])

    return path


class OracleTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=20)

        self.user_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.status_var = tk.StringVar(value="")

        self.build_ui()

    def build_ui(self):
        title = ttk.Label(
            self,
            text="Credenciais Oracle",
            font=("Segoe UI", 13, "bold"),
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(self, text="Usuário").grid(
            row=1, column=0, sticky="w", pady=6
        )

        self.user_entry = ttk.Entry(
            self,
            textvariable=self.user_var,
            width=43,
        )
        self.user_entry.grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=6,
        )

        ttk.Label(self, text="Senha").grid(
            row=2, column=0, sticky="w", pady=6
        )

        self.password_entry = ttk.Entry(
            self,
            textvariable=self.password_var,
            show="●",
            width=43,
        )
        self.password_entry.grid(
            row=2,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=6,
        )





        buttons = ttk.Frame(self)
        buttons.grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(10, 0),
        )
        buttons.columnconfigure(0, weight=1)

        self.save_button = ttk.Button(
            buttons,
            text="Salvar",
            command=self.save_credentials,
        )
        self.save_button.grid(row=0, column=0, sticky="ew", ipady=5)

        ttk.Button(
            buttons,
            text="Limpar",
            command=self.clear_fields,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(
            self,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            wraplength=500,
        ).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(14, 0),
        )

        self.columnconfigure(1, weight=1)
        self.user_entry.focus_set()

    def clear_fields(self):
        self.user_var.set("")
        self.password_var.set("")
        self.status_var.set("")
        self.user_entry.focus_set()

    def save_credentials(self):
        username = self.user_var.get().strip()
        password = self.password_var.get()

        if not username:
            messagebox.showwarning(APP_TITLE, "Digite o usuário Oracle.")
            return

        if not password:
            messagebox.showwarning(APP_TITLE, "Digite a senha Oracle.")
            return

        try:
            path = append_oracle_credentials(username, password)
        except Exception as exc:
            self.status_var.set("Falha ao salvar.")
            messagebox.showerror(
                APP_TITLE,
                f"Não foi possível salvar\n\n{exc}",
            )
            return

        self.status_var.set(
            f""
        )

        messagebox.showinfo(
            APP_TITLE,
            "Credenciais salvas para acesso ao Oracle.",
        )

        self.password_var.set("")
        self.password_entry.focus_set()


class LauncherTab(ttk.Frame):

    def __init__(

        self,

        master,

        app_name,

        executable_label,

        executable_var,

        credential_target,

        browse_title,

        browse_pattern,

        config_key,

        launch_args="",

    ):

        super().__init__(master, padding=20)



        self.app_name = app_name

        self.executable_label = executable_label

        self.executable_var = executable_var

        self.credential_target = credential_target

        self.browse_title = browse_title

        self.browse_pattern = browse_pattern

        self.config_key = config_key

        self.launch_args = launch_args



        self.user_var = tk.StringVar()

        self.password_var = tk.StringVar()

        self.remember_var = tk.BooleanVar(value=True)

        self.status_var = tk.StringVar(value="")

        self.has_saved_credentials = False



        self.load_saved_credentials()

        self.build_ui()



    def load_saved_credentials(self):

        try:

            saved = load_windows_credential(self.credential_target)

        except Exception as exc:

            self.status_var.set(

                f"Não foi possível carregar as credenciais salvas: {exc}"

            )

            return



        if saved:

            raw_user, password = saved

            self.user_var.set(raw_user)

            self.password_var.set(password)

            self.remember_var.set(True)

            self.has_saved_credentials = True

            self.status_var.set(

                f"Credenciais carregadas. É só clicar em Abrir {self.app_name}."

            )



    def build_ui(self):

        title = ttk.Label(

            self,

            text=f"Abrir {self.app_name}",

            font=("Segoe UI", 13, "bold"),

        )

        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))



        ttk.Label(self, text="Usuário").grid(

            row=1, column=0, sticky="w", pady=6

        )



        self.user_entry = ttk.Entry(

            self,

            textvariable=self.user_var,

            width=43,

        )

        self.user_entry.grid(

            row=1,

            column=1,

            sticky="ew",

            padx=(12, 0),

            pady=6,

        )



        ttk.Label(self, text="Senha").grid(

            row=2, column=0, sticky="w", pady=6

        )



        self.password_entry = ttk.Entry(

            self,

            textvariable=self.password_var,

            show="●",

            width=43,

        )

        self.password_entry.grid(

            row=2,

            column=1,

            sticky="ew",

            padx=(12, 0),

            pady=6,

        )



        ttk.Label(self, text=self.executable_label).grid(

            row=3, column=0, sticky="w", pady=6

        )



        executable_row = ttk.Frame(self)

        executable_row.grid(

            row=3,

            column=1,

            sticky="ew",

            padx=(12, 0),

            pady=6,

        )

        executable_row.columnconfigure(0, weight=1)



        ttk.Entry(

            executable_row,

            textvariable=self.executable_var,

            state="readonly",

        ).grid(row=0, column=0, sticky="ew")



        ttk.Button(

            executable_row,

            text="Procurar",

            command=self.choose_executable,

        ).grid(row=0, column=1, padx=(8, 0))



        options = ttk.Frame(self)

        options.grid(

            row=4,

            column=0,

            columnspan=2,

            sticky="ew",

            pady=(7, 12),

        )



        ttk.Checkbutton(

            options,

            text="Acessar com esse usuário",

            variable=self.remember_var,

        ).pack(side="left")



        ttk.Button(

            options,

            text="Limpar",

            command=self.forget_saved_credentials,

        ).pack(side="right")



        self.open_button = ttk.Button(

            self,

            text=f"Abrir {self.app_name}",

            command=self.open_application,

        )

        self.open_button.grid(

            row=5,

            column=0,

            columnspan=2,

            sticky="ew",

            ipady=5,

        )



        ttk.Label(

            self,

            textvariable=self.status_var,

            font=("Segoe UI", 9),

            wraplength=500,

        ).grid(

            row=6,

            column=0,

            columnspan=2,

            sticky="w",

            pady=(14, 0),

        )



        self.columnconfigure(1, weight=1)



        if self.has_saved_credentials:

            self.open_button.focus_set()

        else:

            self.user_entry.focus_set()



    def choose_executable(self):

        path = filedialog.askopenfilename(

            title=self.browse_title,

            filetypes=[

                (self.executable_label, self.browse_pattern),

                ("Executáveis", "*.exe"),

            ],

        )



        if path:

            self.executable_var.set(path)

            try:

                save_config(**{self.config_key: path})

            except Exception:

                pass



    def forget_saved_credentials(self):

        try:

            delete_windows_credential(self.credential_target)

        except Exception as exc:

            messagebox.showerror(

                APP_TITLE,

                f"Não foi possível apagar as credenciais salvas.\n\n{exc}",

            )

            return



        self.user_var.set("")

        self.password_var.set("")

        self.has_saved_credentials = False

        self.status_var.set("Credenciais salvas apagadas.")

        self.user_entry.focus_set()



    def open_application(self):

        raw_user = self.user_var.get().strip()

        password = self.password_var.get()

        executable = self.executable_var.get().strip()



        if not raw_user:

            messagebox.showwarning(APP_TITLE, "Digite o usuário.")

            return



        if not password:

            messagebox.showwarning(APP_TITLE, "Digite a senha.")

            return



        if not executable:

            messagebox.showwarning(

                APP_TITLE,

                f"O {self.app_name} não foi localizado. "

                f"Clique em Procurar e selecione o executável.",

            )

            return



        if not os.path.isfile(executable):

            messagebox.showwarning(

                APP_TITLE,

                "O caminho salvo não existe mais. "

                "Clique em Procurar e selecione o executável novamente.",

            )

            return



        domain, username = split_user(raw_user)



        if not username:

            messagebox.showwarning(APP_TITLE, "Usuário inválido.")

            return



        display_user = f"{domain}\\\\{username}" if domain else username



        self.open_button.config(state="disabled")

        self.status_var.set(

            f"Abrindo {self.app_name} como {display_user}..."

        )

        self.update_idletasks()



        try:

            pid = launch_as_user(

                username=username,

                domain=domain,

                password=password,

                executable=executable,

                args=self.launch_args,

            )



        except OSError as exc:

            self.status_var.set("Falha ao abrir.")

            messagebox.showerror(

                APP_TITLE,

                error_message_for_logon(exc, self.app_name),

            )



        except Exception as exc:

            self.status_var.set("Falha ao abrir.")

            messagebox.showerror(

                APP_TITLE,

                f"Não foi possível abrir o {self.app_name}.\n\n{exc}",

            )



        else:

            save_warning = None



            try:

                save_config(**{self.config_key: executable})

            except Exception:

                pass



            if self.remember_var.get():

                try:

                    save_windows_credential(

                        self.credential_target,

                        raw_user,

                        password,

                        f"Credencial usada para abrir {self.app_name} com outro usuário",

                    )

                    self.has_saved_credentials = True

                except Exception as exc:

                    save_warning = (

                        f"O {self.app_name} abriu, mas o Windows não conseguiu "

                        f"salvar as credenciais.\n\n{exc}"

                    )

            else:

                try:

                    delete_windows_credential(self.credential_target)

                    self.has_saved_credentials = False

                except Exception:

                    pass



            self.status_var.set(

                f"{self.app_name} iniciado com sucesso. PID: {pid}"

            )



            if save_warning:

                messagebox.showwarning(APP_TITLE, save_warning)

            else:

                messagebox.showinfo(

                    APP_TITLE,

                    f"{self.app_name} iniciado como {display_user}.\n\n"

                    "As credenciais ficam separadas por aba. "

                    "Se 'Lembrar credenciais' estiver marcado, a senha é "

                    "guardada pelo Windows Credential Manager.",

                )



        finally:

            self.open_button.config(state="normal")





class App(tk.Tk):

    def __init__(self):

        super().__init__()



        self.title(APP_TITLE)

        self.geometry("610x430")

        self.resizable(False, False)



        try:

            self.iconbitmap(default="")

        except Exception:

            pass



        config = load_config()



        saved_vscode = config.get("vscode_path", "")

        if not saved_vscode or not os.path.isfile(saved_vscode):

            saved_vscode = find_vscode()



        saved_ssms = config.get("ssms_path", "")

        if not saved_ssms or not os.path.isfile(saved_ssms):

            saved_ssms = find_ssms()



        self.vscode_var = tk.StringVar(value=saved_vscode)

        self.ssms_var = tk.StringVar(value=saved_ssms)



        container = ttk.Frame(self, padding=12)

        container.pack(fill="both", expand=True)







        self.notebook = ttk.Notebook(container)

        self.notebook.pack(fill="both", expand=True)



        self.vscode_tab = LauncherTab(

            self.notebook,

            app_name="VS Code",

            executable_label="Code.exe",

            executable_var=self.vscode_var,

            credential_target=VSCODE_CREDENTIAL_TARGET,

            browse_title="Selecione o Code.exe",

            browse_pattern="Code.exe",

            config_key="vscode_path",

            launch_args="--new-window",

        )



        self.ssms_tab = LauncherTab(

            self.notebook,

            app_name="SQL Server",

            executable_label="Ssms.exe",

            executable_var=self.ssms_var,

            credential_target=SSMS_CREDENTIAL_TARGET,

            browse_title="Selecione o Ssms.exe",

            browse_pattern="Ssms.exe",

            config_key="ssms_path",

            launch_args="",

        )



        self.oracle_tab = OracleTab(self.notebook)



        self.notebook.add(self.vscode_tab, text="VS Code")

        self.notebook.add(self.ssms_tab, text="SQL Server")

        self.notebook.add(self.oracle_tab, text="Oracle")



        self.bind("\<Return>", self.open_current_tab)



    def open_current_tab(self, _event=None):

        current = self.notebook.select()

        widget = self.nametowidget(current)



        if isinstance(widget, LauncherTab):

            widget.open_application()

        elif isinstance(widget, OracleTab):

            widget.save_credentials()





if __name__ == "__main__":

    if os.name != "nt":

        messagebox.showerror(

            APP_TITLE,

            "Este programa funciona somente no Windows.",

        )

        sys.exit(1)



    App().mainloop()
