import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import sys
import platform as _platform
import hmac

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.vault_format import MIN_PIN_LENGTH, write_vaultkey_file

def _open_url(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass

C = {

    "bg":        "#0d0d14",
    "surface":   "#13131f",
    "surface2":  "#1a1a2e",
    "surface3":  "#1f1f38",
    "overlay":   "#0a0a12",

    "border":    "#2a2a45",
    "border2":   "#35355a",

    "accent":    "#7c3aed",
    "accent2":   "#9d5bff",
    "accent3":   "#4c1d95",
    "neon":      "#9d5bff",

    "green":     "#22c55e",
    "red":       "#ef4444",
    "yellow":    "#eab308",
    "orange":    "#f97316",

    "text":      "#f1f0ff",
    "text2":     "#9b98c0",
    "text3":     "#5c5a80",
    "text_inv":  "#ffffff",
}

_SYS = _platform.system()
_FONT_BODY = (
    "Inter"          if _SYS == "Windows" else
    "SF Pro Text"    if _SYS == "Darwin"  else
    "Ubuntu"
)
_FONT_MONO = "JetBrains Mono" if _SYS != "Windows" else "Cascadia Code"

FT = {
    "h1":    (_FONT_BODY, 22, "bold"),
    "h2":    (_FONT_BODY, 14, "bold"),
    "h3":    (_FONT_BODY, 11, "bold"),
    "body":  (_FONT_BODY, 10),
    "small": (_FONT_BODY, 9),
    "mono":  (_FONT_MONO, 10),
    "word":  (_FONT_MONO, 11, "bold"),
    "brand": (_FONT_BODY, 26, "bold"),
    "label": (_FONT_BODY, 8),
}

_CLIPBOARD_WIPE_SECONDS = 30

def _clipboard_copy(widget: tk.Misc, text: str, label: str = "Senha") -> None:
    try:
        widget.clipboard_clear()
        widget.clipboard_append(text)
    except tk.TclError:
        messagebox.showerror("Clipboard", "Não foi possível acessar o clipboard.")
        return

    def _wipe():
        try:
            if hmac.compare_digest(widget.clipboard_get(), text):
                widget.clipboard_clear()
                widget.clipboard_append("")
        except tk.TclError:
            pass

    widget.after(_CLIPBOARD_WIPE_SECONDS * 1000, _wipe)
    _toast(widget, f"  {label} copiada  ·  apaga em {_CLIPBOARD_WIPE_SECONDS}s")

def _toast(widget: tk.Misc, msg: str, ms: int = 2500) -> None:
    try:
        root = widget.winfo_toplevel()
        t = tk.Toplevel(root)
        t.overrideredirect(True)
        t.attributes("-topmost", True)
        t.configure(bg=C["surface2"])

        tk.Frame(t, bg=C["neon"], height=1).pack(fill="x")
        inner = tk.Frame(t, bg=C["surface2"])
        inner.pack()
        tk.Label(inner, text=msg, bg=C["surface2"], fg=C["text"],
                 font=FT["small"], padx=18, pady=10).pack()

        t.update_idletasks()
        rw = root.winfo_width()
        rh = root.winfo_height()
        rx = root.winfo_rootx()
        ry = root.winfo_rooty()
        tw = t.winfo_width()
        th = t.winfo_height()
        t.geometry(f"+{rx + rw - tw - 20}+{ry + rh - th - 20}")
        t.after(ms, t.destroy)
    except Exception:
        pass

def Btn(parent, text, cmd, kind="primary", **kw):
    styles = {
        "primary": {
            "bg": C["accent"],  "hov": C["accent2"],
            "fg": "#ffffff",    "pad": (18, 9),
        },
        "ghost": {
            "bg": C["surface2"], "hov": C["surface3"],
            "fg": C["text2"],    "pad": (14, 7),
        },
        "danger": {
            "bg": "#1a0a10",     "hov": C["red"],
            "fg": C["red"],      "pad": (10, 6),
        },
        "neon": {
            "bg": C["surface2"], "hov": C["surface3"],
            "fg": C["neon"],     "pad": (14, 7),
        },
    }
    s = styles.get(kind, styles["primary"])
    padx = kw.pop("padx", s["pad"][0])
    pady = kw.pop("pady", s["pad"][1])
    font = kw.pop("font", FT["h3"] if kind == "primary" else FT["small"])
    bg, hov, fg = s["bg"], s["hov"], s["fg"]
    b = tk.Button(
        parent, text=text, command=cmd,
        bg=bg, fg=fg,
        activebackground=hov, activeforeground=fg,
        relief="flat", cursor="hand2",
        padx=padx, pady=pady,
        font=font, bd=0, **kw,
    )
    b.bind("<Enter>", lambda e: b.config(bg=hov))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b

def Entry(parent, var=None, show=None, width=32, mono=False, **kw):
    return tk.Entry(
        parent,
        textvariable=var, show=show,
        bg=C["surface2"], fg=C["text"],
        insertbackground=C["neon"],
        relief="flat",
        font=FT["mono"] if mono else FT["body"],
        width=width,
        highlightthickness=1,
        highlightbackground=C["border"],
        highlightcolor=C["neon"],
        **kw,
    )

def Label(parent, text="", font=None, fg=None, bg=None, **kw):
    return tk.Label(parent, text=text,
                    font=font or FT["body"],
                    fg=fg or C["text"],
                    bg=bg or C["bg"], **kw)

def Sep(parent, color=None):
    return tk.Frame(parent, bg=color or C["border"], height=1)

def Card(parent, **kw):
    border = tk.Frame(parent, bg=C["border2"], **kw)
    inner = tk.Frame(border, bg=C["surface"])
    inner.pack(fill="both", expand=True, padx=1, pady=1)
    border._inner = inner
    return border

def _styled_scrollbar(parent):
    sb = tk.Scrollbar(parent, orient="vertical",
                      width=6,
                      bg=C["surface3"],
                      troughcolor=C["bg"],
                      activebackground=C["accent2"],
                      relief="flat", bd=0)
    return sb

def PasswordField(parent, var, bg_parent=None):
    bg = bg_parent or C["surface"]
    frame = tk.Frame(parent, bg=bg)
    e = tk.Entry(frame, textvariable=var, show="●",
                 bg=C["surface2"], fg=C["text"],
                 insertbackground=C["neon"],
                 relief="flat", font=FT["mono"], width=30,
                 highlightthickness=1,
                 highlightbackground=C["border"],
                 highlightcolor=C["neon"])
    e.pack(side="left", fill="x", expand=True, ipady=7)
    eye_btn = tk.Button(frame, text="◉",
                        bg=C["surface2"], fg=C["text3"],
                        relief="flat", cursor="hand2", padx=10,
                        font=(_FONT_BODY, 9), bd=0,
                        activebackground=C["surface3"],
                        activeforeground=C["neon"])
    eye_btn.pack(side="left")
    entry_widget = e
    eye_btn.bind("<ButtonPress-1>",   lambda ev: entry_widget.config(show=""))
    eye_btn.bind("<ButtonRelease-1>", lambda ev: entry_widget.config(show="●"))
    return frame, e

def strength_bar(parent, bits=0, bg_parent=None):
    bg = bg_parent or C["surface"]
    frame = tk.Frame(parent, bg=bg)
    bar_bg = tk.Frame(frame, bg=C["border"], height=3)
    bar_bg.pack(fill="x")
    bar_fill = tk.Frame(bar_bg, bg=C["accent"], height=3)
    bar_fill.place(x=0, y=0, relwidth=0, height=3)
    lbl = tk.Label(frame, text="", bg=bg, fg=C["text3"], font=FT["label"])
    lbl.pack(anchor="w", pady=(3, 0))

    def update(b, text=""):
        pct = min(b / 120, 1.0)
        color = (C["red"] if b < 40 else
                 C["yellow"] if b < 60 else
                 C["neon"] if b < 80 else
                 C["green"])
        bar_fill.config(bg=color)
        bar_fill.place(relwidth=pct)
        lbl.config(text=text, fg=color)

    return frame, update

def _bind_strength_meter(owner, var, update_fn, warn_lbl):
    """Liga um StringVar (passphrase ou PIN) a uma barra de força + label de
    avisos, com proteção contra o widget já ter sido destruído quando o
    trace dispara (ex: durante troca de tela).

    [N-04] Antes desta correção, cada tela duplicava esta lógica com o ramo
    de valor vazio (`if not val: ...`) FORA do try/except, causando um
    TclError não tratado ("Exception in Tkinter callback") sempre que o
    StringVar recebia um novo valor depois que a tela já tinha sido
    destruída — reproduzido no fluxo de recuperação por 24 palavras.
    Centralizar aqui também permite ligar o medidor de força ao PIN do
    .vaultkey nas telas de recuperação/rekey (N-09), que antes só existia
    na tela de criação de cofre.
    """
    def _on_change(*_):
        if not owner.winfo_exists():
            return
        try:
            val = var.get()
            if not val:
                update_fn(0, "")
                warn_lbl.config(text="")
                return
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(val)
            update_fn(r["bits"], f"{r['bits']} bits — {r['strength']}")
            warn_lbl.config(text="\n".join(r["warnings"]) if r["warnings"] else "")
        except Exception:
            pass
    var.trace_add("write", _on_change)
    return _on_change

class LoadingDlg(tk.Toplevel):
    def __init__(self, parent, msg="Processando..."):
        super().__init__(parent)
        self.overrideredirect(True)
        self.configure(bg=C["surface"])
        w, h = 320, 100
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        inner = tk.Frame(self, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=24, pady=16)
        tk.Label(inner, text=msg, bg=C["surface"], fg=C["text"],
                 font=FT["body"]).pack()

        style = ttk.Style()
        style.theme_use("default")
        style.configure("KL.Horizontal.TProgressbar",
                        troughcolor=C["surface2"],
                        background=C["neon"],
                        borderwidth=0, relief="flat")
        self._pb = ttk.Progressbar(inner, mode="indeterminate",
                                   length=260, style="KL.Horizontal.TProgressbar")
        self._pb.pack(pady=(10, 0))
        self._pb.start(8)
        self.grab_set()
        self.update()

    def close(self):
        try:
            self._pb.stop()
            self.destroy()
        except Exception:
            pass

class Screen(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C["bg"])
        self.app = app

    def _back_btn(self, target=None):
        cmd = target or self.app.show_welcome
        f = tk.Frame(self, bg=C["bg"])
        f.pack(anchor="w", padx=20, pady=(14, 0))
        b = tk.Button(f, text="← Voltar", command=cmd,
                      bg=C["bg"], fg=C["text3"],
                      relief="flat", cursor="hand2",
                      font=FT["small"], bd=0,
                      activebackground=C["bg"],
                      activeforeground=C["text2"])
        b.pack()
        b.bind("<Enter>", lambda e: b.config(fg=C["text2"]))
        b.bind("<Leave>", lambda e: b.config(fg=C["text3"]))

    def _title(self, icon, text, subtitle=""):
        f = tk.Frame(self, bg=C["bg"])
        f.pack(pady=(10, 0), padx=28, anchor="w")
        tk.Label(f, text=icon, bg=C["bg"],
                 font=("Segoe UI Emoji", 20)).pack(side="left", padx=(0, 10))
        t = tk.Frame(f, bg=C["bg"])
        t.pack(side="left")
        tk.Label(t, text=text, bg=C["bg"], fg=C["text"],
                 font=FT["h1"]).pack(anchor="w")
        if subtitle:
            tk.Label(t, text=subtitle, bg=C["bg"], fg=C["text3"],
                     font=FT["small"]).pack(anchor="w")

    def _section_label(self, parent, title, subtitle=""):
        tk.Label(parent, text=title, bg=C["bg"],
                 fg=C["accent2"], font=FT["label"]).pack(padx=28, pady=(14, 2), anchor="w")
        if subtitle:
            tk.Label(parent, text=subtitle, bg=C["bg"],
                     fg=C["text3"], font=FT["small"]).pack(padx=28, anchor="w")

    def _scrollable_body(self):
        outer = tk.Frame(self, bg=C["bg"])
        outer.pack(fill="both", expand=True)
        sb = _styled_scrollbar(outer)
        sb.pack(side="right", fill="y", padx=0)
        canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0,
                           yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=C["bg"])
        win_id = canvas.create_window(0, 0, window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(win_id, width=e.width))

        canvas.bind("<MouseWheel>",
                    lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        inner.bind("<MouseWheel>",
                   lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        return outer, inner

class WelcomeScreen(Screen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._build()

    def _build(self):
        center = tk.Frame(self, bg=C["bg"])
        center.pack(expand=True)

        logo_f = tk.Frame(center, bg=C["bg"])
        logo_f.pack(pady=(0, 4))
        tk.Label(logo_f, text="🔐", bg=C["bg"],
                 font=("Segoe UI Emoji", 42)).pack()
        tk.Label(center, text="key_lock", bg=C["bg"],
                 fg=C["text"], font=FT["brand"]).pack()
        tk.Label(center,
                 text="Local · Zero-knowledge · BIP-39 · AES-256-GCM",
                 bg=C["bg"], fg=C["text3"], font=FT["small"]).pack(pady=(4, 28))

        card_outer = tk.Frame(center, bg=C["border2"])
        card_outer.pack(ipadx=1, ipady=1)
        card = tk.Frame(card_outer, bg=C["surface"])
        card.pack(fill="both", expand=True)

        tk.Frame(card, bg=C["neon"], height=1).pack(fill="x")

        inner = tk.Frame(card, bg=C["surface"])
        inner.pack(padx=28, pady=24)

        self._menu_btn(inner, "  Abrir cofre existente",
                       self.app.open_vault_flow, primary=True)
        self._menu_btn(inner, "  Criar novo cofre",
                       self.app.show_create, primary=True)

        Sep(inner, C["border"]).pack(fill="x", pady=14)

        self._menu_btn(inner, "  Recuperar (.vaultkey + PIN)",
                       lambda: self.app.show_recover("file"))
        self._menu_btn(inner, "  Recuperar (24 palavras BIP-39)",
                       lambda: self.app.show_recover("words"))

        Sep(inner, C["border"]).pack(fill="x", pady=14)

        self._menu_btn(inner, "  Gerador de senhas",
                       self.app.show_genpass)

        tk.Label(center,
                 text="100% local · sem telemetria · sem rede",
                 bg=C["bg"], fg=C["text3"], font=FT["label"]).pack(pady=(18, 4))

        # Link GitHub com ícone
        gh_frame = tk.Frame(center, bg=C["bg"], cursor="hand2")
        gh_frame.pack(pady=(0, 4))
        gh_icon = tk.Label(gh_frame, text="⌥", bg=C["bg"],
                           fg=C["text3"], font=(_FONT_BODY, 11),
                           cursor="hand2")
        gh_icon.pack(side="left", padx=(0, 4))
        gh_lbl = tk.Label(gh_frame,
                          text="github.com/fabricio-sec/Project-Key_Lock",
                          bg=C["bg"], fg=C["text3"],
                          font=(_FONT_BODY, 9), cursor="hand2")
        gh_lbl.pack(side="left")
        _gh_url = "https://github.com/fabricio-sec/Project-Key_Lock"
        for w in (gh_frame, gh_icon, gh_lbl):
            w.bind("<Enter>", lambda e: (gh_lbl.config(fg=C["neon"]),
                                         gh_icon.config(fg=C["neon"])))
            w.bind("<Leave>", lambda e: (gh_lbl.config(fg=C["text3"]),
                                         gh_icon.config(fg=C["text3"])))
            w.bind("<Button-1>", lambda e: _open_url(_gh_url))

        try:
            from core import __version__
            tk.Label(center, text=f"v{__version__}", bg=C["bg"],
                     fg=C["text3"], font=("Consolas", 8)).pack(pady=(2, 0))
        except Exception:
            pass

        credit = tk.Label(self, text="by Fabrício",
                          bg=C["bg"], fg=C["text3"],
                          font=(_FONT_BODY, 8),
                          cursor="hand2")
        credit.place(relx=1.0, rely=1.0, anchor="se", x=-14, y=-10)
        credit.bind("<Enter>", lambda e: credit.config(fg=C["neon"]))
        credit.bind("<Leave>", lambda e: credit.config(fg=C["text3"]))
        credit.bind("<Button-1>", lambda e: _open_url(
            "https://www.linkedin.com/in/fabrici04/"))

    def _menu_btn(self, parent, text, cmd, primary=False):
        bg  = C["accent"]  if primary else C["surface2"]
        hov = C["accent2"] if primary else C["surface3"]
        fg  = "#ffffff"    if primary else C["text2"]
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg, fg=fg,
                      activebackground=hov, activeforeground=fg,
                      relief="flat", cursor="hand2",
                      font=FT["h3"] if primary else FT["body"],
                      padx=20, pady=9, bd=0, anchor="w")
        b.pack(fill="x", pady=3)
        b.bind("<Enter>", lambda e: b.config(bg=hov))
        b.bind("<Leave>", lambda e: b.config(bg=bg))

class CreateScreen(Screen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._build()

    def _build(self):
        self._back_btn()
        self._title("🔐", "Criar novo cofre",
                    "Defina passphrase principal + PIN de proteção do arquivo de recuperação")
        Sep(self, C["border"]).pack(fill="x", padx=24, pady=10)

        _, inner = self._scrollable_body()
        pad = dict(padx=28, anchor="w")

        tk.Label(inner, text="Arquivo do cofre (.vault)",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(**pad, pady=(0, 4))
        row_f = tk.Frame(inner, bg=C["bg"])
        row_f.pack(padx=28, pady=(0, 14), fill="x")
        self.path_v = tk.StringVar(value=os.path.expanduser("~/meu_cofre.vault"))
        Entry(row_f, var=self.path_v, width=38).pack(side="left", ipady=7)
        Btn(row_f, "…", self._browse, kind="ghost", padx=10).pack(
            side="left", padx=(6, 0))

        self._section_label(inner, "PASSPHRASE PRINCIPAL",
                            "Protege o cofre. Use frase com 4+ palavras.")
        self.pp_v = tk.StringVar()
        pf, _ = PasswordField(inner, self.pp_v, C["bg"])
        pf.pack(padx=28, fill="x", pady=(4, 2))
        sf, self._pp_str = strength_bar(inner, 0, C["bg"])
        sf.pack(padx=28, fill="x")
        self.pp_warn = tk.Label(inner, text="", bg=C["bg"],
                                fg=C["yellow"], font=FT["small"])
        self.pp_warn.pack(padx=28, anchor="w")
        _bind_strength_meter(self, self.pp_v, self._pp_str, self.pp_warn)

        tk.Label(inner, text="Confirmar passphrase",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, pady=(10, 4), anchor="w")
        self.pp2_v = tk.StringVar()
        pf2, _ = PasswordField(inner, self.pp2_v, C["bg"])
        pf2.pack(padx=28, fill="x", pady=(0, 4))

        self._section_label(inner, "PIN DE PROTEÇÃO DO .vaultkey",
                            "Protege o arquivo de recuperação. Pode ser diferente da passphrase.")
        self.pin_v = tk.StringVar()
        pf3, _ = PasswordField(inner, self.pin_v, C["bg"])
        pf3.pack(padx=28, fill="x", pady=(4, 2))
        sf2, self._pin_str = strength_bar(inner, 0, C["bg"])
        sf2.pack(padx=28, fill="x")
        self.pin_warn = tk.Label(inner, text="", bg=C["bg"],
                                 fg=C["yellow"], font=FT["small"])
        self.pin_warn.pack(padx=28, anchor="w")
        _bind_strength_meter(self, self.pin_v, self._pin_str, self.pin_warn)

        tk.Label(inner, text="Confirmar PIN",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, pady=(10, 4), anchor="w")
        self.pin2_v = tk.StringVar()
        pf4, _ = PasswordField(inner, self.pin2_v, C["bg"])
        pf4.pack(padx=28, fill="x", pady=(0, 20))

        Btn(inner, "  Criar cofre  ", self._create).pack(
            padx=28, pady=(0, 36), fill="x")

    def _browse(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".vault",
            filetypes=[("Vault", "*.vault"), ("Todos", "*.*")],
            initialfile="meu_cofre.vault")
        if p:
            self.path_v.set(p)

    def _create(self):
        path = self.path_v.get().strip()
        pp, pp2 = self.pp_v.get(), self.pp2_v.get()
        pin, pin2 = self.pin_v.get(), self.pin2_v.get()

        if not path:
            messagebox.showerror("Erro", "Escolha o caminho do cofre."); return
        if not pp:
            messagebox.showerror("Erro", "Passphrase não pode ser vazia."); return
        if pp != pp2:
            messagebox.showerror("Erro", "Passphrases não coincidem."); return
        if not pin:
            messagebox.showerror("Erro", "PIN não pode ser vazio."); return
        if len(pin) < MIN_PIN_LENGTH:
            messagebox.showerror("PIN muito curto",
                f"O PIN do arquivo de recuperação deve ter pelo menos {MIN_PIN_LENGTH} "
                "caracteres.\nEsse PIN é a única proteção do arquivo .vaultkey caso ele "
                "seja roubado.")
            return
        if pin != pin2:
            messagebox.showerror("Erro", "PINs não coincidem."); return

        try:
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(pp)
            if r["bits"] < 40:
                if not messagebox.askyesno("Passphrase fraca",
                        f"Entropia estimada: {r['bits']} bits.\n"
                        "Recomendamos pelo menos 60 bits.\nContinuar mesmo assim?"):
                    return
        except Exception:
            pass

        if os.path.exists(path):
            if not messagebox.askyesno("Arquivo existe",
                    f"Já existe um arquivo em:\n{path}\n\nSobrescrever?"):
                return

        ld = LoadingDlg(self.app.root, "Derivando chave  (Argon2id 256 MB)…")
        def work():
            try:
                from core.vault import create_vault
                mnemonic, vaultkey_content = create_vault(pp, path, pin)
                vaultkey_path = path.replace(".vault", ".vaultkey")
                write_vaultkey_file(vaultkey_path, vaultkey_content)
                self.app.root.after(0, lambda: self._done(path, vaultkey_path, mnemonic, pp, ld))
            except Exception as ex:
                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Erro ao criar cofre", str(ex))))
        threading.Thread(target=work, daemon=True).start()

    def _done(self, vault_path, vaultkey_path, mnemonic, pp, ld):
        ld.close()
        MnemonicDlg(self.app.root, mnemonic, vaultkey_path)
        self.app.enter_vault(vault_path, pp)

class MnemonicDlg(tk.Toplevel):
    def __init__(self, parent, phrase, vaultkey_path):
        super().__init__(parent)
        self.title("Chave de Recuperação")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 640, 500
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")
        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=20)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="! GUARDE ESTAS 24 PALAVRAS EM LOCAL FÍSICO SEGURO",
                 bg=C["bg"], fg=C["red"], font=FT["h3"]).pack()
        tk.Label(inner,
                 text="Papel físico · Cofre físico · NUNCA em foto, nuvem ou mensagem digital",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(pady=(2, 14))

        words = phrase.split()
        grid_f = tk.Frame(inner, bg=C["border2"])
        grid_f.pack(fill="x")
        g = tk.Frame(grid_f, bg=C["surface"])
        g.pack(fill="x", padx=1, pady=1)
        ginner = tk.Frame(g, bg=C["surface"], padx=14, pady=14)
        ginner.pack(fill="x")

        for i, wd in enumerate(words):
            r, c = divmod(i, 6)
            cell = tk.Frame(ginner, bg=C["surface2"])
            cell.grid(row=r, column=c, padx=2, pady=2, sticky="ew")
            tk.Label(cell, text=f"{i+1:02d}", bg=C["surface2"],
                     fg=C["text3"], font=FT["label"], padx=8, pady=2).pack(anchor="w")
            tk.Label(cell, text=wd, bg=C["surface2"],
                     fg=C["text"], font=FT["word"], padx=8, pady=4).pack(anchor="w")
            ginner.columnconfigure(c, weight=1)

        tk.Label(inner,
                 text=f"Arquivo .vaultkey salvo em:\n{vaultkey_path}",
                 bg=C["bg"], fg=C["text3"], font=FT["small"],
                 justify="left").pack(pady=(12, 14))

        Btn(inner, "  Entendi, já anotei as palavras  ", self.destroy).pack(fill="x")
        self.bind("<Return>", lambda e: self.destroy())

class OpenVaultDlg(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.title("Abrir cofre")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 460, 270
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")
        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=22)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="Abrir cofre", bg=C["bg"],
                 fg=C["text"], font=FT["h2"]).pack(anchor="w", pady=(0, 16))

        tk.Label(inner, text="Arquivo .vault", bg=C["bg"],
                 fg=C["text2"], font=FT["small"]).pack(anchor="w")
        row = tk.Frame(inner, bg=C["bg"])
        row.pack(fill="x", pady=(4, 14))
        self.path_v = tk.StringVar()
        Entry(row, var=self.path_v, width=32).pack(side="left", ipady=7)
        Btn(row, "…", self._browse, kind="ghost", padx=10).pack(
            side="left", padx=(6, 0))

        tk.Label(inner, text="Passphrase", bg=C["bg"],
                 fg=C["text2"], font=FT["small"]).pack(anchor="w")
        self.pp_v = tk.StringVar()
        pf, pe = PasswordField(inner, self.pp_v, C["bg"])
        pf.pack(fill="x", pady=(4, 20))
        pe.bind("<Return>", lambda e: self._open())

        Btn(inner, "  Abrir cofre  ", self._open).pack(fill="x")
        self.bind("<Escape>", lambda e: self.destroy())

    def _browse(self):
        p = filedialog.askopenfilename(
            filetypes=[("Vault", "*.vault"), ("Todos", "*.*")])
        if p:
            self.path_v.set(p)

    def _open(self):
        path = self.path_v.get().strip()
        pp = self.pp_v.get()
        if not path or not pp:
            messagebox.showerror("Erro", "Preencha todos os campos.")
            return
        self.destroy()
        ld = LoadingDlg(self.app.root, "Derivando chave…")
        def work():
            try:
                from core.vault import open_vault_with_passphrase
                contents, kdf_key = open_vault_with_passphrase(pp, path)
                self.app.root.after(0, lambda: (ld.close(),
                    self.app.enter_vault(path, pp, contents, kdf_key)))
            except ValueError as ex:
                msg = str(ex)
                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Não foi possível abrir o cofre", msg)))
            except FileNotFoundError as ex:
                msg = str(ex)
                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Arquivo não encontrado", msg)))
            except Exception as ex:
                from core.filelock import VaultLockError
                if isinstance(ex, VaultLockError):
                    msg = str(ex)
                    self.app.root.after(0, lambda: (ld.close(),
                        messagebox.showerror("Cofre em uso", msg)))
                else:
                    self.app.root.after(0, lambda: (ld.close(),
                        messagebox.showerror("Erro inesperado",
                            "Não foi possível abrir o cofre. Verifique o arquivo e tente novamente.")))
        threading.Thread(target=work, daemon=True).start()

class RecoverFileScreen(Screen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._build()

    def _build(self):
        self._back_btn()
        self._title("🔑", "Recuperar cofre",
                    "Use o arquivo .vaultkey + PIN para recuperar o acesso")
        Sep(self, C["border"]).pack(fill="x", padx=24, pady=10)
        _, inner = self._scrollable_body()

        def file_row(label, var, types):
            tk.Label(inner, text=label, bg=C["bg"],
                     fg=C["text2"], font=FT["small"]).pack(
                         padx=28, anchor="w", pady=(0, 4))
            row = tk.Frame(inner, bg=C["bg"])
            row.pack(padx=28, fill="x", pady=(0, 12))
            Entry(row, var=var, width=38).pack(side="left", ipady=7)
            Btn(row, "…",
                lambda t=types, v=var: v.set(
                    filedialog.askopenfilename(
                        filetypes=t + [("Todos", "*.*")]) or v.get()),
                kind="ghost", padx=10).pack(side="left", padx=(6, 0))

        self.vault_v = tk.StringVar()
        self.key_v   = tk.StringVar()
        file_row("Arquivo .vault",    self.vault_v, [("Vault", "*.vault")])
        file_row("Arquivo .vaultkey", self.key_v,   [("Vaultkey", "*.vaultkey")])

        tk.Label(inner, text="PIN de proteção do .vaultkey",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        self.pin_v = tk.StringVar()
        pf, _ = PasswordField(inner, self.pin_v, C["bg"])
        pf.pack(padx=28, fill="x", pady=(0, 18))

        Sep(inner, C["border"]).pack(padx=28, fill="x", pady=(0, 14))
        self._section_label(inner, "NOVA PASSPHRASE PARA O COFRE")

        self.new_pp_v = tk.StringVar()
        pf2, _ = PasswordField(inner, self.new_pp_v, C["bg"])
        pf2.pack(padx=28, fill="x", pady=(4, 2))
        sf, self._str_fn = strength_bar(inner, 0, C["bg"])
        sf.pack(padx=28, fill="x")
        self.warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                 fg=C["yellow"], font=FT["small"])
        self.warn_lbl.pack(padx=28, anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self.new_pp_v, self._str_fn, self.warn_lbl)

        tk.Label(inner, text="Confirmar nova passphrase",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        self.new_pp2_v = tk.StringVar()
        pf3, _ = PasswordField(inner, self.new_pp2_v, C["bg"])
        pf3.pack(padx=28, fill="x", pady=(0, 20))

        Sep(inner, C["border"]).pack(padx=28, fill="x", pady=(0, 14))
        self._section_label(inner, "NOVO PIN PARA O ARQUIVO .vaultkey",
                            "Defina um PIN diferente do antigo, especialmente se ele "
                            "pode ter sido comprometido.")
        self.new_pin_v = tk.StringVar()
        pf4, _ = PasswordField(inner, self.new_pin_v, C["bg"])
        pf4.pack(padx=28, fill="x", pady=(4, 2))
        sf_pin, self._pin_str_fn = strength_bar(inner, 0, C["bg"])
        sf_pin.pack(padx=28, fill="x")
        self.pin_warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                     fg=C["yellow"], font=FT["small"])
        self.pin_warn_lbl.pack(padx=28, anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self.new_pin_v, self._pin_str_fn, self.pin_warn_lbl)

        tk.Label(inner, text="Confirmar novo PIN",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        self.new_pin2_v = tk.StringVar()
        pf5, _ = PasswordField(inner, self.new_pin2_v, C["bg"])
        pf5.pack(padx=28, fill="x", pady=(0, 20))

        Btn(inner, "  Recuperar e redefinir passphrase  ",
            self._recover).pack(padx=28, fill="x", pady=(0, 36))

    def _recover(self):
        vault_p  = self.vault_v.get().strip()
        key_p    = self.key_v.get().strip()
        pin      = self.pin_v.get()
        new_pp   = self.new_pp_v.get()
        new_pp2  = self.new_pp2_v.get()
        new_pin  = self.new_pin_v.get()
        new_pin2 = self.new_pin2_v.get()

        if not vault_p or not key_p or not pin:
            messagebox.showerror("Erro", "Preencha todos os campos."); return
        if not new_pp:
            messagebox.showerror("Erro", "Digite a nova passphrase."); return
        if new_pp != new_pp2:
            messagebox.showerror("Erro", "Passphrases não coincidem."); return
        if not new_pin:
            messagebox.showerror("Erro", "Digite o novo PIN do .vaultkey."); return
        if len(new_pin) < MIN_PIN_LENGTH:
            messagebox.showerror("PIN muito curto",
                f"O novo PIN do .vaultkey deve ter pelo menos {MIN_PIN_LENGTH} caracteres.")
            return
        if new_pin != new_pin2:
            messagebox.showerror("Erro", "Os novos PINs não coincidem."); return

        try:
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(new_pp)
            if r["bits"] < 40:
                if not messagebox.askyesno("Passphrase fraca",
                        f"Entropia: {r['bits']} bits. Continuar mesmo assim?"):
                    return
        except Exception:
            pass

        ld = LoadingDlg(self.app.root, "Recuperando cofre…")
        def work():
            try:
                from core.vault import open_vault_with_recovery_file, rotate_master_key
                contents, old_kdf = open_vault_with_recovery_file(key_p, vault_p, pin)
                from core.crypto import secure_zero
                secure_zero(old_kdf)

                new_mnemonic, new_vaultkey = rotate_master_key(
                    old_passphrase=None,
                    new_passphrase=new_pp,
                    vault_path=vault_p,
                    vaultkey_pin=new_pin,
                    contents=contents,
                )

                vaultkey_path = vault_p.replace(".vault", ".vaultkey")
                write_vaultkey_file(vaultkey_path, new_vaultkey)

                from core.vault import open_vault_with_passphrase
                contents2, kdf_key = open_vault_with_passphrase(new_pp, vault_p)

                def _done():
                    ld.close()
                    # [N-02] Exibe o NOVO mnemônico gerado pela rotação — antes
                    # esse valor era descartado (`_, new_vaultkey = ...`) e o
                    # usuário terminava a recuperação sem nunca ver/anotar as
                    # novas 24 palavras, mesmo com tudo dando certo.
                    MnemonicDlg(self.app.root, new_mnemonic, vaultkey_path)
                    self.app.enter_vault(vault_p, new_pp, contents2, kdf_key)
                self.app.root.after(0, _done)
            except ValueError as ex:
                msg = str(ex)
                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Recuperação falhou",
                        f"{msg}\n\nVerifique o PIN e os arquivos selecionados.")))
            except Exception:
                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Erro",
                        "Falha ao recuperar o cofre.\n"
                        "Verifique se os arquivos .vault e .vaultkey são compatíveis.")))
        threading.Thread(target=work, daemon=True).start()

class RecoverWordsScreen(Screen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._build()

    def _build(self):
        self._back_btn()
        self._title("📝", "Recuperar com 24 palavras",
                    "Digite as 24 palavras BIP-39 na ordem correta")
        Sep(self, C["border"]).pack(fill="x", padx=24, pady=10)
        _, inner = self._scrollable_body()

        tk.Label(inner, text="Arquivo .vault", bg=C["bg"],
                 fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        row = tk.Frame(inner, bg=C["bg"])
        row.pack(padx=28, fill="x", pady=(0, 14))
        self.vault_v = tk.StringVar()
        Entry(row, var=self.vault_v, width=38).pack(side="left", ipady=7)
        Btn(row, "…",
            lambda: self.vault_v.set(
                filedialog.askopenfilename(
                    filetypes=[("Vault", "*.vault"), ("Todos", "*.*")]
                ) or self.vault_v.get()),
            kind="ghost", padx=10).pack(side="left", padx=(6, 0))

        tk.Label(inner, text="24 PALAVRAS DE RECUPERAÇÃO",
                 bg=C["bg"], fg=C["accent2"], font=FT["label"]).pack(
                     padx=28, anchor="w", pady=(0, 8))

        grid_outer = tk.Frame(inner, bg=C["border2"])
        grid_outer.pack(padx=28, fill="x", pady=(0, 14))
        grid_surface = tk.Frame(grid_outer, bg=C["surface"])
        grid_surface.pack(fill="x", padx=1, pady=1)
        g = tk.Frame(grid_surface, bg=C["surface"], padx=14, pady=14)
        g.pack(fill="x")

        self._word_vars = []
        self._word_entries = []
        for i in range(24):
            ri, ci = divmod(i, 6)
            cell = tk.Frame(g, bg=C["surface2"])
            cell.grid(row=ri, column=ci, padx=2, pady=2, sticky="ew")
            tk.Label(cell, text=f"{i+1:02d}", bg=C["surface2"],
                     fg=C["text3"], font=FT["label"], padx=6, pady=2).pack(anchor="w")
            v = tk.StringVar()
            e = tk.Entry(cell, textvariable=v,
                         bg=C["surface2"], fg=C["text"],
                         insertbackground=C["neon"],
                         relief="flat", font=FT["word"], width=10,
                         highlightthickness=0)
            e.pack(fill="x", ipady=4, padx=4)

            if i < 23:
                e.bind("<Return>", lambda ev, idx=i: self._focus_next_word(idx))
            self._word_vars.append(v)
            self._word_entries.append(e)
            g.columnconfigure(ci, weight=1)

            e.bind("<MouseWheel>",
                   lambda ev, c=g: c.master.master.master.event_generate(
                       "<MouseWheel>", delta=ev.delta), add="+")

        Sep(inner, C["border"]).pack(padx=28, fill="x", pady=(0, 14))
        self._section_label(inner, "NOVA PASSPHRASE PARA O COFRE")

        self.new_pp_v = tk.StringVar()
        pf, _ = PasswordField(inner, self.new_pp_v, C["bg"])
        pf.pack(padx=28, fill="x", pady=(4, 2))
        sf, self._str_fn = strength_bar(inner, 0, C["bg"])
        sf.pack(padx=28, fill="x")
        self.warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                 fg=C["yellow"], font=FT["small"])
        self.warn_lbl.pack(padx=28, anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self.new_pp_v, self._str_fn, self.warn_lbl)

        tk.Label(inner, text="Confirmar nova passphrase",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        self.new_pp2_v = tk.StringVar()
        pf2, _ = PasswordField(inner, self.new_pp2_v, C["bg"])
        pf2.pack(padx=28, fill="x", pady=(0, 20))

        Sep(inner, C["border"]).pack(padx=28, fill="x", pady=(0, 14))
        self._section_label(inner, "NOVO PIN PARA O ARQUIVO .vaultkey",
                            "Recomendado: diferente da passphrase principal.")
        self.new_pin_v = tk.StringVar()
        pf3, _ = PasswordField(inner, self.new_pin_v, C["bg"])
        pf3.pack(padx=28, fill="x", pady=(4, 2))
        sf_pin, self._pin_str_fn = strength_bar(inner, 0, C["bg"])
        sf_pin.pack(padx=28, fill="x")
        self.pin_warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                     fg=C["yellow"], font=FT["small"])
        self.pin_warn_lbl.pack(padx=28, anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self.new_pin_v, self._pin_str_fn, self.pin_warn_lbl)

        tk.Label(inner, text="Confirmar novo PIN",
                 bg=C["bg"], fg=C["text2"], font=FT["small"]).pack(
                     padx=28, anchor="w", pady=(0, 4))
        self.new_pin2_v = tk.StringVar()
        pf4, _ = PasswordField(inner, self.new_pin2_v, C["bg"])
        pf4.pack(padx=28, fill="x", pady=(0, 20))

        Btn(inner, "  Recuperar cofre  ",
            self._recover).pack(padx=28, fill="x", pady=(0, 36))

    def _focus_next_word(self, idx):
        try:
            self._word_entries[idx + 1].focus_set()
        except IndexError:
            pass

    def _recover(self):
        vault_p  = self.vault_v.get().strip()
        words    = [v.get().strip().lower() for v in self._word_vars]
        new_pp   = self.new_pp_v.get()
        new_pp2  = self.new_pp2_v.get()
        new_pin  = self.new_pin_v.get()
        new_pin2 = self.new_pin2_v.get()

        if not vault_p:
            messagebox.showerror("Erro", "Selecione o arquivo .vault."); return
        if any(not w for w in words):
            messagebox.showerror("Erro", "Preencha todas as 24 palavras."); return
        if not new_pp:
            messagebox.showerror("Erro", "Digite a nova passphrase."); return
        if new_pp != new_pp2:
            messagebox.showerror("Erro", "Passphrases não coincidem."); return
        if not new_pin:
            messagebox.showerror("Erro", "Digite o novo PIN do .vaultkey."); return
        if len(new_pin) < MIN_PIN_LENGTH:
            messagebox.showerror("PIN muito curto",
                f"O novo PIN do .vaultkey deve ter pelo menos {MIN_PIN_LENGTH} caracteres.")
            return
        if new_pin != new_pin2:
            messagebox.showerror("Erro", "Os novos PINs não coincidem."); return

        for i, w in enumerate(words, 1):
            if not w.isalpha():
                messagebox.showerror("Palavra inválida",
                    f"Palavra {i} contém caracteres inválidos.\n"
                    "Use apenas letras minúsculas sem acento.")
                return

        invalid_words = self._validate_bip39_words(words)
        if invalid_words:
            preview = ", ".join(f"{i}: '{w}'" for i, w in invalid_words[:4])
            messagebox.showerror("Palavras BIP-39 inválidas",
                f"As seguintes palavras não pertencem ao dicionário BIP-39:\n{preview}\n\n"
                "Verifique a ortografia e a ordem das palavras.")
            return

        try:
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(new_pp)
            if r["bits"] < 40:
                if not messagebox.askyesno("Passphrase fraca",
                        f"Entropia: {r['bits']} bits. Continuar?"):
                    return
        except Exception:
            pass

        phrase = " ".join(words)
        ld = LoadingDlg(self.app.root, "Verificando mnemônico…")
        def work():
            try:
                from core.vault import open_vault_with_mnemonic, rotate_master_key
                from core.crypto import secure_zero
                contents, old_kdf = open_vault_with_mnemonic(phrase, vault_p)
                secure_zero(old_kdf)

                new_mnemonic, new_vaultkey = rotate_master_key(
                    old_passphrase=None,
                    new_passphrase=new_pp,
                    vault_path=vault_p,
                    vaultkey_pin=new_pin,
                    contents=contents,
                )
                vaultkey_path = vault_p.replace(".vault", ".vaultkey")
                write_vaultkey_file(vaultkey_path, new_vaultkey)

                from core.vault import open_vault_with_passphrase
                contents2, kdf_key = open_vault_with_passphrase(new_pp, vault_p)

                def _done():
                    ld.close()
                    # [N-02] Exibe o NOVO mnemônico gerado pela rotação — antes
                    # esse valor era descartado (`_, new_vaultkey = ...`) e o
                    # usuário terminava a recuperação sem nunca ver/anotar as
                    # novas 24 palavras, mesmo com tudo dando certo.
                    MnemonicDlg(self.app.root, new_mnemonic, vaultkey_path)
                    self.app.enter_vault(vault_p, new_pp, contents2, kdf_key)
                self.app.root.after(0, _done)
            except Exception:

                self.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Recuperação falhou",
                        "Chave de recuperação inválida ou cofre corrompido.\n\n"
                        "Verifique:\n"
                        "• As 24 palavras estão na ordem correta?\n"
                        "• O arquivo .vault selecionado é o correto?\n"
                        "• Cada palavra é uma palavra BIP-39 válida em inglês?")))
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _validate_bip39_words(words: list) -> list:
        try:
            from mnemonic import Mnemonic
            wordlist = set(Mnemonic("english").wordlist)
            return [(i + 1, w) for i, w in enumerate(words) if w not in wordlist]
        except Exception:
            return []

class VaultScreen(tk.Frame):
    def __init__(self, parent, app, contents, vault_path, kdf_key=None):
        super().__init__(parent, bg=C["bg"])
        self.app        = app
        self.contents   = contents
        self.vault_path = vault_path

        self.kdf_key    = kdf_key
        self._search_active = False
        self._active_files_view = None

        self._IDLE_SECONDS = 600
        self._idle_timer   = None
        self._reset_idle_timer()
        self.bind_all("<Any-KeyPress>", self._on_activity, add="+")
        self.bind_all("<Any-Button>",   self._on_activity, add="+")

        self._build()
        self._set_nav_active(self._nav_senhas)
        self._topbar_title.config(text="Senhas")
        self._refresh()

    def _on_activity(self, event=None):
        self._reset_idle_timer()

    def _reset_idle_timer(self):
        if self._idle_timer:
            try:
                self.after_cancel(self._idle_timer)
            except Exception:
                pass
        try:
            self._idle_timer = self.after(self._IDLE_SECONDS * 1000, self._auto_lock)
        except Exception:
            pass

    def _wipe_secrets(self):
        from core.crypto import secure_zero
        if self.kdf_key is not None:
            secure_zero(self.kdf_key)
            self.kdf_key = None
        self.contents   = {}

    def _unbind_activity(self):
        # [N-06] bind_all registra o callback na janela raiz do Tk, não no
        # widget desta instância. Sem desfazer explicitamente, cada ciclo de
        # abrir/fechar cofre (incluindo auto-lock por inatividade) deixava
        # dois handlers "zumbis" acumulados permanentemente no root, cada um
        # referenciando uma VaultScreen já destruída. Chamado tanto em
        # _close() (fechamento manual) quanto em _auto_lock() (inatividade).
        try:
            self.unbind_all("<Any-KeyPress>")
            self.unbind_all("<Any-Button>")
        except Exception:
            pass

    def _auto_lock(self):

        if getattr(self.app, "_current", None) is not self:
            return
        self._unbind_activity()
        self._wipe_secrets()
        try:
            self.app.show_home()
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb
            mb.showinfo("Sessão expirada",
                "O cofre foi bloqueado por inatividade.\nDigite a passphrase para reabrir.")
        except Exception:
            pass

    def _build(self):

        sb_outer = tk.Frame(self, bg=C["border2"], width=202)
        sb_outer.pack(side="left", fill="y")
        sb_outer.pack_propagate(False)

        sidebar = tk.Frame(sb_outer, bg=C["surface"])
        sidebar.pack(fill="both", expand=True, padx=1, pady=0)

        tk.Frame(sidebar, bg=C["neon"], width=1).pack(side="right", fill="y")

        sb = tk.Frame(sidebar, bg=C["surface"])
        sb.pack(side="left", fill="both", expand=True)

        logo_f = tk.Frame(sb, bg=C["surface"])
        logo_f.pack(pady=(22, 0))
        tk.Label(logo_f, text="🔐", bg=C["surface"],
                 font=("Segoe UI Emoji", 22)).pack()
        tk.Label(sb, text="key_lock", bg=C["surface"],
                 fg=C["text"], font=FT["h2"]).pack()
        fname = os.path.basename(self.vault_path)
        tk.Label(sb, text=fname, bg=C["surface"],
                 fg=C["text3"], font=FT["label"]).pack(pady=(2, 18))

        Sep(sb, C["border"]).pack(fill="x", padx=12, pady=(0, 12))

        self._nav_senhas  = self._sb_nav(sb, "🔑  Senhas",            self._show_entries)
        self._nav_files   = self._sb_nav(sb, "📁  Arquivos",           self._show_files)
        self._nav_genpass = self._sb_nav(sb, "⊞  Gerar senha",        self._show_genpass)
        self._nav_rekey   = self._sb_nav(sb, "↻  Rotacionar chaves",  self._show_rekey)
        Sep(sb, C["border"]).pack(fill="x", padx=12, pady=8)
        self._sb_btn(sb, "× Fechar cofre",        self._close)

        spacer = tk.Frame(sb, bg=C["surface"])
        spacer.pack(fill="both", expand=True)

        main = tk.Frame(self, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)

        topbar = tk.Frame(main, bg=C["bg"])
        topbar.pack(fill="x", padx=24, pady=(20, 8))
        self._topbar_title = tk.Label(topbar, text="Entradas", bg=C["bg"],
                 fg=C["text"], font=FT["h2"])
        self._topbar_title.pack(side="left")
        self._count_lbl = tk.Label(
            topbar, text="0",
            bg=C["accent3"], fg=C["neon"],
            font=FT["label"], padx=8, pady=3)
        self._count_lbl.pack(side="left", padx=(10, 0))

        # Contador de arquivos (exibido na topbar quando aba Arquivos está ativa)
        self._files_count_lbl = tk.Label(
            topbar, text="0",
            bg=C["accent3"], fg=C["neon"],
            font=FT["label"], padx=8, pady=3)
        # Não empacotado aqui — empacotado em _show_files

        self._add_row = tk.Frame(main, bg=C["bg"])
        self._add_row.pack(fill="x", padx=24, pady=(0, 8))
        Btn(self._add_row, "  + Nova entrada  ", self._add_entry).pack(side="left")

        self._search_row = tk.Frame(main, bg=C["bg"])
        sf = self._search_row
        sf.pack(fill="x", padx=24, pady=(0, 10))
        search_outer = tk.Frame(sf, bg=C["border"])
        search_outer.pack(side="left", fill="x", expand=True)
        search_inner = tk.Frame(search_outer, bg=C["surface2"])
        search_inner.pack(fill="x", padx=1, pady=1)

        self._search_v = tk.StringVar()
        self._search_v.trace_add("write", self._on_search_change)
        self._search_entry = tk.Entry(
            search_inner, textvariable=self._search_v,
            bg=C["surface2"], fg=C["text3"],
            insertbackground=C["neon"],
            relief="flat", font=FT["body"],
            highlightthickness=0)
        self._search_entry.pack(side="left", fill="x", expand=True,
                                padx=14, ipady=8)
        tk.Label(search_inner, text="⌕", bg=C["surface2"],
                 fg=C["text3"], font=FT["body"]).pack(side="right", padx=10)

        _ph = "Buscar por nome, usuário ou URL…"
        def _ph_in(e):
            self._search_active = True
            if self._search_v.get() == _ph:
                self._search_entry.delete(0, "end")
                self._search_entry.config(fg=C["text"])
        def _ph_out(e):
            if not self._search_v.get():
                self._search_active = False
                self._search_entry.insert(0, _ph)
                self._search_entry.config(fg=C["text3"])
        self._search_entry.insert(0, _ph)
        self._search_entry.bind("<FocusIn>",  _ph_in)
        self._search_entry.bind("<FocusOut>", _ph_out)
        self._placeholder = _ph

        lf = tk.Frame(main, bg=C["bg"])
        lf.pack(fill="both", expand=True, padx=(24, 0), pady=(0, 16))
        sb2 = _styled_scrollbar(lf)
        sb2.pack(side="right", fill="y", padx=0)
        self._canvas = tk.Canvas(lf, bg=C["bg"], highlightthickness=0,
                                 yscrollcommand=sb2.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        sb2.config(command=self._canvas.yview)
        self._list_frame = tk.Frame(self._canvas, bg=C["bg"])
        self._win_id = self._canvas.create_window(
            0, 0, window=self._list_frame, anchor="nw")
        self._list_frame.bind("<Configure>",
            lambda e: self._after_configure())
        self._canvas.bind("<Configure>",
            lambda e: (self._canvas.itemconfig(self._win_id, width=e.width),
                       self._after_configure()))
        self._canvas.bind("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))
        self._list_frame.bind("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._files_frame  = tk.Frame(main, bg=C["bg"])
        self._genpass_frame = tk.Frame(main, bg=C["bg"])
        self._rekey_frame   = tk.Frame(main, bg=C["bg"])

        self._main_frame = lf

        self.winfo_toplevel().bind("<Control-n>", lambda e: self._add_entry())
        self.winfo_toplevel().bind("<Control-w>", lambda e: self._close())

    def _after_configure(self):
        self._canvas.update_idletasks()
        bbox = self._canvas.bbox("all")
        if bbox:

            ch = self._canvas.winfo_height()
            x1, y1, x2, y2 = bbox
            y2 = max(y2, ch)
            self._canvas.configure(scrollregion=(x1, 0, x2, y2))

    def _sb_nav(self, parent, text, cmd):
        bg_idle = C["surface"]
        bg_act  = C["accent3"]
        fg_idle = C["text2"]
        fg_act  = C["neon"]
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg_idle, fg=fg_idle,
                      activebackground=C["accent3"],
                      activeforeground=fg_act,
                      relief="flat", cursor="hand2",
                      font=FT["small"],
                      padx=12, pady=8, bd=0, anchor="w")
        b.pack(fill="x", padx=12, pady=2)
        b._bg_idle = bg_idle
        b._bg_act  = bg_act
        b._fg_idle = fg_idle
        b._fg_act  = fg_act
        b.bind("<Enter>", lambda e: b.config(
            bg=b._bg_act if getattr(b, "_active", False) else C["surface3"]))
        b.bind("<Leave>", lambda e: b.config(
            bg=b._bg_act if getattr(b, "_active", False) else b._bg_idle))
        return b

    def _set_nav_active(self, active_btn):
        for btn in (self._nav_senhas, self._nav_files):
            is_active = (btn is active_btn)
            btn._active = is_active
            btn.config(
                bg=btn._bg_act  if is_active else btn._bg_idle,
                fg=btn._fg_act  if is_active else btn._fg_idle,
            )

    def _sb_btn(self, parent, text, cmd, primary=False):
        bg  = C["accent"]  if primary else C["surface"]
        hov = C["accent2"] if primary else C["surface3"]
        fg  = "#ffffff"    if primary else C["text2"]
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg, fg=fg,
                      activebackground=hov, activeforeground=fg,
                      relief="flat", cursor="hand2",
                      font=FT["small"],
                      padx=12, pady=7, bd=0, anchor="w")
        b.pack(fill="x", padx=12, pady=3)
        b.bind("<Enter>", lambda e: b.config(bg=hov))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    def _on_search_change(self, *_):

        if self._search_active:
            self._refresh()

    def _refresh(self):
        for w in self._list_frame.winfo_children():
            w.destroy()

        self._canvas.update_idletasks()
        self._canvas.yview_moveto(0)
        self._after_configure()
        for w in self._list_frame.winfo_children():
            w.destroy()

        entries = self.contents.get("entries", [])
        self._count_lbl.config(text=str(len(entries)))

        q = self._search_v.get().lower() if self._search_active else ""

        if q == self._placeholder.lower():
            q = ""

        if q:
            shown = [e for e in entries
                     if q in e.get("name", "").lower()
                     or q in e.get("username", "").lower()
                     or q in e.get("url", "").lower()]
        else:
            shown = list(entries)

        if not shown:
            msg = ("Nenhum resultado para esta busca." if q
                   else "Nenhuma entrada.\nCtrl+N para adicionar.")
            tk.Label(self._list_frame, text=msg,
                     bg=C["bg"], fg=C["text3"],
                     font=FT["body"], justify="center").pack(pady=48)
            return

        for entry in shown:
            self._entry_row(entry)

    def _entry_row(self, entry):
        row_outer = tk.Frame(self._list_frame, bg=C["border"], pady=0)
        row_outer.pack(fill="x", pady=2)
        row = tk.Frame(row_outer, bg=C["surface"], cursor="hand2")
        row.pack(fill="x", padx=1, pady=1)
        inn = tk.Frame(row, bg=C["surface"], padx=14, pady=11)
        inn.pack(fill="x")

        ic = tk.Label(inn, text="🔑", bg=C["surface"],
                      font=("Segoe UI Emoji", 18))
        ic.pack(side="left", padx=(0, 12))

        info = tk.Frame(inn, bg=C["surface"])
        info.pack(side="left", fill="x", expand=True)
        tk.Label(info, text=entry.get("name", ""), bg=C["surface"],
                 fg=C["text"], font=FT["h3"]).pack(anchor="w")
        tk.Label(info, text=entry.get("username", ""), bg=C["surface"],
                 fg=C["text2"], font=FT["small"]).pack(anchor="w")
        if entry.get("url"):
            tk.Label(info, text=entry["url"], bg=C["surface"],
                     fg=C["text3"], font=FT["label"]).pack(anchor="w")

        btns = tk.Frame(inn, bg=C["surface"])
        btns.pack(side="right")

        def _icon_btn(parent, text, cmd, danger=False):
            fg_ = C["red"] if danger else C["text3"]
            hov = C["red"] if danger else C["neon"]
            b = tk.Button(parent, text=text, command=cmd,
                          bg=C["surface"], fg=fg_,
                          relief="flat", cursor="hand2",
                          font=FT["small"], padx=8, pady=4, bd=0,
                          activebackground=C["surface3"],
                          activeforeground=hov)
            b.pack(side="left", padx=1)
            b.bind("<Enter>", lambda e: b.config(fg=hov))
            b.bind("<Leave>", lambda e: b.config(fg=fg_))
            return b

        _icon_btn(btns, "⎘ Copiar",  lambda e=entry: self._copy_pw(e))
        _icon_btn(btns, "◉ Ver",     lambda e=entry: self._view_entry(e))
        _icon_btn(btns, "⊗ Deletar", lambda e=entry: self._del_entry(e), danger=True)

        _n, _h = C["surface"], C["surface3"]
        def _enter(ev):
            for w in _all_widgets(row):
                try:
                    if w.cget("bg") in (_n, C["surface"]):
                        w.config(bg=_h)
                except Exception:
                    pass
        def _leave(ev):
            for w in _all_widgets(row):
                try:
                    if w.cget("bg") == _h:
                        w.config(bg=_n)
                except Exception:
                    pass
        row.bind("<Enter>", _enter)
        row.bind("<Leave>", _leave)

        for w in _all_widgets(row):
            try:
                w.bind("<MouseWheel>",
                       lambda e: self._canvas.yview_scroll(
                           -1 * (e.delta // 120), "units"), add="+")
            except Exception:
                pass

    def _hide_all_panels(self):
        """Oculta todos os painéis de conteúdo e controles contextuais."""
        for f in (self._files_frame, self._genpass_frame, self._rekey_frame):
            if f.winfo_ismapped():
                f.pack_forget()
            for w in f.winfo_children():
                w.destroy()
        self._files_count_lbl.pack_forget()
        self._add_row.pack_forget()
        self._search_row.pack_forget()
        self._main_frame.pack_forget()
        self._active_files_view = None

    def _show_entries(self):
        self._set_nav_active(self._nav_senhas)
        self._hide_all_panels()
        self._topbar_title.config(text="Senhas")
        self._count_lbl.pack(side="left", padx=(10, 0))
        self._add_row.pack(fill="x", padx=24, pady=(0, 8))
        self._search_row.pack(fill="x", padx=24, pady=(0, 10))
        self._main_frame.pack(fill="both", expand=True, padx=(24, 0), pady=(0, 16))
        self._refresh()

    def _show_files(self):
        self._set_nav_active(self._nav_files)
        self._hide_all_panels()
        self._count_lbl.pack_forget()
        self._topbar_title.config(text="Arquivos")

        n_files = len(self.contents.get("files", []))
        self._files_count_lbl.config(text=str(n_files))
        self._files_count_lbl.pack(side="left", padx=(10, 0))

        self._files_frame.pack(fill="both", expand=True, padx=(24, 0), pady=(0, 16))
        fv = _FilesView(self._files_frame, self)
        fv.pack(fill="both", expand=True)
        self._active_files_view = fv

    def _copy_pw(self, entry):
        _clipboard_copy(self, entry["password"],
                        label=f"Senha de '{entry.get('name', '')}'")

    def _view_entry(self, entry):
        EntryViewDlg(self.app.root, entry, self._copy_pw)

    def _del_entry(self, entry):
        if messagebox.askyesno("Confirmar exclusão",
                               f"Deletar a entrada '{entry.get('name', '')}'?"):
            from core.vault import delete_entry, save_vault_with_key
            self.contents = delete_entry(self.contents, entry["id"])
            save_vault_with_key(self.contents, self.kdf_key, self.vault_path)
            self._refresh()

    def _add_entry(self):
        AddEntryDlg(self.app.root, self._on_added)

    def _on_added(self, name, user, pw, url):
        from core.vault import add_entry, save_vault_with_key
        self.contents = add_entry(self.contents, name, user, pw, url)
        save_vault_with_key(self.contents, self.kdf_key, self.vault_path)
        self._refresh()

    def _show_genpass(self):
        self._set_nav_active(self._nav_genpass)
        self._hide_all_panels()
        self._count_lbl.pack_forget()
        self._topbar_title.config(text="Gerar senha")
        self._genpass_frame.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        _InlineGenpass(self._genpass_frame).pack(fill="both", expand=True)

    def _show_rekey(self):
        self._set_nav_active(self._nav_rekey)
        self._hide_all_panels()
        self._count_lbl.pack_forget()
        self._topbar_title.config(text="Rotacionar chaves")
        self._rekey_frame.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        _InlineRekey(self._rekey_frame, self).pack(fill="both", expand=True)

    def _close(self):

        if self._idle_timer:
            try:
                self.after_cancel(self._idle_timer)
            except Exception:
                pass
            self._idle_timer = None
        self._unbind_activity()
        self._wipe_secrets()
        self.app.show_welcome()



class _InlineGenpass(tk.Frame):
    """Gerador de senhas inline — exibido dentro do painel principal do VaultScreen."""

    def __init__(self, parent):
        super().__init__(parent, bg=C["bg"])
        self._build()

    def _build(self):
        inner = tk.Frame(self, bg=C["bg"])
        inner.pack(fill="x", pady=(8, 0))

        sr = tk.Frame(inner, bg=C["bg"])
        sr.pack(fill="x", pady=(0, 14))
        tk.Label(sr, text="Tamanho:", bg=C["bg"],
                 fg=C["text2"], font=FT["body"]).pack(side="left")
        self._len_v = tk.IntVar(value=20)
        self._len_v.trace_add("write", lambda *_: self._regen())
        slider = tk.Scale(sr, variable=self._len_v, from_=8, to=64,
                          orient="horizontal",
                          bg=C["bg"], fg=C["text"],
                          troughcolor=C["surface2"],
                          highlightthickness=0, sliderrelief="flat",
                          activebackground=C["neon"],
                          length=320, showvalue=False)
        slider.pack(side="left", padx=(10, 8))
        self._len_lbl = tk.Label(sr, text="20", bg=C["bg"],
                                  fg=C["neon"], font=FT["h3"], width=3)
        self._len_lbl.pack(side="left")

        opt_r = tk.Frame(inner, bg=C["bg"])
        opt_r.pack(fill="x", pady=(0, 16))
        self._upper_v   = tk.BooleanVar(value=True)
        self._digits_v  = tk.BooleanVar(value=True)
        self._symbols_v = tk.BooleanVar(value=True)
        for txt, var in [("Maiúsculas (A-Z)", self._upper_v),
                         ("Números (0-9)",    self._digits_v),
                         ("Símbolos (!@#)",   self._symbols_v)]:
            tk.Checkbutton(opt_r, text=txt, variable=var,
                           bg=C["bg"], fg=C["text2"],
                           selectcolor=C["surface2"],
                           activebackground=C["bg"],
                           activeforeground=C["text"],
                           font=FT["small"],
                           command=self._regen).pack(side="left", padx=(0, 18))

        res_outer = tk.Frame(inner, bg=C["border"])
        res_outer.pack(fill="x", pady=(0, 6))
        res_f = tk.Frame(res_outer, bg=C["surface2"])
        res_f.pack(fill="x", padx=1, pady=1)
        self._pw_v = tk.StringVar()
        tk.Label(res_f, textvariable=self._pw_v,
                 bg=C["surface2"], fg=C["neon"],
                 font=(_FONT_MONO, 16, "bold"),
                 padx=18, pady=20, anchor="center").pack(fill="x", expand=True)

        self._ent_lbl = tk.Label(inner, text="", bg=C["bg"],
                                  fg=C["text3"], font=FT["small"])
        self._ent_lbl.pack(anchor="w", pady=(4, 16))

        btn_r = tk.Frame(inner, bg=C["bg"])
        btn_r.pack(fill="x")
        Btn(btn_r, "  Gerar nova senha  ", self._regen).pack(side="left")
        Btn(btn_r, "  Copiar  ", self._copy, kind="ghost").pack(side="left", padx=(10, 0))

        self._regen()

    def _regen(self, *_):
        try:
            length = self._len_v.get()
            self._len_lbl.config(text=str(length))
            from core.crypto import generate_password, estimate_passphrase_entropy
            pw = generate_password(
                length=length,
                use_upper=self._upper_v.get(),
                use_digits=self._digits_v.get(),
                use_symbols=self._symbols_v.get(),
            )
            self._pw_v.set(pw)
            r = estimate_passphrase_entropy(pw, machine_generated=True)
            self._ent_lbl.config(text=f"Entropia: {r['bits']} bits — {r['strength']}")
        except Exception as ex:
            print(f"[key_lock] _InlineGenpass._regen: {ex}", file=sys.stderr)
            self._pw_v.set("— erro —")

    def _copy(self):
        pw = self._pw_v.get()
        if pw and pw != "— erro —":
            _clipboard_copy(self, pw, label="Senha gerada")


class _InlineRekey(tk.Frame):
    """Rotacionador de chaves inline — exibido dentro do painel principal do VaultScreen."""

    def __init__(self, parent, vault_screen: "VaultScreen"):
        super().__init__(parent, bg=C["bg"])
        self._vs = vault_screen
        self._build()

    def _build(self):
        tk.Label(self,
                 text="Gera nova passphrase, novo salt Argon2id e novo mnemônico de recuperação.\n"
                      "Cópias antigas do cofre ficam inutilizáveis após esta operação.",
                 bg=C["bg"], fg=C["text3"], font=FT["small"],
                 justify="left", wraplength=560).pack(anchor="w", pady=(4, 16))

        Sep(self, C["border"]).pack(fill="x", pady=(0, 16))

        inner = tk.Frame(self, bg=C["bg"])
        inner.pack(fill="x")

        def _lbl(t):
            tk.Label(inner, text=t, bg=C["bg"], fg=C["text2"],
                     font=FT["small"]).pack(anchor="w", pady=(0, 4))

        _lbl("Passphrase atual (para confirmar identidade)")
        self._old_pp_v = tk.StringVar()
        pf0, _ = PasswordField(inner, self._old_pp_v, C["bg"])
        pf0.pack(fill="x", pady=(0, 12))

        _lbl("Nova passphrase")
        self._new_pp_v = tk.StringVar()
        pf1, _ = PasswordField(inner, self._new_pp_v, C["bg"])
        pf1.pack(fill="x", pady=(0, 2))
        sf, self._str_fn = strength_bar(inner, 0, C["bg"])
        sf.pack(fill="x")
        self._warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                   fg=C["yellow"], font=FT["small"])
        self._warn_lbl.pack(anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self._new_pp_v, self._str_fn, self._warn_lbl)

        _lbl("Confirmar nova passphrase")
        self._new_pp2_v = tk.StringVar()
        pf2, _ = PasswordField(inner, self._new_pp2_v, C["bg"])
        pf2.pack(fill="x", pady=(0, 12))

        _lbl("PIN para o novo arquivo .vaultkey")
        self._pin_v = tk.StringVar()
        pf3, _ = PasswordField(inner, self._pin_v, C["bg"])
        pf3.pack(fill="x", pady=(0, 2))
        sf_pin, self._pin_str_fn = strength_bar(inner, 0, C["bg"])
        sf_pin.pack(fill="x")
        self._pin_warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                       fg=C["yellow"], font=FT["small"])
        self._pin_warn_lbl.pack(anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self._pin_v, self._pin_str_fn, self._pin_warn_lbl)

        _lbl("Confirmar PIN do .vaultkey")
        self._pin2_v = tk.StringVar()
        pf4, _ = PasswordField(inner, self._pin2_v, C["bg"])
        pf4.pack(fill="x", pady=(0, 20))

        Sep(self, C["border"]).pack(fill="x", pady=(0, 16))
        Btn(self, "  Rotacionar agora  ", self._do).pack(anchor="w")

    def _do(self):
        old_pp  = self._old_pp_v.get()
        new_pp  = self._new_pp_v.get()
        new_pp2 = self._new_pp2_v.get()
        pin     = self._pin_v.get()
        pin2    = self._pin2_v.get()

        if not old_pp:
            messagebox.showerror("Erro", "Digite a passphrase atual."); return
        if not new_pp:
            messagebox.showerror("Erro", "Digite a nova passphrase."); return
        if new_pp != new_pp2:
            messagebox.showerror("Erro", "Novas passphrases não coincidem."); return
        if not pin:
            messagebox.showerror("Erro", "O PIN do .vaultkey não pode ser vazio."); return
        if len(pin) < MIN_PIN_LENGTH:
            messagebox.showerror("PIN muito curto",
                f"O PIN do arquivo de recuperação deve ter pelo menos {MIN_PIN_LENGTH} "
                "caracteres.\nEsse PIN é a única proteção do arquivo .vaultkey caso ele "
                "seja roubado.")
            return
        if pin != pin2:
            messagebox.showerror("Erro", "Os PINs do .vaultkey não coincidem."); return

        try:
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(new_pp)
            if r["bits"] < 40:
                if not messagebox.askyesno("Passphrase fraca",
                        f"Entropia: {r['bits']} bits. Continuar mesmo assim?"):
                    return
        except Exception:
            pass

        if not messagebox.askyesno("Confirmar rotação",
                "Esta operação irá:\n\n"
                "  • Alterar a passphrase do cofre\n"
                "  • Gerar um novo arquivo .vaultkey\n"
                "  • Invalidar a chave de recuperação antiga\n\n"
                "Tem certeza que deseja continuar?"):
            return

        ld = LoadingDlg(self._vs.app.root, "Rotacionando credenciais  (Argon2id 256 MB)…")

        def work():
            try:
                from core.vault import rotate_master_key, open_vault_with_passphrase
                new_mnemonic, new_vaultkey_content = rotate_master_key(
                    old_pp, new_pp, self._vs.vault_path, pin
                )
                vaultkey_path = self._vs.vault_path.replace(".vault", ".vaultkey")
                write_vaultkey_file(vaultkey_path, new_vaultkey_content)

                new_contents, new_kdf_key = open_vault_with_passphrase(
                    new_pp, self._vs.vault_path
                )

                def _done():
                    ld.close()
                    from core.crypto import secure_zero
                    if self._vs.kdf_key is not None:
                        secure_zero(self._vs.kdf_key)
                    self._vs.kdf_key  = new_kdf_key
                    self._vs.contents = new_contents
                    MnemonicDlg(self._vs.app.root, new_mnemonic, vaultkey_path)
                    _toast(self._vs, "  Credenciais rotacionadas com sucesso  ", ms=3500)
                    # Voltar para a aba de senhas após rotação bem-sucedida
                    self._vs._show_entries()

                self._vs.app.root.after(0, _done)
            except ValueError as ex:
                self._vs.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Rotação falhou",
                        f"Passphrase atual incorreta ou cofre corrompido.\n\n{ex}")))
            except Exception as ex:
                self._vs.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Erro", str(ex))))

        threading.Thread(target=work, daemon=True).start()


class RekeyDlg(tk.Toplevel):
    def __init__(self, parent, vault_screen: "VaultScreen"):
        super().__init__(parent)
        self._vs = vault_screen
        self.title("Rotacionar credenciais do cofre")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 500, 540
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        footer = tk.Frame(self, bg=C["surface"], padx=28, pady=12)
        footer.pack(side="bottom", fill="x")
        tk.Frame(footer, bg=C["border"], height=1).pack(fill="x", pady=(0, 12))
        Btn(footer, "  Rotacionar agora  ", self._do).pack(fill="x")

        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=20)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="↻  Rotacionar credenciais", bg=C["bg"],
                 fg=C["text"], font=FT["h2"]).pack(anchor="w")
        tk.Label(inner,
                 text="Gera nova passphrase, novo salt Argon2id e novo mnemônico de recuperação.\n"
                      "Cópias antigas do cofre ficam inutilizáveis após esta operação.",
                 bg=C["bg"], fg=C["text3"], font=FT["small"],
                 justify="left", wraplength=440).pack(anchor="w", pady=(4, 16))

        Sep(inner, C["border"]).pack(fill="x", pady=(0, 14))

        def _lbl(t): tk.Label(inner, text=t, bg=C["bg"], fg=C["text2"],
                               font=FT["small"]).pack(anchor="w", pady=(0, 4))

        _lbl("Passphrase atual (para confirmar identidade)")
        self._old_pp_v = tk.StringVar()
        pf0, _ = PasswordField(inner, self._old_pp_v, C["bg"])
        pf0.pack(fill="x", pady=(0, 12))

        _lbl("Nova passphrase")
        self._new_pp_v = tk.StringVar()
        pf1, _ = PasswordField(inner, self._new_pp_v, C["bg"])
        pf1.pack(fill="x", pady=(0, 2))
        sf, self._str_fn = strength_bar(inner, 0, C["bg"])
        sf.pack(fill="x")
        self._warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                   fg=C["yellow"], font=FT["small"])
        self._warn_lbl.pack(anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self._new_pp_v, self._str_fn, self._warn_lbl)

        _lbl("Confirmar nova passphrase")
        self._new_pp2_v = tk.StringVar()
        pf2, _ = PasswordField(inner, self._new_pp2_v, C["bg"])
        pf2.pack(fill="x", pady=(0, 12))

        _lbl("PIN para o novo arquivo .vaultkey")
        self._pin_v = tk.StringVar()
        pf3, _ = PasswordField(inner, self._pin_v, C["bg"])
        pf3.pack(fill="x", pady=(0, 2))
        sf_pin, self._pin_str_fn = strength_bar(inner, 0, C["bg"])
        sf_pin.pack(fill="x")
        self._pin_warn_lbl = tk.Label(inner, text="", bg=C["bg"],
                                       fg=C["yellow"], font=FT["small"])
        self._pin_warn_lbl.pack(anchor="w", pady=(0, 8))
        _bind_strength_meter(self, self._pin_v, self._pin_str_fn, self._pin_warn_lbl)

        _lbl("Confirmar PIN do .vaultkey")
        self._pin2_v = tk.StringVar()
        pf4, _ = PasswordField(inner, self._pin2_v, C["bg"])
        pf4.pack(fill="x", pady=(0, 0))

        self.bind("<Escape>", lambda e: self.destroy())

    def _do(self):
        old_pp  = self._old_pp_v.get()
        new_pp  = self._new_pp_v.get()
        new_pp2 = self._new_pp2_v.get()
        pin     = self._pin_v.get()
        pin2    = self._pin2_v.get()

        if not old_pp:
            messagebox.showerror("Erro", "Digite a passphrase atual."); return
        if not new_pp:
            messagebox.showerror("Erro", "Digite a nova passphrase."); return
        if new_pp != new_pp2:
            messagebox.showerror("Erro", "Novas passphrases não coincidem."); return
        if not pin:
            messagebox.showerror("Erro", "O PIN do .vaultkey não pode ser vazio."); return
        if len(pin) < MIN_PIN_LENGTH:
            messagebox.showerror("PIN muito curto",
                f"O PIN do arquivo de recuperação deve ter pelo menos {MIN_PIN_LENGTH} "
                "caracteres.\nEsse PIN é a única proteção do arquivo .vaultkey caso ele "
                "seja roubado.")
            return
        if pin != pin2:
            messagebox.showerror("Erro", "Os PINs do .vaultkey não coincidem."); return

        try:
            from core.crypto import estimate_passphrase_entropy
            r = estimate_passphrase_entropy(new_pp)
            if r["bits"] < 40:
                if not messagebox.askyesno("Passphrase fraca",
                        f"Entropia: {r['bits']} bits. Continuar mesmo assim?"):
                    return
        except Exception:
            pass

        if not messagebox.askyesno("Confirmar rotação",
                "Esta operação irá:\n\n"
                "  • Alterar a passphrase do cofre\n"
                "  • Gerar um novo arquivo .vaultkey\n"
                "  • Invalidar a chave de recuperação antiga\n\n"
                "Tem certeza que deseja continuar?"):
            return

        self.destroy()
        ld = LoadingDlg(self._vs.app.root, "Rotacionando credenciais  (Argon2id 256 MB)…")

        def work():
            try:
                from core.vault import rotate_master_key, open_vault_with_passphrase
                new_mnemonic, new_vaultkey_content = rotate_master_key(
                    old_pp, new_pp, self._vs.vault_path, pin
                )
                vaultkey_path = self._vs.vault_path.replace(".vault", ".vaultkey")
                write_vaultkey_file(vaultkey_path, new_vaultkey_content)

                new_contents, new_kdf_key = open_vault_with_passphrase(
                    new_pp, self._vs.vault_path
                )

                def _done():
                    ld.close()
                    from core.crypto import secure_zero
                    if self._vs.kdf_key is not None:
                        secure_zero(self._vs.kdf_key)
                    self._vs.kdf_key    = new_kdf_key
                    self._vs.contents   = new_contents
                    MnemonicDlg(self._vs.app.root, new_mnemonic, vaultkey_path)
                    _toast(self._vs, "  Credenciais rotacionadas com sucesso  ", ms=3500)

                self._vs.app.root.after(0, _done)
            except ValueError as ex:
                self._vs.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Rotação falhou",
                        f"Passphrase atual incorreta ou cofre corrompido.\n\n{ex}")))
            except Exception as ex:
                self._vs.app.root.after(0, lambda: (ld.close(),
                    messagebox.showerror("Erro", str(ex))))

        threading.Thread(target=work, daemon=True).start()

def _all_widgets(w):
    result = [w]
    try:
        for child in w.winfo_children():
            result.extend(_all_widgets(child))
    except Exception:
        pass
    return result

class EntryViewDlg(tk.Toplevel):
    def __init__(self, parent, entry, copy_cb):
        super().__init__(parent)
        self.title(entry.get("name", "Entrada"))
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 460, 340
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")
        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=22)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text=f"🔑  {entry.get('name', '')}", bg=C["bg"],
                 fg=C["text"], font=FT["h2"]).pack(anchor="w", pady=(0, 16))

        def _field(lbl, val):
            tk.Label(inner, text=lbl, bg=C["bg"],
                     fg=C["text2"], font=FT["label"]).pack(anchor="w")
            f = tk.Frame(inner, bg=C["surface2"])
            f.pack(fill="x", pady=(2, 12))
            tk.Label(f, text=val, bg=C["surface2"], fg=C["text"],
                     font=FT["body"], padx=12, pady=7, anchor="w").pack(fill="x")

        _field("Usuário / Email", entry.get("username", ""))
        if entry.get("url"):
            _field("URL", entry["url"])

        tk.Label(inner, text="Senha", bg=C["bg"],
                 fg=C["text2"], font=FT["label"]).pack(anchor="w")
        pw_frame = tk.Frame(inner, bg=C["surface2"])
        pw_frame.pack(fill="x", pady=(2, 16))
        pw = entry.get("password", "")
        self._pw_v = tk.StringVar(value="●" * len(pw))
        tk.Label(pw_frame, textvariable=self._pw_v,
                 bg=C["surface2"], fg=C["text"],
                 font=FT["mono"], padx=12, pady=7).pack(side="left", fill="x", expand=True)
        eye = tk.Button(pw_frame, text="◉",
                        bg=C["surface2"], fg=C["text3"],
                        relief="flat", cursor="hand2", padx=10,
                        font=FT["small"], bd=0,
                        activebackground=C["surface3"],
                        activeforeground=C["neon"])
        eye.pack(side="right")
        eye.bind("<ButtonPress-1>",   lambda e: self._pw_v.set(pw))
        eye.bind("<ButtonRelease-1>", lambda e: self._pw_v.set("●" * len(pw)))

        row = tk.Frame(inner, bg=C["bg"])
        row.pack(fill="x")
        Btn(row, "  Copiar senha  ",
            lambda: copy_cb(entry)).pack(side="left")
        Btn(row, "Fechar", self.destroy, kind="ghost").pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

class AddEntryDlg(tk.Toplevel):
    def __init__(self, parent, callback):
        super().__init__(parent)
        self.callback = callback
        self.title("Nova entrada")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 480, 470
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        footer = tk.Frame(self, bg=C["surface"], padx=28, pady=12)
        footer.pack(side="bottom", fill="x")
        tk.Frame(footer, bg=C["border"], height=1).pack(fill="x", pady=(0, 12))
        Btn(footer, "  Salvar entrada  ", self._save).pack(fill="x")

        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=20)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="Nova entrada", bg=C["bg"],
                 fg=C["text"], font=FT["h2"]).pack(anchor="w", pady=(0, 18))

        def txt_field(lbl, placeholder=""):
            tk.Label(inner, text=lbl, bg=C["bg"],
                     fg=C["text2"], font=FT["small"]).pack(anchor="w", pady=(0, 4))
            v = tk.StringVar()
            e = Entry(inner, var=v, width=44)
            e.pack(fill="x", ipady=7, pady=(0, 12))
            if placeholder:
                e.insert(0, placeholder)
                e.config(fg=C["text3"])
                e.bind("<FocusIn>", lambda ev, _e=e, _v=v: (
                    (_v.set("") or _e.config(fg=C["text"]))
                    if _e.get() == placeholder else None))
            return v

        self.name_v = txt_field("Nome", "ex: GitHub")
        self.user_v = txt_field("Usuário / Email")
        self.url_v  = txt_field("URL (opcional)", "https://")

        tk.Label(inner, text="Senha", bg=C["bg"],
                 fg=C["text2"], font=FT["small"]).pack(anchor="w", pady=(0, 4))
        pw_row = tk.Frame(inner, bg=C["bg"])
        pw_row.pack(fill="x")
        self.pw_v = tk.StringVar()
        self._pw_e = tk.Entry(pw_row, textvariable=self.pw_v,
                              show="●", bg=C["surface2"], fg=C["text"],
                              insertbackground=C["neon"],
                              relief="flat", font=FT["mono"], width=26,
                              highlightthickness=1,
                              highlightbackground=C["border"],
                              highlightcolor=C["neon"])
        self._pw_e.pack(side="left", ipady=7)
        eye = tk.Button(pw_row, text="◉",
                        bg=C["surface2"], fg=C["text3"],
                        relief="flat", cursor="hand2", padx=8,
                        font=FT["small"], bd=0,
                        activebackground=C["surface3"],
                        activeforeground=C["neon"])
        eye.pack(side="left")
        eye.bind("<ButtonPress-1>",   lambda e: self._pw_e.config(show=""))
        eye.bind("<ButtonRelease-1>", lambda e: self._pw_e.config(show="●"))

        Btn(pw_row, "⊞ Gerar", self._gen_pw, kind="ghost",
            padx=10).pack(side="left", padx=(6, 0))
        self.bind("<Escape>", lambda e: self.destroy())

    def _gen_pw(self):
        try:
            from core.crypto import generate_password
            pw = generate_password()
            self.pw_v.set(pw)
            self._pw_e.config(show="")
            _clipboard_copy(self, pw, label="Senha gerada")
        except Exception as ex:
            print(f"[key_lock] _gen_pw error: {ex}", file=sys.stderr)

    def _save(self):
        name = self.name_v.get().strip()
        user = self.user_v.get().strip()
        pw   = self.pw_v.get()
        url  = self.url_v.get().strip()

        if url in ("https://", ""):
            url = ""
        if name in ("ex: GitHub", ""):
            name = ""
        if not name or not user or not pw:
            messagebox.showerror("Erro", "Nome, usuário e senha são obrigatórios.")
            return
        self.callback(name, user, pw, url)
        self.destroy()

class GenpassDlg(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Gerador de Senhas")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        w, h = 480, 360
        rx = parent.winfo_rootx() + parent.winfo_width() // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")
        inner = tk.Frame(self, bg=C["bg"], padx=28, pady=20)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="Gerador de Senhas", bg=C["bg"],
                 fg=C["text"], font=FT["h2"]).pack(anchor="w", pady=(0, 16))

        sr = tk.Frame(inner, bg=C["bg"])
        sr.pack(fill="x", pady=(0, 12))
        tk.Label(sr, text="Tamanho:", bg=C["bg"],
                 fg=C["text2"], font=FT["body"]).pack(side="left")
        self._len_v = tk.IntVar(value=20)
        self._len_v.trace_add("write", lambda *_: self._regen())
        slider = tk.Scale(sr, variable=self._len_v, from_=8, to=64,
                          orient="horizontal",
                          bg=C["bg"], fg=C["text"],
                          troughcolor=C["surface2"],
                          highlightthickness=0,
                          sliderrelief="flat",
                          activebackground=C["neon"],
                          length=260, showvalue=False)
        slider.pack(side="left", padx=(8, 6))
        self._len_lbl = tk.Label(sr, text="20", bg=C["bg"],
                                  fg=C["neon"], font=FT["h3"], width=3)
        self._len_lbl.pack(side="left")

        opt_r = tk.Frame(inner, bg=C["bg"])
        opt_r.pack(fill="x", pady=(0, 14))
        self._upper_v   = tk.BooleanVar(value=True)
        self._digits_v  = tk.BooleanVar(value=True)
        self._symbols_v = tk.BooleanVar(value=True)
        for txt, var in [("A-Z", self._upper_v),
                         ("0-9", self._digits_v),
                         ("!@#", self._symbols_v)]:
            tk.Checkbutton(opt_r, text=txt, variable=var,
                           bg=C["bg"], fg=C["text2"],
                           selectcolor=C["surface2"],
                           activebackground=C["bg"],
                           activeforeground=C["text"],
                           font=FT["small"],
                           command=self._regen).pack(side="left", padx=(0, 14))

        res_f = tk.Frame(inner, bg=C["surface2"])
        res_f.pack(fill="x", pady=(0, 6))
        self._pw_v = tk.StringVar()
        tk.Label(res_f, textvariable=self._pw_v,
                 bg=C["surface2"], fg=C["neon"],
                 font=(_FONT_MONO, 14, "bold"),
                 padx=14, pady=13, anchor="center").pack(fill="x", expand=True)

        self._ent_lbl = tk.Label(inner, text="", bg=C["bg"],
                                  fg=C["text3"], font=FT["label"])
        self._ent_lbl.pack(anchor="w", pady=(0, 14))

        btn_r = tk.Frame(inner, bg=C["bg"])
        btn_r.pack(fill="x")
        Btn(btn_r, "  Gerar nova  ", self._regen).pack(side="left")
        Btn(btn_r, "  Copiar  ", self._copy, kind="ghost").pack(side="left", padx=(8, 0))
        Btn(btn_r, "Fechar", self.destroy, kind="ghost").pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

        self._regen()

    def _regen(self, *_):
        try:
            length = self._len_v.get()
            self._len_lbl.config(text=str(length))
            from core.crypto import generate_password, estimate_passphrase_entropy
            pw = generate_password(
                length=length,
                use_upper=self._upper_v.get(),
                use_digits=self._digits_v.get(),
                use_symbols=self._symbols_v.get(),
            )
            self._pw_v.set(pw)

            r = estimate_passphrase_entropy(pw, machine_generated=True)
            self._ent_lbl.config(text=f"Entropia: {r['bits']} bits — {r['strength']}")
        except Exception as ex:
            print(f"[key_lock] GenpassDlg._regen: {ex}", file=sys.stderr)
            self._pw_v.set("— erro —")

    def _copy(self):
        pw = self._pw_v.get()
        if pw and pw != "— erro —":
            _clipboard_copy(self, pw, label="Senha gerada")

class GenpassScreen(Screen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._build()

    def _build(self):
        self._back_btn()
        self._title("🎲", "Gerador de Senhas",
                    "Criptograficamente seguro — módulo secrets do Python")
        Sep(self, C["border"]).pack(fill="x", padx=24, pady=10)

        inner = tk.Frame(self, bg=C["bg"])
        inner.pack(padx=32, fill="x")

        sr = tk.Frame(inner, bg=C["bg"])
        sr.pack(fill="x", pady=(0, 12))
        tk.Label(sr, text="Tamanho:", bg=C["bg"],
                 fg=C["text2"], font=FT["body"]).pack(side="left")
        self._len_v = tk.IntVar(value=20)
        self._len_v.trace_add("write", lambda *_: self._regen())
        slider = tk.Scale(sr, variable=self._len_v, from_=8, to=64,
                          orient="horizontal",
                          bg=C["bg"], fg=C["text"],
                          troughcolor=C["surface2"],
                          highlightthickness=0, sliderrelief="flat",
                          activebackground=C["neon"],
                          length=280, showvalue=False)
        slider.pack(side="left", padx=(8, 6))
        self._len_lbl = tk.Label(sr, text="20", bg=C["bg"],
                                  fg=C["neon"], font=FT["h3"], width=3)
        self._len_lbl.pack(side="left")

        opt_r = tk.Frame(inner, bg=C["bg"])
        opt_r.pack(fill="x", pady=(0, 16))
        self._upper_v   = tk.BooleanVar(value=True)
        self._digits_v  = tk.BooleanVar(value=True)
        self._symbols_v = tk.BooleanVar(value=True)
        for txt, var in [("Maiúsculas (A-Z)", self._upper_v),
                         ("Números (0-9)",    self._digits_v),
                         ("Símbolos (!@#)",   self._symbols_v)]:
            tk.Checkbutton(opt_r, text=txt, variable=var,
                           bg=C["bg"], fg=C["text2"],
                           selectcolor=C["surface2"],
                           activebackground=C["bg"],
                           font=FT["small"],
                           command=self._regen).pack(side="left", padx=(0, 16))

        res_outer = tk.Frame(inner, bg=C["border"])
        res_outer.pack(fill="x", pady=(0, 6))
        res_f = tk.Frame(res_outer, bg=C["surface2"])
        res_f.pack(fill="x", padx=1, pady=1)
        self._pw_v = tk.StringVar()
        tk.Label(res_f, textvariable=self._pw_v,
                 bg=C["surface2"], fg=C["neon"],
                 font=(_FONT_MONO, 16, "bold"),
                 padx=18, pady=18, anchor="center").pack(fill="x", expand=True)

        self._ent_lbl = tk.Label(inner, text="", bg=C["bg"],
                                  fg=C["text3"], font=FT["small"])
        self._ent_lbl.pack(anchor="w", pady=(0, 16))

        btn_r = tk.Frame(inner, bg=C["bg"])
        btn_r.pack(fill="x")
        Btn(btn_r, "  Gerar nova senha  ", self._regen).pack(side="left")
        Btn(btn_r, "  Copiar  ", self._copy, kind="ghost").pack(side="left", padx=(8, 0))

        self._regen()

    def _regen(self, *_):
        try:
            length = self._len_v.get()
            self._len_lbl.config(text=str(length))
            from core.crypto import generate_password, estimate_passphrase_entropy
            pw = generate_password(
                length=length,
                use_upper=self._upper_v.get(),
                use_digits=self._digits_v.get(),
                use_symbols=self._symbols_v.get(),
            )
            self._pw_v.set(pw)

            r = estimate_passphrase_entropy(pw, machine_generated=True)
            self._ent_lbl.config(text=f"Entropia: {r['bits']} bits — {r['strength']}")
        except Exception as ex:
            print(f"[key_lock] GenpassScreen._regen: {ex}", file=sys.stderr)
            self._pw_v.set("— erro —")

    def _copy(self):
        pw = self._pw_v.get()
        if pw and pw != "— erro —":
            _clipboard_copy(self, pw, label="Senha gerada")

class FileViewDlg(tk.Toplevel):
    _TEXT_EXT = {"txt","md","csv","json","xml","log","py","js","ts","html",
                 "htm","css","sh","yaml","yml","ini","cfg","toml","sql"}
    _IMG_EXT  = {"png","jpg","jpeg","gif","bmp","webp"}

    def __init__(self, parent, filename: str, data: bytes):
        super().__init__(parent)
        self.title(f"Visualizar — {filename}")
        self.configure(bg=C["bg"])
        self.grab_set()
        w, h = 760, 560
        rx = parent.winfo_rootx() + parent.winfo_width()  // 2 - w // 2
        ry = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"{w}x{h}+{rx}+{ry}")
        self.resizable(True, True)
        self.minsize(500, 360)

        tk.Frame(self, bg=C["neon"], height=1).pack(fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        hdr = tk.Frame(self, bg=C["bg"], padx=20, pady=12)
        hdr.pack(fill="x")
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        icon = ("🖼" if ext in self._IMG_EXT else
                "📝" if ext in self._TEXT_EXT else "📎")
        tk.Label(hdr, text=f"{icon}  {filename}", bg=C["bg"],
                 fg=C["text"], font=FT["h3"]).pack(side="left")
        size_txt = (f"{len(data)/1048576:.1f} MB" if len(data) >= 1048576
                    else f"{len(data)/1024:.1f} KB")
        tk.Label(hdr, text=size_txt, bg=C["bg"],
                 fg=C["text3"], font=FT["small"]).pack(side="right")

        Sep(self, C["border"]).pack(fill="x")

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=0, pady=0)

        if ext in self._IMG_EXT:
            self._show_image(body, data, ext)
        elif ext in self._TEXT_EXT:
            self._show_text(body, data)
        else:
            self._show_binary(body, filename, len(data))

        footer = tk.Frame(self, bg=C["surface"], padx=20, pady=10)
        footer.pack(fill="x", side="bottom")
        Btn(footer, "Fechar", self.destroy, kind="ghost").pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

    def _show_image(self, parent, data: bytes, ext: str):
        try:
            from PIL import Image, ImageTk
            import io
            img = Image.open(io.BytesIO(data))

            img.thumbnail((720, 480), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            lbl = tk.Label(parent, image=photo, bg=C["bg"])
            lbl.image = photo
            lbl.pack(expand=True, pady=8)
        except ImportError:

            if ext == "png":
                try:
                    import base64 as _b64
                    photo = tk.PhotoImage(data=_b64.b64encode(data))
                    tk.Label(parent, image=photo, bg=C["bg"]).pack(expand=True, pady=8)
                    parent.image = photo
                    return
                except Exception:
                    pass
            tk.Label(parent,
                     text=f"Preview de imagem requer Pillow.\n\n"
                          f"  pip install Pillow\n\n"
                          f"Tamanho: {len(data)/1024:.1f} KB",
                     bg=C["bg"], fg=C["text3"], font=FT["body"],
                     justify="center").pack(expand=True)
        except Exception as ex:
            tk.Label(parent, text=f"Não foi possível exibir a imagem:\n{ex}",
                     bg=C["bg"], fg=C["text3"], font=FT["body"]).pack(expand=True)

    def _show_text(self, parent, data: bytes):
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                text_content = data.decode(enc)
                break
            except Exception:
                text_content = None
        if text_content is None:
            text_content = data.decode("utf-8", errors="replace")

        sb = _styled_scrollbar(parent)
        sb.pack(side="right", fill="y")
        txt = tk.Text(parent,
                      bg=C["surface2"], fg=C["text"],
                      font=FT["mono"], relief="flat",
                      wrap="none", yscrollcommand=sb.set,
                      insertbackground=C["neon"],
                      selectbackground=C["accent3"],
                      padx=16, pady=12,
                      highlightthickness=0)
        txt.pack(side="left", fill="both", expand=True)
        sb.config(command=txt.yview)

        hsb = tk.Scrollbar(parent, orient="horizontal", command=txt.xview,
                           bg=C["surface3"], troughcolor=C["bg"],
                           relief="flat", bd=0, width=6)
        hsb.pack(side="bottom", fill="x")
        txt.config(xscrollcommand=hsb.set)

        txt.insert("1.0", text_content)
        txt.config(state="disabled")

    def _show_binary(self, parent, filename: str, size: int):
        tk.Label(parent,
                 text=f"📎  {filename}\n\n"
                      f"Tamanho: {size/1024:.1f} KB\n\n"
                      f"Preview não disponível para este tipo de arquivo.\n"
                      f"Use 'Exportar' para abrir com o programa adequado.",
                 bg=C["bg"], fg=C["text3"], font=FT["body"],
                 justify="center").pack(expand=True)

class _FilesView(tk.Frame):
    _ICON = {
        "pdf":  "📄", "png": "🖼", "jpg": "🖼", "jpeg": "🖼",
        "gif":  "🖼", "mp4": "🎬", "mp3": "🎵", "zip": "🗜",
        "txt":  "📝", "md":  "📝", "doc": "📝", "docx": "📝",
        "xls":  "📊", "xlsx": "📊", "ppt": "📊", "pptx": "📊",
    }
    _MAX_FILE_MB = 20
    _NONCE_SIZE  = 12

    def __init__(self, parent, vault_screen: "VaultScreen"):
        super().__init__(parent, bg=C["bg"])
        self._vs = vault_screen
        self._build()

    def _build(self):

        act_row = tk.Frame(self, bg=C["bg"])
        act_row.pack(fill="x", pady=(0, 6))
        Btn(act_row, "  + Carregar arquivo  ", self._load_file).pack(side="left")
        self._status_lbl = tk.Label(act_row, text="", bg=C["bg"],
                                    fg=C["text3"], font=FT["small"])
        self._status_lbl.pack(side="left", padx=(14, 0))
        tk.Label(act_row, text="Cifrado com AES-256-GCM", bg=C["bg"],
                 fg=C["text3"], font=FT["label"]).pack(side="right")

        search_row = tk.Frame(self, bg=C["bg"])
        search_row.pack(fill="x", pady=(0, 8))
        search_inner = tk.Frame(search_row, bg=C["surface2"], padx=0)
        search_inner.pack(fill="x", side="left", expand=True)
        self._search_v = tk.StringVar()
        self._search_v.trace_add("write", lambda *_: self._redraw())
        self._search_entry = tk.Entry(search_inner, textvariable=self._search_v,
                                      bg=C["surface2"], fg=C["text"],
                                      insertbackground=C["text"],
                                      relief="flat", font=FT["body"], bd=0)
        self._search_entry.pack(side="left", fill="x", expand=True,
                                padx=14, ipady=8)
        tk.Label(search_inner, text="⌕", bg=C["surface2"],
                 fg=C["text3"], font=FT["body"]).pack(side="right", padx=10)
        _ph = "Buscar por nome…"
        def _ph_in(e):
            if self._search_v.get() == _ph:
                self._search_entry.delete(0, "end")
                self._search_entry.config(fg=C["text"])
        def _ph_out(e):
            if not self._search_v.get():
                self._search_entry.insert(0, _ph)
                self._search_entry.config(fg=C["text3"])
        self._search_entry.insert(0, _ph)
        self._search_entry.bind("<FocusIn>",  _ph_in)
        self._search_entry.bind("<FocusOut>", _ph_out)
        self._placeholder = _ph

        self._count_lbl = tk.Label(search_row, text="",
                                   bg=C["accent3"], fg=C["neon"],
                                   font=FT["label"], padx=8, pady=3)
        self._count_lbl.pack(side="left", padx=(8, 0))

        Sep(self, C["border"]).pack(fill="x", pady=(0, 10))

        list_outer = tk.Frame(self, bg=C["bg"])
        list_outer.pack(fill="both", expand=True)
        sb = _styled_scrollbar(list_outer)
        sb.pack(side="right", fill="y")
        self._canvas = tk.Canvas(list_outer, bg=C["bg"], highlightthickness=0,
                                 yscrollcommand=sb.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=C["bg"])
        _wid = self._canvas.create_window(0, 0, window=self._inner, anchor="nw")

        def _update_sr(e=None):
            self._canvas.update_idletasks()
            bbox = self._canvas.bbox("all")
            if bbox:
                ch = self._canvas.winfo_height()
                x1, y1, x2, y2 = bbox
                self._canvas.configure(scrollregion=(x1, 0, x2, max(y2, ch)))

        self._inner.bind("<Configure>", _update_sr)
        self._canvas.bind("<Configure>",
            lambda e: (self._canvas.itemconfig(_wid, width=e.width), _update_sr()))
        for w in (self._canvas, self._inner):
            w.bind("<MouseWheel>",
                   lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._redraw()

    def _get_aes_key(self) -> "tuple[bytearray, bool]":
        if self._vs.kdf_key is not None:
            return self._vs.kdf_key, False
        # kdf_key deve estar sempre disponível durante a sessão.
        # A passphrase não é mais armazenada na VaultScreen (B-01 fix).
        raise RuntimeError(
            "kdf_key não disponível. O cofre pode ter sido bloqueado por inatividade. "
            "Reabra o cofre para continuar."
        )

    def _decrypt_blob(self, entry: dict) -> bytearray:
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw   = base64.urlsafe_b64decode(entry["blob"].encode())
        nonce = raw[:self._NONCE_SIZE]
        ct    = raw[self._NONCE_SIZE:]
        aad   = (f"key_lock:file:{entry['id']}".encode()
                 if entry.get("aad_version", 0) >= 1 else None)
        key, was_derived = self._get_aes_key()
        try:
            return bytearray(AESGCM(key).decrypt(nonce, ct, aad))
        finally:
            if was_derived:
                from core.crypto import secure_zero
                secure_zero(key)

    def _get_files(self) -> list:
        return self._vs.contents.get("files", [])

    def _save(self):
        from core.vault import save_vault_with_key
        save_vault_with_key(self._vs.contents, self._vs.kdf_key, self._vs.vault_path)
        # Atualizar contador de arquivos na topbar
        try:
            n = len(self._vs.contents.get("files", []))
            self._vs._files_count_lbl.config(text=str(n))
        except Exception:
            pass

    def _search_term(self) -> str:
        val = self._search_v.get()
        return "" if val == self._placeholder else val.lower()

    def _load_file(self):
        from tkinter import filedialog
        import base64, uuid
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        path = filedialog.askopenfilename(title="Selecionar arquivo para cifrar e armazenar")
        if not path:
            return
        fname = os.path.basename(path)
        try:
            with open(path, "rb") as f:
                file_bytes = f.read()
        except Exception as ex:
            messagebox.showerror("Erro", f"Não foi possível ler o arquivo:\n{ex}")
            return

        limit = self._MAX_FILE_MB * 1024 * 1024
        if len(file_bytes) > limit:
            messagebox.showerror("Arquivo muito grande",
                f"O arquivo excede o limite de {self._MAX_FILE_MB} MB.\n"
                "Arquivos maiores devem ser comprimidos antes de importar.")
            return

        try:
            file_id = str(uuid.uuid4())
            aad     = f"key_lock:file:{file_id}".encode()
            nonce   = os.urandom(self._NONCE_SIZE)
            key, was_derived = self._get_aes_key()
            try:
                ct = AESGCM(key).encrypt(nonce, file_bytes, aad)
            finally:
                if was_derived:
                    from core.crypto import secure_zero
                    secure_zero(key)
            blob = base64.urlsafe_b64encode(nonce + ct).decode()
        except Exception as ex:
            messagebox.showerror("Erro de cifragem", str(ex))
            return

        entry = {
            "id":          file_id,
            "name":        fname,
            "size":        len(file_bytes),
            "blob":        blob,
            "aad_version": 1,
        }
        self._vs.contents.setdefault("files", []).append(entry)

        ld = LoadingDlg(self._vs.app.root, f"Cifrando e salvando {fname}…")
        def work():
            try:
                self._save()
                self._vs.app.root.after(0, lambda: (
                    ld.close(), self._redraw(),
                    self._status_lbl.config(text=f"✓ {fname} adicionado"),
                ))
            except Exception as ex:
                self._vs.contents["files"].pop()
                self._vs.app.root.after(0, lambda: (
                    ld.close(),
                    messagebox.showerror("Erro ao salvar", str(ex)),
                ))
        import threading
        threading.Thread(target=work, daemon=True).start()

    def _view_file(self, entry):
        plaintext = None
        try:
            plaintext = self._decrypt_blob(entry)
        except Exception as ex:
            messagebox.showerror("Erro ao decifrar", str(ex))
            return
        FileViewDlg(self._vs.app.root, entry["name"], bytes(plaintext))
        from core.crypto import secure_zero
        secure_zero(plaintext)

    def _export_file(self, entry):
        from tkinter import filedialog
        dest = filedialog.asksaveasfilename(
            initialfile=entry["name"],
            title="Salvar arquivo decifrado como…")
        if not dest:
            return
        plaintext = None
        try:
            plaintext = self._decrypt_blob(entry)
            with open(dest, "wb") as f:
                f.write(plaintext)
            _toast(self, f"  Arquivo salvo em {os.path.basename(dest)}")
        except Exception as ex:
            messagebox.showerror("Erro ao exportar", str(ex))
        finally:
            if plaintext is not None:
                from core.crypto import secure_zero
                secure_zero(plaintext)

    def _delete_file(self, entry):
        if not messagebox.askyesno("Remover arquivo",
                f"Remover '{entry['name']}' do cofre?\n"
                "O arquivo original no disco NÃO é afetado."):
            return
        self._vs.contents["files"] = [
            f for f in self._vs.contents.get("files", []) if f["id"] != entry["id"]
        ]
        try:
            self._save()
        except Exception as ex:
            messagebox.showerror("Erro ao salvar", str(ex))
        self._redraw()

    def _redraw(self):
        # Guard: _inner pode não existir se _build ainda não completou ou se o
        # widget foi destruído mas o trace_add ainda disparou (ex: recovery falha).
        if not hasattr(self, "_inner") or not self._inner.winfo_exists():
            return
        for w in self._inner.winfo_children():
            w.destroy()
        self._canvas.yview_moveto(0)

        term  = self._search_term()
        files = [f for f in self._get_files()
                 if not term or term in f.get("name", "").lower()]

        total = len(self._get_files())
        self._count_lbl.config(text=str(total))
        if total == 0:
            self._count_lbl.pack_forget()
        elif not self._count_lbl.winfo_ismapped():
            self._count_lbl.pack(side="left", padx=(8, 0))

        if not files:
            msg = ("Nenhum resultado para a busca."
                   if term else
                   "Nenhum arquivo armazenado.\nClique em '+ Carregar arquivo' para adicionar.")
            tk.Label(self._inner, text=msg, bg=C["bg"], fg=C["text3"],
                     font=FT["body"], justify="center").pack(pady=56)
            return

        for f in files:
            self._file_row(f)

    def _fmt_size(self, n: int) -> str:
        if n < 1024:    return f"{n} B"
        if n < 1048576: return f"{n/1024:.1f} KB"
        return f"{n/1048576:.1f} MB"

    def _file_icon(self, name: str) -> str:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return self._ICON.get(ext, "📎")

    def _file_row(self, entry):
        row_outer = tk.Frame(self._inner, bg=C["border"], pady=0)
        row_outer.pack(fill="x", pady=2)
        row = tk.Frame(row_outer, bg=C["surface"])
        row.pack(fill="x", padx=1, pady=1)
        inn = tk.Frame(row, bg=C["surface"], padx=14, pady=11)
        inn.pack(fill="x")

        tk.Label(inn, text=self._file_icon(entry["name"]),
                 bg=C["surface"], font=("Segoe UI Emoji", 18)).pack(side="left", padx=(0, 12))

        info = tk.Frame(inn, bg=C["surface"])
        info.pack(side="left", fill="x", expand=True)
        tk.Label(info, text=entry["name"], bg=C["surface"],
                 fg=C["text"], font=FT["h3"]).pack(anchor="w")
        tk.Label(info, text=self._fmt_size(entry.get("size", 0)),
                 bg=C["surface"], fg=C["text2"], font=FT["small"]).pack(anchor="w")

        btns = tk.Frame(inn, bg=C["surface"])
        btns.pack(side="right")

        def _ibtn(txt, cmd, danger=False):
            fg_ = C["red"] if danger else C["text3"]
            hov = C["red"] if danger else C["neon"]
            b = tk.Button(btns, text=txt, command=cmd,
                          bg=C["surface"], fg=fg_,
                          relief="flat", cursor="hand2",
                          font=FT["small"], padx=8, pady=4, bd=0,
                          activebackground=C["surface3"],
                          activeforeground=hov)
            b.pack(side="left", padx=1)
            b.bind("<Enter>", lambda e: b.config(fg=hov))
            b.bind("<Leave>", lambda e: b.config(fg=fg_))

        _ibtn("◉ Visualizar", lambda e=entry: self._view_file(e))
        _ibtn("⬇ Exportar",   lambda e=entry: self._export_file(e))
        _ibtn("⊗ Remover",    lambda e=entry: self._delete_file(e), danger=True)

        _n, _h = C["surface"], C["surface3"]
        def _enter(ev):
            for w in _all_widgets(row):
                try:
                    if w.cget("bg") in (_n, C["surface"]): w.config(bg=_h)
                except Exception:
                    pass
        def _leave(ev):
            for w in _all_widgets(row):
                try:
                    if w.cget("bg") == _h: w.config(bg=_n)
                except Exception:
                    pass
        row.bind("<Enter>", _enter)
        row.bind("<Leave>", _leave)
        for w in _all_widgets(row):
            try:
                w.bind("<MouseWheel>",
                       lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))
            except Exception:
                pass

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("key_lock")
        self.root.configure(bg=C["bg"])

        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        win_w = max(900, int(sw * 0.75))
        win_h = max(600, int(sh * 0.80))
        ox = (sw - win_w) // 2
        oy = (sh - win_h) // 2
        self.root.geometry(f"{win_w}x{win_h}+{ox}+{oy}")
        self.root.minsize(760, 520)
        self.root.resizable(True, True)

        s = ttk.Style()
        s.theme_use("default")
        s.configure("Vertical.TScrollbar",
                    troughcolor=C["bg"],
                    background=C["surface3"],
                    arrowcolor=C["text3"],
                    borderwidth=0)
        s.configure("KL.Horizontal.TProgressbar",
                    troughcolor=C["surface2"],
                    background=C["neon"],
                    borderwidth=0)

        self._current = None
        self.show_welcome()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_request)

    def _on_close_request(self):
        try:
            if isinstance(self._current, VaultScreen):
                self._current._wipe_secrets()
        except Exception:
            pass
        self.root.destroy()

    def _set(self, screen):
        if self._current:
            # [N-06] Rede de segurança adicional: se por algum motivo uma
            # VaultScreen for substituída sem passar por _close()/_auto_lock()
            # (ex: um novo caminho de transição adicionado no futuro), ainda
            # assim desfazemos os bind_all globais aqui, no único ponto por
            # onde toda troca de tela do app passa.
            if isinstance(self._current, VaultScreen):
                self._current._unbind_activity()
            self._current.destroy()
        self._current = screen
        screen.pack(fill="both", expand=True)

    def show_welcome(self):       self._set(WelcomeScreen(self.root, self))
    def show_home(self):          self._set(WelcomeScreen(self.root, self))
    def show_create(self):        self._set(CreateScreen(self.root, self))
    def show_genpass(self):       self._set(GenpassScreen(self.root, self))
    def open_vault_flow(self):    OpenVaultDlg(self.root, self)

    def show_recover(self, mode="file"):
        if mode == "file":
            self._set(RecoverFileScreen(self.root, self))
        else:
            self._set(RecoverWordsScreen(self.root, self))

    def enter_vault(self, vault_path, passphrase, contents=None, kdf_key=None):
        if contents is None:
            from core.vault import open_vault_with_passphrase
            contents, kdf_key = open_vault_with_passphrase(passphrase, vault_path)
        # Não armazenamos a passphrase na VaultScreen — apenas o kdf_key (bytearray, zeroizável)
        # A passphrase (str imutável) não pode ser zerada em Python; por isso não deve
        # persistir além do instante de abertura. O kdf_key cobre todas as operações de sessão.
        self._set(VaultScreen(self.root, self, contents, vault_path, kdf_key=kdf_key))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    App().run()
