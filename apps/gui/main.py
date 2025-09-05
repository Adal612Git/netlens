import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk


def _ensure_core_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    core_path = repo_root / "packages" / "core"
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))


_ensure_core_on_path()

from core import normalize_url, resolve_ip  # noqa: E402


def on_resolve(name_var: tk.StringVar, url_var: tk.StringVar, output: tk.Text) -> None:
    output.delete("1.0", tk.END)
    name = name_var.get().strip()
    url = url_var.get().strip()
    if not name or not url:
        output.insert(tk.END, "Por favor, completa Nombre y URL.\n")
        return
    try:
        host, port = normalize_url(url)
        ip = resolve_ip(host)
        output.insert(tk.END, f"{name}, {ip}, {port}\n")
    except Exception as exc:  # noqa: BLE001
        output.insert(tk.END, f"Error: {exc}\n")


def main() -> None:
    root = tk.Tk()
    root.title("NetLens – IP Extractor")

    mainframe = ttk.Frame(root, padding=10)
    mainframe.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))

    name_var = tk.StringVar()
    url_var = tk.StringVar()

    ttk.Label(mainframe, text="Nombre").grid(column=0, row=0, sticky=tk.W)
    name_entry = ttk.Entry(mainframe, width=40, textvariable=name_var)
    name_entry.grid(column=1, row=0, sticky=(tk.W, tk.E))

    ttk.Label(mainframe, text="URL").grid(column=0, row=1, sticky=tk.W)
    url_entry = ttk.Entry(mainframe, width=40, textvariable=url_var)
    url_entry.grid(column=1, row=1, sticky=(tk.W, tk.E))

    output = tk.Text(mainframe, width=50, height=5)
    output.grid(column=0, row=3, columnspan=2, pady=(8, 0))

    resolve_btn = ttk.Button(
        mainframe,
        text="Resolver",
        command=lambda: on_resolve(name_var, url_var, output),
    )
    resolve_btn.grid(column=0, row=2, columnspan=2, pady=(8, 0))

    for child in mainframe.winfo_children():
        child.grid_configure(padx=5, pady=5)

    name_entry.focus()
    root.mainloop()


if __name__ == "__main__":
    main()

