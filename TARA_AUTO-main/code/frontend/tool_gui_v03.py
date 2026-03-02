# tool2_gui.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path   # ✅ 이 줄 추가

DEFAULT_TOOL2_SCRIPT = "parse_attack_graph_final.py"
DEFAULT_OUT_JSON = "attack_graph.json"
DEFAULT_ASSET_MAP = "asset_to_threats.json"
DEFAULT_THREAT_MAP = "threat_to_tactic.json"


class Tool2GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        # Fixed backend + mapping files (user cannot change)
        self.base_dir = Path(__file__).resolve().parent
        self.fixed_tool2_script = self.base_dir / DEFAULT_TOOL2_SCRIPT
        self.fixed_asset_map = self.base_dir / DEFAULT_ASSET_MAP
        self.fixed_threat_map = self.base_dir / DEFAULT_THREAT_MAP
        self.title("Vehicle Threat Modeling - Attack Graph Generator (Tool-2)")
        self.geometry("820x520")
        self.minsize(780, 500)

        self.var_tm7 = tk.StringVar(value="")
        self.var_mode = tk.StringVar(value="Remote/Adjacent")
        self.var_target = tk.StringVar(value="")
        self.var_asset_map = tk.StringVar(value=str(self.fixed_asset_map))
        self.var_threat_map = tk.StringVar(value=str(self.fixed_threat_map))
        self.var_out_json = tk.StringVar(value=DEFAULT_OUT_JSON)
        self.var_max_depth = tk.StringVar(value="30")
        self.var_tool2_script = tk.StringVar(value=str(self.fixed_tool2_script))

        self._build_ui()

    # -----------------------------
    # UI
    # -----------------------------
    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

        # --- Banner (vehicle security themed) ---
        banner = ttk.Frame(root)
        banner.pack(fill="x", **pad)
        self._build_banner(banner)
        # Tool-2 backend script is fixed (hidden from UI)

        # --- Inputs ---
        row = ttk.LabelFrame(root, text="Inputs")
        row.pack(fill="x", **pad)

        ttk.Label(row, text=".tm7 파일").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        e = ttk.Entry(row, textvariable=self.var_tm7)
        e.grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(row, text="Browse", command=self._browse_tm7).grid(row=0, column=2, padx=8, pady=6)

        ttk.Label(row, text="모드").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        mode = ttk.Combobox(
            row,
            textvariable=self.var_mode,
            values=["Remote/Adjacent", "Local/Physical"],
            state="readonly",
            width=18,
        )
        mode.grid(row=1, column=1, sticky="w", padx=8, pady=6)

        ttk.Label(row, text="목표 자산명").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        e = ttk.Entry(row, textvariable=self.var_target)
        e.grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        row.columnconfigure(1, weight=1)

        # --- Optional mapping files + output ---
        row2 = ttk.LabelFrame(root, text="Mappings / Output (optional)")
        row2.pack(fill="x", **pad)
        # Mapping files are fixed (hidden from UI)

        ttk.Label(row2, text="출력 JSON").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        e = ttk.Entry(row2, textvariable=self.var_out_json)
        e.grid(row=2, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(row2, text="Browse", command=self._browse_out_json).grid(row=2, column=2, padx=8, pady=6)

        ttk.Label(row2, text="max depth").grid(row=3, column=0, sticky="w", padx=8, pady=6)
        e = ttk.Entry(row2, textvariable=self.var_max_depth, width=10)
        e.grid(row=3, column=1, sticky="w", padx=8, pady=6)

        row2.columnconfigure(1, weight=1)

        # --- Actions + Log ---
        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)

        self.btn_run = ttk.Button(actions, text="Run (Generate JSON)", command=self._run_clicked)
        self.btn_run.pack(side="left")

        ttk.Button(actions, text="Quit", command=self.destroy).pack(side="right")

        logf = ttk.LabelFrame(root, text="Log")
        logf.pack(fill="both", expand=True, **pad)

        self.txt_log = tk.Text(logf, height=10, wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=8, pady=8)
        self._log("Ready.\n")

    def _build_banner(self, parent: ttk.Frame):
        """
        Vehicle security themed banner using Canvas (no external image needed).
        """
        self.banner_canvas = tk.Canvas(parent, height=92, highlightthickness=0)
        self.banner_canvas.pack(fill="x", expand=True)

        self.banner_title = tk.StringVar(value="Vehicle Threat Modeling Automation")
        self.banner_sub = tk.StringVar(value="TM7 DFD → Attack Graph (In → Through → Out)")

        # Redraw on resize
        self.banner_canvas.bind("<Configure>", lambda e: self._draw_banner())

        # initial draw
        self.after(50, self._draw_banner)

    def _draw_banner(self):
        c = self.banner_canvas
        c.delete("all")
        w = max(c.winfo_width(), 1)
        h = max(c.winfo_height(), 1)

        # --- gradient background ---
        # (tkinter canvas doesn't do gradients natively; draw thin rectangles)
        steps = 40
        for i in range(steps):
            t = i / (steps - 1)
            # dark navy -> teal-ish
            r1, g1, b1 = (10, 24, 55)
            r2, g2, b2 = (0, 120, 140)
            r = int(r1 + (r2 - r1) * t)
            g = int(g1 + (g2 - g1) * t)
            b = int(b1 + (b2 - b1) * t)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y0 = int(i * h / steps)
            y1 = int((i + 1) * h / steps)
            c.create_rectangle(0, y0, w, y1, outline=color, fill=color)

        # subtle grid lines
        for x in range(0, w, 48):
            c.create_line(x, 0, x, h, fill="#20324f")
        for y in range(0, h, 24):
            c.create_line(0, y, w, y, fill="#20324f")

        # --- title/subtitle ---
        c.create_text(
            18, 22,
            anchor="w",
            text=self.banner_title.get(),
            fill="white",
            font=("Segoe UI", 16, "bold"),
        )
        c.create_text(
            18, 52,
            anchor="w",
            text=self.banner_sub.get(),
            fill="#d7f3ff",
            font=("Segoe UI", 10, "normal"),
        )

        # --- draw a simple car silhouette (right side) ---
        # car base coords relative to right
        cx = w - 220
        cy = 54

        # body
        body = [
            (cx - 80, cy + 10),
            (cx + 90, cy + 10),
            (cx + 110, cy - 2),
            (cx + 70, cy - 18),
            (cx - 10, cy - 18),
            (cx - 40, cy - 6),
            (cx - 80, cy - 6),
        ]
        c.create_polygon(body, fill="#eaf6ff", outline="#c5e6ff", width=2)

        # windows
        win = [
            (cx - 5, cy - 16),
            (cx + 55, cy - 16),
            (cx + 70, cy - 6),
            (cx - 20, cy - 6),
        ]
        c.create_polygon(win, fill="#0b1c33", outline="#c5e6ff", width=2)

        # wheels
        c.create_oval(cx - 55, cy + 2, cx - 25, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
        c.create_oval(cx + 55, cy + 2, cx + 85, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
        c.create_oval(cx - 47, cy + 10, cx - 33, cy + 24, fill="#eaf6ff", outline="")
        c.create_oval(cx + 63, cy + 10, cx + 77, cy + 24, fill="#eaf6ff", outline="")

        # --- lock icon overlay (security) ---
        lx = w - 70
        ly = 28
        # shackle
        c.create_arc(lx - 18, ly - 18, lx + 18, ly + 18, start=200, extent=140, style="arc", width=4, outline="#ffffff")
        # body
        c.create_rectangle(lx - 20, ly + 12, lx + 20, ly + 46, fill="#ffffff", outline="#ffffff")
        # keyhole
        c.create_oval(lx - 4, ly + 24, lx + 4, ly + 32, fill="#0b1c33", outline="#0b1c33")
        c.create_rectangle(lx - 2, ly + 32, lx + 2, ly + 40, fill="#0b1c33", outline="#0b1c33")

    # -----------------------------
    # browse helpers
    # -----------------------------
    def _browse_tm7(self):
        path = filedialog.askopenfilename(
            title="Select .tm7 file",
            filetypes=[("TM7 files", "*.tm7"), ("All files", "*.*")],
        )
        if path:
            self.var_tm7.set(path)

    def _browse_tool2_script(self):
        path = filedialog.askopenfilename(
            title="Select Tool-2 script (tool2_attack_graph.py)",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")],
        )
        if path:
            self.var_tool2_script.set(path)

    def _browse_asset_map(self):
        path = filedialog.askopenfilename(
            title="Select asset_to_threats.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.var_asset_map.set(path)

    def _browse_threat_map(self):
        path = filedialog.askopenfilename(
            title="Select threat_to_tactic.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.var_threat_map.set(path)

    def _browse_out_json(self):
        path = filedialog.asksaveasfilename(
            title="Save output JSON as...",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=self.var_out_json.get() or DEFAULT_OUT_JSON,
        )
        if path:
            self.var_out_json.set(path)

    # -----------------------------
    # logging
    # -----------------------------
    def _log(self, msg: str):
        self.txt_log.insert("end", msg)
        self.txt_log.see("end")

    def _set_running(self, running: bool):
        self.btn_run.config(state=("disabled" if running else "normal"))
        self.config(cursor=("watch" if running else ""))

    # -----------------------------
    # run
    # -----------------------------
    def _validate_inputs(self) -> bool:
        tm7 = self.var_tm7.get().strip()
        target = self.var_target.get().strip()
        mode = self.var_mode.get().strip()
        tool2_script = self.var_tool2_script.get().strip()

        if not tool2_script:
            messagebox.showerror("Missing", "Tool-2 스크립트 경로가 비어있습니다.")
            return False
        if not os.path.isfile(tool2_script):
            messagebox.showerror("Not found", f"Tool-2 스크립트를 찾을 수 없습니다:\n{tool2_script}")
            return False

        if not tm7:
            messagebox.showerror("Missing", ".tm7 파일을 선택해주세요.")
            return False
        if not os.path.isfile(tm7):
            messagebox.showerror("Not found", f".tm7 파일을 찾을 수 없습니다:\n{tm7}")
            return False

        if mode not in ("Remote/Adjacent", "Local/Physical"):
            messagebox.showerror("Invalid", "모드는 Remote/Adjacent 또는 Local/Physical 이어야 합니다.")
            return False

        if not target:
            messagebox.showerror("Missing", "목표 자산명을 입력해주세요.")
            return False

        try:
            d = int(self.var_max_depth.get().strip())
            if d <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid", "max depth는 1 이상의 정수여야 합니다.")
            return False

        asset_map = self.var_asset_map.get().strip()
        threat_map = self.var_threat_map.get().strip()
        if not asset_map or not os.path.isfile(asset_map):
            messagebox.showerror("Not found", f"asset_to_threats.json 경로가 유효하지 않습니다:\n{asset_map}")
            return False
        if not threat_map or not os.path.isfile(threat_map):
            messagebox.showerror("Not found", f"threat_to_tactic.json 경로가 유효하지 않습니다:\n{threat_map}")
            return False

        out_json = self.var_out_json.get().strip()
        if not out_json:
            messagebox.showerror("Missing", "출력 JSON 경로를 지정해주세요.")
            return False

        return True

    def _run_clicked(self):
        if not self._validate_inputs():
            return

        self._set_running(True)
        self._log("\n--- Running Tool-2 ---\n")
        t = threading.Thread(target=self._run_tool2_subprocess, daemon=True)
        t.start()

    def _run_tool2_subprocess(self):
        tool2_script = self.var_tool2_script.get().strip()
        tm7 = self.var_tm7.get().strip()
        mode = self.var_mode.get().strip()
        target = self.var_target.get().strip()
        asset_map = self.var_asset_map.get().strip()
        threat_map = self.var_threat_map.get().strip()
        out_json = self.var_out_json.get().strip()
        max_depth = self.var_max_depth.get().strip()

        cmd = [
            sys.executable,
            tool2_script,
            "--tm7", tm7,
            "--type", mode,
            "--target", target,
            "--asset-map", asset_map,
            "--threat-map", threat_map,
            "--max-depth", max_depth,
            "--out", out_json,
        ]

        workdir = os.path.dirname(os.path.abspath(tool2_script)) or None

        try:
            self._log("CMD:\n  " + " ".join(f'"{c}"' if " " in c else c for c in cmd) + "\n\n")

            proc = subprocess.Popen(
                cmd,
                cwd=workdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            out, err = proc.communicate()

            def done():
                if out:
                    self._log(out + ("\n" if not out.endswith("\n") else ""))
                if err:
                    self._log("\n[stderr]\n" + err + ("\n" if not err.endswith("\n") else ""))

                if proc.returncode == 0:
                    self._log(f"\n[OK] Output written: {out_json}\n")
                    messagebox.showinfo("Done", f"완료!\n출력 JSON:\n{out_json}")
                else:
                    self._log(f"\n[FAIL] return code: {proc.returncode}\n")
                    messagebox.showerror("Failed", f"실행 실패(return code={proc.returncode}).\n로그를 확인하세요.")

                self._set_running(False)

            self.after(0, done)

        except Exception as e:
            def fail():
                self._log(f"\n[EXCEPTION] {e}\n")
                self._set_running(False)
                messagebox.showerror("Exception", str(e))
            self.after(0, fail)


if __name__ == "__main__":
    # Windows DPI scaling
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore
    except Exception:
        pass

    app = Tool2GUI()
    app.mainloop()