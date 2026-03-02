# tool2_v9.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# ✅ parse_attack_graph_v17.py에 맞춘 고정 경로들
DEFAULT_TOOL2_SCRIPT = "../backend/parse_attack_graph_v17.py"

DEFAULT_ASSET_MAP = "../backend/threat_library/asset_to_threats_ver0.1.json"
DEFAULT_THREAT_MAP = "../backend/threat_library/threat_to_tactic.json"
DEFAULT_ATTACK_VECTOR_MAP = "../backend/threat_library/attack_vector_feasibility.json"
DEFAULT_DEPENDENCY_MAP = "../backend/threat_library/dependency.json"

# ✅ 출력 기본값(사용자가 GUI에서 변경 가능)
DEFAULT_OUT_JSON = "../out/attack_graph.json"
DEFAULT_MERGED_GRAPH_PREFIX = "../out/merged_attack_graph"   # 확장자 제외 prefix
DEFAULT_ATTACK_TREE_PNG = "../out/attack_tree.png"


class Tool2GUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # Fixed backend + mapping files (user cannot change)
        self.base_dir = Path(__file__).resolve().parent
        self.fixed_tool2_script = (self.base_dir / DEFAULT_TOOL2_SCRIPT).resolve()
        self.fixed_asset_map = (self.base_dir / DEFAULT_ASSET_MAP).resolve()
        self.fixed_threat_map = (self.base_dir / DEFAULT_THREAT_MAP).resolve()
        self.fixed_attack_vector_map = (self.base_dir / DEFAULT_ATTACK_VECTOR_MAP).resolve()
        self.fixed_dependency_map = (self.base_dir / DEFAULT_DEPENDENCY_MAP).resolve()

        self.title("Vehicle Threat Modeling - Attack Graph Generator (Tool-2)")
        self.geometry("880x620")
        self.minsize(860, 580)

        # Inputs
        self.var_tm7 = tk.StringVar(value="")
        self.var_mode = tk.StringVar(value="remote")  # remote/adjacent/local/physical
        self.var_target = tk.StringVar(value="")
        self.var_boundary = tk.StringVar(value="")

        # Outputs 3종 (사용자 입력)
        self.var_out_json = tk.StringVar(value=str((self.base_dir / DEFAULT_OUT_JSON).resolve()))

        # ✅ Attack Graph Image에서 format을 같이 입력받음 (prefix + format)
        self.var_attack_graph_image_path = tk.StringVar(
            value=str((self.base_dir / (DEFAULT_MERGED_GRAPH_PREFIX + ".png")).resolve())
        )

        self.var_attack_tree_png = tk.StringVar(value=str((self.base_dir / DEFAULT_ATTACK_TREE_PNG).resolve()))

        # Advanced
        self.var_max_depth = tk.StringVar(value="30")
        self.var_attack_tree_no_reverse = tk.BooleanVar(value=False)

        # Fixed paths (hidden but used)
        self.var_tool2_script = tk.StringVar(value=str(self.fixed_tool2_script))
        self.var_asset_map = tk.StringVar(value=str(self.fixed_asset_map))
        self.var_threat_map = tk.StringVar(value=str(self.fixed_threat_map))
        self.var_attack_vector_map = tk.StringVar(value=str(self.fixed_attack_vector_map))
        self.var_dependency_map = tk.StringVar(value=str(self.fixed_dependency_map))

        # ✅ Options: Render Attack Graph Image / Render Attack Tree는 항상 True로 간주 (UI에도 표시 안 함)
        self.render_merged_graph_always = True
        self.render_attack_tree_always = True

        self._build_ui()

    # -----------------------------
    # UI
    # -----------------------------
    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

        banner = ttk.Frame(root)
        banner.pack(fill="x", **pad)
        self._build_banner(banner)

        # --- Inputs ---
        lf_in = ttk.LabelFrame(root, text="Inputs")
        lf_in.pack(fill="x", **pad)

        ttk.Label(lf_in, text=".tm7 파일").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_in, textvariable=self.var_tm7).grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_in, text="Browse", command=self._browse_tm7).grid(row=0, column=2, padx=8, pady=6)

        ttk.Label(lf_in, text="모드(--type)").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ttk.Combobox(
            lf_in,
            textvariable=self.var_mode,
            values=["remote", "adjacent", "local", "physical"],
            state="readonly",
            width=18,
        ).grid(row=1, column=1, sticky="w", padx=8, pady=6)

        ttk.Label(lf_in, text="목표 자산명(--target)").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_in, textvariable=self.var_target).grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        ttk.Label(lf_in, text="경계명(--boundary)").grid(row=3, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_in, textvariable=self.var_boundary).grid(row=3, column=1, sticky="ew", padx=8, pady=6)

        lf_in.columnconfigure(1, weight=1)

        # --- Outputs (3종) ---
        lf_out = ttk.LabelFrame(root, text="Outputs (3 items)")
        lf_out.pack(fill="x", **pad)

        # 1) Attack Graph JSON
        ttk.Label(lf_out, text="Attack Graph JSON (--out)").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_out, textvariable=self.var_out_json).grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_out_json).grid(row=0, column=2, padx=8, pady=6)

        # 2) Attack Graph Image (merged graph) : 파일 경로로 직접 받음 (확장자=포맷)
        ttk.Label(lf_out, text="Attack Graph Image (merged) (*.png/*.svg/*.pdf)").grid(
            row=1, column=0, sticky="w", padx=8, pady=6
        )
        ttk.Entry(lf_out, textvariable=self.var_attack_graph_image_path).grid(row=1, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_attack_graph_image).grid(row=1, column=2, padx=8, pady=6)

        # 3) Attack Tree PNG
        ttk.Label(lf_out, text="Attack Tree Image (--attack-tree-png)").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_out, textvariable=self.var_attack_tree_png).grid(row=2, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_attack_tree_png).grid(row=2, column=2, padx=8, pady=6)

        lf_out.columnconfigure(1, weight=1)

        # --- Options (일부만 노출) ---
        lf_opt = ttk.LabelFrame(root, text="Options")
        lf_opt.pack(fill="x", **pad)

        ttk.Label(lf_opt, text="max depth (--max-depth)").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_opt, textvariable=self.var_max_depth, width=10).grid(row=0, column=1, sticky="w", padx=8, pady=6)

        ttk.Checkbutton(
            lf_opt,
            text="Attack Tree no reverse (--attack-tree-no-reverse)",
            variable=self.var_attack_tree_no_reverse,
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=8, pady=4)

        lf_opt.columnconfigure(1, weight=1)

        # --- Actions + Log ---
        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)

        self.btn_run = ttk.Button(actions, text="Run", command=self._run_clicked)
        self.btn_run.pack(side="left")

        ttk.Button(actions, text="Quit", command=self.destroy).pack(side="right")

        logf = ttk.LabelFrame(root, text="Log")
        logf.pack(fill="both", expand=True, **pad)

        self.txt_log = tk.Text(logf, height=12, wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=8, pady=8)
        self._log("Ready.\n")

    def _build_banner(self, parent: ttk.Frame):
        self.banner_canvas = tk.Canvas(parent, height=92, highlightthickness=0)
        self.banner_canvas.pack(fill="x", expand=True)

        self.banner_title = tk.StringVar(value="Vehicle Threat Modeling Automation")
        self.banner_sub = tk.StringVar(value="TM7 DFD → Attack Graph JSON + Merged Graph + Attack Tree (parse_attack_graph_v17.py)")

        self.banner_canvas.bind("<Configure>", lambda e: self._draw_banner())
        self.after(50, self._draw_banner)

    def _draw_banner(self):
        c = self.banner_canvas
        c.delete("all")
        w = max(c.winfo_width(), 1)
        h = max(c.winfo_height(), 1)

        steps = 40
        for i in range(steps):
            t = i / (steps - 1)
            r1, g1, b1 = (10, 24, 55)
            r2, g2, b2 = (0, 120, 140)
            r = int(r1 + (r2 - r1) * t)
            g = int(g1 + (g2 - g1) * t)
            b = int(b1 + (b2 - b1) * t)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y0 = int(i * h / steps)
            y1 = int((i + 1) * h / steps)
            c.create_rectangle(0, y0, w, y1, outline=color, fill=color)

        for x in range(0, w, 48):
            c.create_line(x, 0, x, h, fill="#20324f")
        for y in range(0, h, 24):
            c.create_line(0, y, w, y, fill="#20324f")

        c.create_text(18, 22, anchor="w", text=self.banner_title.get(), fill="white", font=("Segoe UI", 16, "bold"))
        c.create_text(18, 52, anchor="w", text=self.banner_sub.get(), fill="#d7f3ff", font=("Segoe UI", 10, "normal"))

        cx = w - 220
        cy = 54
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

        win = [(cx - 5, cy - 16), (cx + 55, cy - 16), (cx + 70, cy - 6), (cx - 20, cy - 6)]
        c.create_polygon(win, fill="#0b1c33", outline="#c5e6ff", width=2)

        c.create_oval(cx - 55, cy + 2, cx - 25, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
        c.create_oval(cx + 55, cy + 2, cx + 85, cy + 32, fill="#0b1c33", outline="#c5e6ff", width=2)
        c.create_oval(cx - 47, cy + 10, cx - 33, cy + 24, fill="#eaf6ff", outline="")
        c.create_oval(cx + 63, cy + 10, cx + 77, cy + 24, fill="#eaf6ff", outline="")

        lx = w - 70
        ly = 28
        c.create_arc(lx - 18, ly - 18, lx + 18, ly + 18, start=200, extent=140, style="arc", width=4, outline="#ffffff")
        c.create_rectangle(lx - 20, ly + 12, lx + 20, ly + 46, fill="#ffffff", outline="#ffffff")
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

    def _browse_out_json(self):
        path = filedialog.asksaveasfilename(
            title="Save Attack Graph JSON as...",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=Path(self.var_out_json.get() or DEFAULT_OUT_JSON).name,
        )
        if path:
            self.var_out_json.set(path)

    def _browse_attack_graph_image(self):
        path = filedialog.asksaveasfilename(
            title="Save Attack Graph Image (merged) as...",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("SVG files", "*.svg"), ("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=Path(self.var_attack_graph_image_path.get() or (DEFAULT_MERGED_GRAPH_PREFIX + ".png")).name,
        )
        if path:
            self.var_attack_graph_image_path.set(path)

    def _browse_attack_tree_png(self):
        path = filedialog.asksaveasfilename(
            title="Save Attack Tree PNG as...",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            initialfile=Path(self.var_attack_tree_png.get() or DEFAULT_ATTACK_TREE_PNG).name,
        )
        if path:
            self.var_attack_tree_png.set(path)

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
    # validate
    # -----------------------------
    def _validate_inputs(self) -> bool:
        tool2_script = self.var_tool2_script.get().strip()
        tm7 = self.var_tm7.get().strip()
        mode = self.var_mode.get().strip()
        target = self.var_target.get().strip()
        boundary = self.var_boundary.get().strip()

        if not tool2_script or not os.path.isfile(tool2_script):
            messagebox.showerror("Not found", f"Backend 스크립트를 찾을 수 없습니다:\n{tool2_script}")
            return False

        if not tm7 or not os.path.isfile(tm7):
            messagebox.showerror("Not found", f".tm7 파일을 찾을 수 없습니다:\n{tm7}")
            return False

        if mode not in ("remote", "adjacent", "local", "physical"):
            messagebox.showerror("Invalid", "--type은 remote/adjacent/local/physical 중 하나여야 합니다.")
            return False

        if not target:
            messagebox.showerror("Missing", "목표 자산명(--target)을 입력해주세요.")
            return False

        # parse_attack_graph_v17.py: 모든 타입에서 --boundary 필수
        if not boundary:
            messagebox.showerror("Missing", "경계명(--boundary)을 입력해주세요.")
            return False

        try:
            d = int(self.var_max_depth.get().strip())
            if d <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid", "max depth는 1 이상의 정수여야 합니다.")
            return False

        # fixed mapping files must exist
        for pth, label in [
            (self.var_asset_map.get().strip(), "asset_to_threats"),
            (self.var_threat_map.get().strip(), "threat_to_tactic"),
            (self.var_attack_vector_map.get().strip(), "attack_vector_feasibility"),
            (self.var_dependency_map.get().strip(), "dependency"),
        ]:
            if not pth or not os.path.isfile(pth):
                messagebox.showerror("Not found", f"{label} 파일 경로가 유효하지 않습니다:\n{pth}")
                return False

        # outputs
        out_json = self.var_out_json.get().strip()
        if not out_json:
            messagebox.showerror("Missing", "Attack Graph JSON 출력 경로(--out)를 지정해주세요.")
            return False

        ag_img = self.var_attack_graph_image_path.get().strip()
        if not ag_img:
            messagebox.showerror("Missing", "Attack Graph Image 출력 경로를 지정해주세요.")
            return False
        ext = Path(ag_img).suffix.lower()
        if ext not in (".png", ".svg", ".pdf"):
            messagebox.showerror("Invalid", "Attack Graph Image 확장자는 .png / .svg / .pdf 중 하나여야 합니다.")
            return False

        at_png = self.var_attack_tree_png.get().strip()
        if not at_png:
            messagebox.showerror("Missing", "Attack Tree PNG 출력 경로(--attack-tree-png)를 지정해주세요.")
            return False
        if Path(at_png).suffix.lower() != ".png":
            messagebox.showerror("Invalid", "Attack Tree Image는 .png로 저장하는 걸 권장합니다(backend도 png 기준 옵션).")
            return False

        return True

    # -----------------------------
    # run
    # -----------------------------
    def _run_clicked(self):
        if not self._validate_inputs():
            return
        self._set_running(True)
        self._log("\n--- Running Tool-2 (parse_attack_graph_v17.py) ---\n")
        t = threading.Thread(target=self._run_tool2_subprocess, daemon=True)
        t.start()

    def _run_tool2_subprocess(self):
        tool2_script = self.var_tool2_script.get().strip()
        tm7 = self.var_tm7.get().strip()
        mode = self.var_mode.get().strip()
        target = self.var_target.get().strip()
        boundary = self.var_boundary.get().strip()

        asset_map = self.var_asset_map.get().strip()
        threat_map = self.var_threat_map.get().strip()
        attack_vector_map = self.var_attack_vector_map.get().strip()
        dependency_map = self.var_dependency_map.get().strip()

        out_json = self.var_out_json.get().strip()
        max_depth = self.var_max_depth.get().strip()

        # ✅ 항상 렌더링: merged graph + attack tree
        attack_graph_image_path = self.var_attack_graph_image_path.get().strip()
        merged_fmt = Path(attack_graph_image_path).suffix.lower().lstrip(".")
        merged_prefix = str(Path(attack_graph_image_path).with_suffix(""))

        attack_tree_png = self.var_attack_tree_png.get().strip()
        no_reverse = self.var_attack_tree_no_reverse.get()

        cmd = [
            sys.executable,
            tool2_script,
            "--tm7", tm7,
            "--type", mode,
            "--target", target,
            "--boundary", boundary,
            "--asset-map", asset_map,
            "--threat-map", threat_map,
            "--attack-vector-map", attack_vector_map,
            "--dependency-map", dependency_map,
            "--max-depth", max_depth,
            "--out", out_json,
            # merged graph (always on)
            "--render-merged-graph",
            "--merged-graph-out", merged_prefix,
            "--merged-graph-format", merged_fmt,
            # attack tree (always on)
            "--render-attack-tree",
            "--attack-tree-png", attack_tree_png,
        ]

        if no_reverse:
            cmd.append("--attack-tree-no-reverse")

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
                    self._log(out + ("" if out.endswith("\n") else "\n"))
                if err:
                    self._log("\n[stderr]\n" + err + ("" if err.endswith("\n") else "\n"))

                if proc.returncode == 0:
                    merged_out_path = f"{merged_prefix}.{merged_fmt}"
                    self._log("\n[OK] Done.\n")
                    messagebox.showinfo(
                        "Done",
                        "완료!\n\n"
                        f"Attack Graph JSON:\n{out_json}\n\n"
                        f"Attack Graph Image:\n{merged_out_path}\n\n"
                        f"Attack Tree Image:\n{attack_tree_png}",
                    )
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
