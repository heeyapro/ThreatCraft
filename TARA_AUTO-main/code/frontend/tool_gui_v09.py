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

# ✅ Splash 이미지: frontend 스크립트 위치 기준
SPLASH_IMAGE_REL = "../../1770647509745-Photoroom.png"

# 스플래시 연출
SPLASH_TOTAL_MS = 2000
FADE_IN_MS = 250
FADE_OUT_MS = 250
DOT_TICK_MS = 220


def _center_window(win: tk.Toplevel | tk.Tk, w: int, h: int):
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = int((sw - w) / 2)
    y = int((sh - h) / 2)
    win.geometry(f"{w}x{h}+{x}+{y}")


def _open_file_default(path: str):
    """Open file with OS default viewer."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            import subprocess as _sp
            _sp.Popen(["open", path])
        else:
            import subprocess as _sp
            _sp.Popen(["xdg-open", path])
    except Exception:
        pass


def show_splash_then(app: tk.Tk, image_path: Path,
                    total_ms: int = SPLASH_TOTAL_MS,
                    fade_in_ms: int = FADE_IN_MS,
                    fade_out_ms: int = FADE_OUT_MS):
    splash = tk.Toplevel(app)
    splash.overrideredirect(True)
    splash.attributes("-topmost", True)

    alpha_supported = True
    try:
        splash.attributes("-alpha", 0.0)
    except Exception:
        alpha_supported = False

    outer = ttk.Frame(splash, padding=14)
    outer.pack(fill="both", expand=True)
    card = ttk.Frame(outer, padding=14, relief="ridge")
    card.pack(fill="both", expand=True)

    img_ref = None
    used_image = False
    try:
        if image_path.is_file():
            img = tk.PhotoImage(file=str(image_path))
            max_w, max_h = 480, 360
            scale = max(1, int(max(img.width() / max_w, img.height() / max_h)))
            if scale > 1:
                img = img.subsample(scale, scale)
            img_ref = img
            used_image = True
    except Exception:
        used_image = False
        img_ref = None

    if used_image and img_ref is not None:
        ttk.Label(card, image=img_ref).pack(padx=6, pady=(6, 10))
        base_w = img_ref.width() + 14 * 4
        base_h = img_ref.height() + 140
    else:
        ttk.Label(card, text="⏳", font=("Segoe UI", 34)).pack(padx=6, pady=(6, 6))
        base_w, base_h = 420, 220

    ttk.Label(card, text="TARA Threat Modeling Automation Tool", font=("Segoe UI", 13, "bold")).pack(pady=(0, 6))

    loading_var = tk.StringVar(value="Loading")
    ttk.Label(card, textvariable=loading_var, font=("Segoe UI", 10)).pack(pady=(0, 10))

    pb = ttk.Progressbar(card, mode="indeterminate", length=320)
    pb.pack(pady=(0, 6))
    pb.start(12)

    ttk.Label(card, text="Preparing the UI…", font=("Segoe UI", 9)).pack(pady=(2, 2))

    _center_window(splash, max(420, base_w), max(220, base_h))

    dot_state = {"i": 0, "running": True}

    def tick_dots():
        if not dot_state["running"]:
            return
        dot_state["i"] = (dot_state["i"] + 1) % 4
        loading_var.set("Loading" + ("." * dot_state["i"]))
        splash.after(DOT_TICK_MS, tick_dots)

    def fade_to(target: float, duration_ms: int, steps: int = 20, on_done=None):
        if not alpha_supported:
            if on_done:
                on_done()
            return
        try:
            cur = float(splash.attributes("-alpha"))
        except Exception:
            cur = 1.0

        delta = (target - cur) / max(1, steps)
        interval = max(10, duration_ms // max(1, steps))

        def step(k=0):
            try:
                splash.attributes("-alpha", cur + delta * k)
            except Exception:
                if on_done:
                    on_done()
                return
            if k >= steps:
                try:
                    splash.attributes("-alpha", target)
                except Exception:
                    pass
                if on_done:
                    on_done()
                return
            splash.after(interval, lambda: step(k + 1))

        step(0)

    def finish():
        dot_state["running"] = False
        try:
            pb.stop()
        except Exception:
            pass
        try:
            splash.destroy()
        except Exception:
            pass
        app.deiconify()
        app.lift()
        app.focus_force()

    body_ms = max(0, total_ms - (fade_in_ms + fade_out_ms))

    def start_sequence():
        tick_dots()
        if alpha_supported:
            fade_to(1.0, fade_in_ms, steps=18, on_done=lambda: splash.after(
                body_ms, lambda: fade_to(0.0, fade_out_ms, steps=18, on_done=finish)
            ))
        else:
            splash.after(total_ms, finish)

    splash._img_ref = img_ref  # type: ignore[attr-defined]
    start_sequence()


class Tool2GUI(tk.Tk):
    def __init__(self, start_hidden: bool = True):
        super().__init__()

        if start_hidden:
            self.withdraw()

        self.base_dir = Path(__file__).resolve().parent
        self.fixed_tool2_script = (self.base_dir / DEFAULT_TOOL2_SCRIPT).resolve()
        self.fixed_asset_map = (self.base_dir / DEFAULT_ASSET_MAP).resolve()
        self.fixed_threat_map = (self.base_dir / DEFAULT_THREAT_MAP).resolve()
        self.fixed_attack_vector_map = (self.base_dir / DEFAULT_ATTACK_VECTOR_MAP).resolve()
        self.fixed_dependency_map = (self.base_dir / DEFAULT_DEPENDENCY_MAP).resolve()

        self.title("Vehicle Threat Modeling - Attack Graph Generator (Tool-2)")
        self.geometry("880x720")
        self.minsize(860, 660)

        # Inputs
        self.var_tm7 = tk.StringVar(value="")
        self.var_mode = tk.StringVar(value="remote")
        self.var_target = tk.StringVar(value="")
        self.var_boundary = tk.StringVar(value="")

        # Outputs
        self.var_out_json = tk.StringVar(value=str((self.base_dir / DEFAULT_OUT_JSON).resolve()))
        self.var_attack_graph_image_path = tk.StringVar(
            value=str((self.base_dir / (DEFAULT_MERGED_GRAPH_PREFIX + ".png")).resolve())
        )
        self.var_attack_tree_png = tk.StringVar(value=str((self.base_dir / DEFAULT_ATTACK_TREE_PNG).resolve()))

        # Advanced
        self.var_max_depth = tk.StringVar(value="30")
        self.var_attack_tree_no_reverse = tk.BooleanVar(value=False)

        # Fixed paths
        self.var_tool2_script = tk.StringVar(value=str(self.fixed_tool2_script))
        self.var_asset_map = tk.StringVar(value=str(self.fixed_asset_map))
        self.var_threat_map = tk.StringVar(value=str(self.fixed_threat_map))
        self.var_attack_vector_map = tk.StringVar(value=str(self.fixed_attack_vector_map))
        self.var_dependency_map = tk.StringVar(value=str(self.fixed_dependency_map))

        # preview image refs
        self._preview_refs: dict[str, tk.PhotoImage] = {}

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
            lf_in, textvariable=self.var_mode,
            values=["remote", "adjacent", "local", "physical"],
            state="readonly", width=18,
        ).grid(row=1, column=1, sticky="w", padx=8, pady=6)

        ttk.Label(lf_in, text="목표 자산명(--target)").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_in, textvariable=self.var_target).grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        ttk.Label(lf_in, text="경계명(--boundary)").grid(row=3, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_in, textvariable=self.var_boundary).grid(row=3, column=1, sticky="ew", padx=8, pady=6)

        lf_in.columnconfigure(1, weight=1)

        # --- Outputs ---
        lf_out = ttk.LabelFrame(root, text="Outputs (3 items)")
        lf_out.pack(fill="x", **pad)

        ttk.Label(lf_out, text="Attack Graph JSON (--out)").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_out, textvariable=self.var_out_json).grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_out_json).grid(row=0, column=2, padx=8, pady=6)

        ttk.Label(lf_out, text="Attack Graph Image (merged) (*.png/*.svg/*.pdf)").grid(
            row=1, column=0, sticky="w", padx=8, pady=6
        )
        ttk.Entry(lf_out, textvariable=self.var_attack_graph_image_path).grid(row=1, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_attack_graph_image).grid(row=1, column=2, padx=8, pady=6)

        ttk.Label(lf_out, text="Attack Tree Image (--attack-tree-png)").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_out, textvariable=self.var_attack_tree_png).grid(row=2, column=1, sticky="ew", padx=8, pady=6)
        ttk.Button(lf_out, text="Browse", command=self._browse_attack_tree_png).grid(row=2, column=2, padx=8, pady=6)

        lf_out.columnconfigure(1, weight=1)

        # --- Options ---
        lf_opt = ttk.LabelFrame(root, text="Options")
        lf_opt.pack(fill="x", **pad)

        ttk.Label(lf_opt, text="max depth (--max-depth)").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(lf_opt, textvariable=self.var_max_depth, width=10).grid(row=0, column=1, sticky="w", padx=8, pady=6)

        ttk.Checkbutton(
            lf_opt, text="Attack Tree no reverse (--attack-tree-no-reverse)",
            variable=self.var_attack_tree_no_reverse,
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=8, pady=4)

        lf_opt.columnconfigure(1, weight=1)

        # --- Actions ---
        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)

        self.btn_run = ttk.Button(actions, text="Run", command=self._run_clicked)
        self.btn_run.pack(side="left")
        ttk.Button(actions, text="Quit", command=self.destroy).pack(side="right")

        # --- Log + Preview ---
        logf = ttk.LabelFrame(root, text="Log")
        logf.pack(fill="both", expand=True, **pad)

        # 상단: 로그 텍스트
        self.txt_log = tk.Text(logf, height=8, wrap="word")
        self.txt_log.pack(fill="x", expand=False, padx=8, pady=(8, 6))
        self._log("Ready.\n")

        # 하단: 결과 미리보기(스크롤 가능)
        preview_outer = ttk.Frame(logf)
        preview_outer.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.preview_canvas = tk.Canvas(preview_outer, highlightthickness=0)
        self.preview_canvas.pack(side="left", fill="both", expand=True)

        vsb = ttk.Scrollbar(preview_outer, orient="vertical", command=self.preview_canvas.yview)
        vsb.pack(side="right", fill="y")
        self.preview_canvas.configure(yscrollcommand=vsb.set)

        self.preview_frame = ttk.Frame(self.preview_canvas)
        self.preview_window_id = self.preview_canvas.create_window((0, 0), window=self.preview_frame, anchor="nw")

        def _on_frame_config(_e):
            self.preview_canvas.configure(scrollregion=self.preview_canvas.bbox("all"))

        def _on_canvas_config(e):
            # 프레임 폭을 캔버스 폭에 맞춤
            self.preview_canvas.itemconfigure(self.preview_window_id, width=e.width)

        self.preview_frame.bind("<Configure>", _on_frame_config)
        self.preview_canvas.bind("<Configure>", _on_canvas_config)

        # 2열 카드
        self.preview_frame.columnconfigure(0, weight=1, uniform="col")
        self.preview_frame.columnconfigure(1, weight=1, uniform="col")

        # 미리보기 카드 준비
        self._build_preview_cards()

    def _build_preview_cards(self):
        self.card_graph = ttk.LabelFrame(self.preview_frame, text="Attack Graph (merged)")
        self.card_tree = ttk.LabelFrame(self.preview_frame, text="Attack Tree")

        self.card_graph.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=6)
        self.card_tree.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=6)

        for card in (self.card_graph, self.card_tree):
            card.columnconfigure(0, weight=1)

        # graph card
        self.graph_path_var = tk.StringVar(value="(not generated yet)")
        ttk.Label(self.card_graph, textvariable=self.graph_path_var).grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        self.lbl_graph_img = ttk.Label(self.card_graph, text="No preview")
        self.lbl_graph_img.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        btns_g = ttk.Frame(self.card_graph)
        btns_g.grid(row=2, column=0, sticky="e", padx=8, pady=(0, 8))
        ttk.Button(btns_g, text="Open", command=lambda: self._open_current("graph")).pack(side="right")

        # tree card
        self.tree_path_var = tk.StringVar(value="(not generated yet)")
        ttk.Label(self.card_tree, textvariable=self.tree_path_var).grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        self.lbl_tree_img = ttk.Label(self.card_tree, text="No preview")
        self.lbl_tree_img.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        btns_t = ttk.Frame(self.card_tree)
        btns_t.grid(row=2, column=0, sticky="e", padx=8, pady=(0, 8))
        ttk.Button(btns_t, text="Open", command=lambda: self._open_current("tree")).pack(side="right")

        # 클릭하면 열기
        self.lbl_graph_img.bind("<Button-1>", lambda _e: self._open_current("graph"))
        self.lbl_tree_img.bind("<Button-1>", lambda _e: self._open_current("tree"))
        self.lbl_graph_img.configure(cursor="hand2")
        self.lbl_tree_img.configure(cursor="hand2")

        self._current_paths = {"graph": "", "tree": ""}

    def _open_current(self, which: str):
        p = self._current_paths.get(which, "")
        if p and os.path.isfile(p):
            _open_file_default(p)

    def _set_preview(self, which: str, path: str):
        """
        PNG는 미리보기, SVG/PDF는 미리보기 대신 안내 텍스트.
        """
        if which not in ("graph", "tree"):
            return

        label = self.lbl_graph_img if which == "graph" else self.lbl_tree_img
        var = self.graph_path_var if which == "graph" else self.tree_path_var
        var.set(path if path else "(not generated)")

        self._current_paths[which] = path

        if not path or not os.path.isfile(path):
            label.configure(text="(file not found)", image="")
            self._preview_refs.pop(which, None)
            return

        ext = Path(path).suffix.lower()
        if ext == ".png":
            try:
                img = tk.PhotoImage(file=path)
                # 카드에 맞게 축소
                max_w, max_h = 360, 240
                scale = max(1, int(max(img.width() / max_w, img.height() / max_h)))
                if scale > 1:
                    img = img.subsample(scale, scale)

                self._preview_refs[which] = img
                label.configure(image=img, text="")
            except Exception as e:
                label.configure(text=f"(preview failed: {e})", image="")
                self._preview_refs.pop(which, None)
        else:
            # Tk 기본만으로는 svg/pdf 렌더링 불가
            label.configure(
                text=f"Preview not supported for {ext}.\nClick Open to view.",
                image="",
                justify="center"
            )
            self._preview_refs.pop(which, None)

    # -----------------------------
    # Banner
    # -----------------------------
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

        for pth, label in [
            (self.var_asset_map.get().strip(), "asset_to_threats"),
            (self.var_threat_map.get().strip(), "threat_to_tactic"),
            (self.var_attack_vector_map.get().strip(), "attack_vector_feasibility"),
            (self.var_dependency_map.get().strip(), "dependency"),
        ]:
            if not pth or not os.path.isfile(pth):
                messagebox.showerror("Not found", f"{label} 파일 경로가 유효하지 않습니다:\n{pth}")
                return False

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
            messagebox.showerror("Invalid", "Attack Tree Image는 .png로 저장하는 걸 권장합니다.")
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
            "--render-merged-graph",
            "--merged-graph-out", merged_prefix,
            "--merged-graph-format", merged_fmt,
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

                    # ✅ Log 아래 미리보기 2개 세팅
                    self._set_preview("graph", merged_out_path)
                    self._set_preview("tree", attack_tree_png)

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

    app = Tool2GUI(start_hidden=True)

    splash_img_path = (Path(__file__).resolve().parent / SPLASH_IMAGE_REL).resolve()
    show_splash_then(
        app,
        splash_img_path,
        total_ms=SPLASH_TOTAL_MS,
        fade_in_ms=FADE_IN_MS,
        fade_out_ms=FADE_OUT_MS,
    )

    app.mainloop()
