# -*- coding: utf-8 -*-
from __future__ import annotations
import os
import sys
import threading
import subprocess
import json
import shutil
import argparse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Pillow (권장): PNG를 "패널에 맞게 확대/축소 + 휠 줌" 하려면 필요
try:
    from PIL import Image, ImageTk  # type: ignore
    PIL_OK = True
except Exception:
    PIL_OK = False
    Image = None  # type: ignore
    ImageTk = None  # type: ignore

# ✅ parse_attack_graph_v27.py에 맞춘 고정 경로들
DEFAULT_TOOL2_SCRIPT = "../backend/parse_attack_graph_v29.py"        ## 백엔드 코드 파일
DEFAULT_ASSET_MAP = "../backend/threat_library/asset_to_threats_ver0.2.json"
DEFAULT_THREAT_MAP = "../backend/threat_library/threat_to_tactic.json"
DEFAULT_ATTACK_VECTOR_MAP = "../backend/threat_library/attack_vector_feasibility.json"
DEFAULT_DEPENDENCY_MAP = "../backend/threat_library/dependency.json"
DEFAULT_IMPACT_MAP = "../backend/threat_library/impact_map.json"

# ✅ 출력 기본값(고정 사용)
DEFAULT_OUT_JSON = "../out/attack_graph.json"
DEFAULT_OUT_WITH_RISK_JSON = "../out/attack_graph_with_risk_temp.json"
DEFAULT_MERGED_GRAPH_PREFIX = "../out/merged_attack_graph"   # 확장자 제외 prefix
DEFAULT_ATTACK_TREE_PNG = "../out/attack_tree.png"
DEFAULT_REPORT = "../out/result_report.html"

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
        img_label = ttk.Label(card, image=img_ref)
        img_label.pack(padx=6, pady=(6, 10))
        base_w = img_ref.width() + 14 * 2 + 14 * 2
        base_h = img_ref.height() + 140
    else:
        icon = ttk.Label(card, text="⏳", font=("Segoe UI", 34))
        icon.pack(padx=6, pady=(6, 6))
        base_w, base_h = 420, 220

    title = ttk.Label(card, text="TARA Threat Modeling Automation Tool",
                      font=("Segoe UI", 13, "bold"))
    title.pack(pady=(0, 6))

    loading_var = tk.StringVar(value="Loading")
    loading_lbl = ttk.Label(card, textvariable=loading_var, font=("Segoe UI", 10))
    loading_lbl.pack(pady=(0, 10))

    pb = ttk.Progressbar(card, mode="indeterminate", length=320)
    pb.pack(pady=(0, 6))
    pb.start(12)

    hint = ttk.Label(card, text="Preparing the UI…", font=("Segoe UI", 9))
    hint.pack(pady=(2, 2))

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
    def __init__(self, backend_script_path: str | None = None, start_hidden: bool = True):
        super().__init__()
        if start_hidden:
            self.withdraw()

        self.base_dir = Path(__file__).resolve().parent

        if backend_script_path:
            self.fixed_tool2_script = Path(backend_script_path).resolve()
        else:
            self.fixed_tool2_script = (self.base_dir / DEFAULT_TOOL2_SCRIPT).resolve()

        self.fixed_asset_map = (self.base_dir / DEFAULT_ASSET_MAP).resolve()
        self.fixed_threat_map = (self.base_dir / DEFAULT_THREAT_MAP).resolve()
        self.fixed_attack_vector_map = (self.base_dir / DEFAULT_ATTACK_VECTOR_MAP).resolve()
        self.fixed_dependency_map = (self.base_dir / DEFAULT_DEPENDENCY_MAP).resolve()
        self.fixed_impact_map = (self.base_dir / DEFAULT_IMPACT_MAP).resolve()
        self.fixed_result_report = (self.base_dir / DEFAULT_REPORT).resolve()

        self.fixed_out_json = (self.base_dir / DEFAULT_OUT_JSON).resolve()
        self.fixed_out_with_risk_json = (self.base_dir / DEFAULT_OUT_WITH_RISK_JSON).resolve()
        self.fixed_merged_graph_prefix = (self.base_dir / DEFAULT_MERGED_GRAPH_PREFIX).resolve()
        self.fixed_attack_graph_png = Path(str(self.fixed_merged_graph_prefix) + ".png")
        self.fixed_attack_tree_png = (self.base_dir / DEFAULT_ATTACK_TREE_PNG).resolve()

        self.title("Vehicle Threat Modeling - Attack Graph Generator (Tool-2)")
        self.geometry("1040x760")
        self.minsize(980, 680)

        # Inputs
        self.var_tm7 = tk.StringVar(value="")
        self.var_mode = tk.StringVar(value="remote")
        self.var_target = tk.StringVar(value="")
        self.var_boundary = tk.StringVar(value="")

        # Advanced
        self.var_max_depth = tk.StringVar(value="30")
        self.var_attack_tree_no_reverse = tk.BooleanVar(value=False)

        # Fixed paths (hidden)
        self.var_tool2_script = tk.StringVar(value=str(self.fixed_tool2_script))
        self.var_asset_map = tk.StringVar(value=str(self.fixed_asset_map))
        self.var_threat_map = tk.StringVar(value=str(self.fixed_threat_map))
        self.var_attack_vector_map = tk.StringVar(value=str(self.fixed_attack_vector_map))
        self.var_dependency_map = tk.StringVar(value=str(self.fixed_dependency_map))
        self.var_impact_map = tk.StringVar(value=str(self.fixed_impact_map))
        self.var_result_report = tk.StringVar(value=str(self.fixed_result_report))

        # Report
        self.last_report_path = str(self.fixed_result_report)

        # Total Risk + Attack path count
        self.var_total_risk = tk.StringVar(value="Total Risk: -")
        self.var_path_count = tk.StringVar(value="Attack Paths: -")

        # Preview state
        self._preview_state = {
            "graph": {"path": "", "pil": None, "tk": None, "zoom": 1.0},
        }

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

        # Inputs
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

        # Options
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

        # Actions
        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)

        self.btn_run = ttk.Button(actions, text="Run", command=self._run_clicked)
        self.btn_run.pack(side="left")

        self.btn_open_report = ttk.Button(actions, text="Open Report", command=self._open_report, state="disabled")
        self.btn_open_report.pack(side="left", padx=(8, 0))

        self.btn_save_report_pdf = ttk.Button(actions, text="Save Report PDF", command=self._save_report_pdf_clicked, state="disabled")
        self.btn_save_report_pdf.pack(side="left", padx=(8, 0))

        ttk.Button(actions, text="Quit", command=self.destroy).pack(side="right")

        # Preview only
        previewf = ttk.LabelFrame(root, text="Attack Graph Preview")
        previewf.pack(fill="both", expand=True, **pad)

        preview_root = ttk.Frame(previewf)
        preview_root.pack(fill="both", expand=True, padx=8, pady=8)
        preview_root.rowconfigure(1, weight=1)
        preview_root.columnconfigure(0, weight=1)

        topbar = ttk.Frame(preview_root)
        topbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        topbar.columnconfigure(0, weight=1)

        ttk.Label(topbar, textvariable=self.var_total_risk, font=("Segoe UI", 10, "bold")).pack(side="top", anchor="w")
        ttk.Label(topbar, textvariable=self.var_path_count, font=("Segoe UI", 10, "bold")).pack(side="top", anchor="w")

        self._build_graph_preview(preview_root)

    def _build_graph_preview(self, parent: ttk.Frame):
        self.card_graph = ttk.LabelFrame(parent, text="Attack Graph (merged) Preview  —  Wheel: Zoom  |  Reset: Fit")
        self.card_graph.grid(row=1, column=0, sticky="nsew")

        self.card_graph.columnconfigure(0, weight=1)
        self.card_graph.rowconfigure(0, weight=1)

        self.lbl_graph_img = ttk.Label(self.card_graph, text="(no image)", anchor="center", justify="center")
        self.lbl_graph_img.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        btns_g = ttk.Frame(self.card_graph)
        btns_g.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))

        ttk.Button(btns_g, text="Open", command=lambda: self._open_file(self._preview_state["graph"]["path"])).pack(side="right")
        ttk.Button(btns_g, text="Reset", command=lambda: self._reset_zoom("graph")).pack(side="right", padx=(0, 6))

        self.card_graph.bind("<Configure>", lambda e: self._render_preview("graph"))

        self.lbl_graph_img.bind("<MouseWheel>", lambda ev: self._on_zoom(ev, "graph"))
        self.lbl_graph_img.bind("<Button-4>", lambda ev: self._on_zoom(ev, "graph"))
        self.lbl_graph_img.bind("<Button-5>", lambda ev: self._on_zoom(ev, "graph"))

    def _open_file(self, path: str):
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Not found", f"파일을 찾을 수 없습니다:\n{path}")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def _open_report(self):
        self._open_file(self.last_report_path)

    def _find_browser_executable(self) -> str | None:
        candidates = [
            "msedge", "microsoft-edge", "chrome", "google-chrome",
            "chromium", "chromium-browser", "brave",
        ]
        for name in candidates:
            found = shutil.which(name)
            if found:
                return found

        common_windows = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        ]
        for p in common_windows:
            if os.path.exists(p):
                return p
        return None

    def _convert_html_to_pdf(self, html_path: Path, pdf_path: Path) -> tuple[bool, str]:
        html_path = html_path.resolve()
        pdf_path = pdf_path.resolve()
        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from weasyprint import HTML  # type: ignore
            HTML(filename=str(html_path), base_url=str(html_path.parent)).write_pdf(str(pdf_path))
            return True, f"PDF saved via WeasyPrint:\n{pdf_path}"
        except Exception:
            pass

        wk = shutil.which("wkhtmltopdf")
        if wk:
            try:
                subprocess.run(
                    [wk, "--enable-local-file-access", str(html_path), str(pdf_path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return True, f"PDF saved via wkhtmltopdf:\n{pdf_path}"
            except Exception:
                pass

        browser = self._find_browser_executable()
        if browser:
            try:
                html_uri = html_path.as_uri()
                subprocess.run(
                    [
                        browser,
                        "--headless",
                        "--disable-gpu",
                        "--allow-file-access-from-files",
                        f"--print-to-pdf={str(pdf_path)}",
                        html_uri,
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return True, f"PDF saved via headless browser:\n{pdf_path}"
            except Exception:
                pass

        return False, (
            "HTML to PDF conversion failed.\n\n"
            "Install one of the following:\n"
            "- weasyprint\n"
            "- wkhtmltopdf\n"
            "- Edge / Chrome / Chromium / Brave"
        )

    def _save_report_pdf_clicked(self):
        html_path = Path(self.last_report_path)

        if not html_path.is_file():
            messagebox.showwarning("Not found", f"HTML 보고서를 찾을 수 없습니다:\n{html_path}")
            return

        default_pdf = str(html_path.with_suffix(".pdf"))
        save_path = filedialog.asksaveasfilename(
            title="Save Report PDF as...",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=Path(default_pdf).name,
        )
        if not save_path:
            return

        self._set_running(True)
        t = threading.Thread(
            target=self._save_report_pdf_from_html_thread,
            args=(str(html_path), save_path),
            daemon=True,
        )
        t.start()

    def _save_report_pdf_from_html_thread(self, html_path: str, pdf_path: str):
        ok, msg = self._convert_html_to_pdf(Path(html_path), Path(pdf_path))

        def done():
            self._set_running(False)
            if ok:
                messagebox.showinfo("Done", msg)
            else:
                messagebox.showerror("Failed", msg)

        self.after(0, done)

    def _build_banner(self, parent: ttk.Frame):
        self.banner_canvas = tk.Canvas(parent, height=92, highlightthickness=0)
        self.banner_canvas.pack(fill="x", expand=True)

        self.banner_title = tk.StringVar(value="Vehicle Threat Modeling Automation")
        self.banner_sub = tk.StringVar(value="complying TARA in ISO/SAE 21434")

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
    # Preview
    # -----------------------------
    def _set_preview(self, which: str, path: str):
        if which != "graph":
            return

        label = self.lbl_graph_img

        self._preview_state[which]["path"] = path
        self._preview_state[which]["zoom"] = 1.0

        if not path or not os.path.isfile(path):
            self._preview_state[which]["pil"] = None
            self._preview_state[which]["tk"] = None
            label.configure(text="(file not found)", image="")
            return

        ext = Path(path).suffix.lower()
        if ext != ".png":
            self._preview_state[which]["pil"] = None
            self._preview_state[which]["tk"] = None
            label.configure(
                text=f"Preview not supported for {ext}.\nClick Open to view.",
                image="",
                justify="center"
            )
            return

        if not PIL_OK:
            self._preview_state[which]["pil"] = None
            self._preview_state[which]["tk"] = None
            label.configure(
                text="Pillow(PIL) not installed.\nInstall: pip install pillow",
                image="",
                justify="center"
            )
            return

        try:
            pil = Image.open(path).convert("RGBA")  # type: ignore[attr-defined]
            self._preview_state[which]["pil"] = pil
            self._render_preview(which)
        except Exception as e:
            self._preview_state[which]["pil"] = None
            self._preview_state[which]["tk"] = None
            label.configure(text=f"(preview failed: {e})", image="")

    def _render_preview(self, which: str):
        st = self._preview_state.get(which)
        if not st:
            return

        pil = st["pil"]
        if pil is None or not PIL_OK:
            return

        card = self.card_graph
        label = self.lbl_graph_img

        card.update_idletasks()
        w = card.winfo_width()
        h = card.winfo_height()
        if w <= 10 or h <= 10:
            return

        usable_w = max(80, w - 24)
        usable_h = max(80, h - 70)

        zoom = float(st["zoom"])
        pw, ph = pil.size
        fit_scale = min(usable_w / pw, usable_h / ph)
        scale = max(0.05, fit_scale * zoom)

        new_w = max(1, int(pw * scale))
        new_h = max(1, int(ph * scale))

        try:
            resized = pil.resize((new_w, new_h), Image.LANCZOS)  # type: ignore[attr-defined]
            tkimg = ImageTk.PhotoImage(resized)  # type: ignore[attr-defined]
        except Exception:
            return

        st["tk"] = tkimg
        label.configure(image=tkimg, text="")
        label.image = tkimg

    def _on_zoom(self, event, which: str):
        st = self._preview_state.get(which)
        if not st or st["pil"] is None or not PIL_OK:
            return

        delta = 0
        if hasattr(event, "delta") and event.delta != 0:
            delta = event.delta
        elif hasattr(event, "num"):
            delta = 120 if event.num == 4 else -120

        if delta > 0:
            st["zoom"] = min(5.0, st["zoom"] * 1.12)
        else:
            st["zoom"] = max(0.2, st["zoom"] / 1.12)

        self._render_preview(which)

    def _reset_zoom(self, which: str):
        st = self._preview_state.get(which)
        if not st:
            return
        st["zoom"] = 1.0
        self._render_preview(which)

    # -----------------------------
    # browse
    # -----------------------------
    def _browse_tm7(self):
        path = filedialog.askopenfilename(
            title="Select .tm7 file",
            filetypes=[("TM7 files", "*.tm7"), ("All files", "*.*")],
        )
        if path:
            self.var_tm7.set(path)

    # -----------------------------
    # helper
    # -----------------------------
    def _log(self, msg: str):
        return

    def _set_running(self, running: bool):
        self.btn_run.config(state=("disabled" if running else "normal"))
        self.btn_open_report.config(state=("disabled" if running else "normal"))
        self.btn_save_report_pdf.config(state=("disabled" if running else "normal"))
        self.config(cursor=("watch" if running else ""))

    def _read_attack_summary(self, json_path: str) -> tuple[int | str, int]:
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            paths = data.get("paths", [])
            total_risk = data.get("total_risk", "-")

            if isinstance(paths, list):
                return total_risk, len(paths)
        except Exception:
            pass
        return "-", 0

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
            (self.var_impact_map.get().strip(), "impact_map"),
        ]:
            if not pth or not os.path.isfile(pth):
                messagebox.showerror("Not found", f"{label} 파일 경로가 유효하지 않습니다:\n{pth}")
                return False

        return True

    # -----------------------------
    # run
    # -----------------------------
    def _run_clicked(self):
        if not self._validate_inputs():
            return
        self._set_running(True)
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
        impact_map = self.var_impact_map.get().strip()
        result_report = self.var_result_report.get().strip()
        out_json = str(self.fixed_out_json)
        max_depth = self.var_max_depth.get().strip()
        attack_graph_image_path = str(self.fixed_attack_graph_png)
        merged_fmt = Path(attack_graph_image_path).suffix.lower().lstrip(".")
        merged_prefix = str(Path(attack_graph_image_path).with_suffix(""))
        attack_tree_png = str(self.fixed_attack_tree_png)
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
            "--impact-map", impact_map,
            "--max-depth", max_depth,
            "--out", out_json,
            "--render-merged-graph",
            "--merged-graph-out", merged_prefix,
            "--merged-graph-format", merged_fmt,
            "--render-attack-tree",
            "--attack-tree-png", attack_tree_png,
            "--detection-report", result_report
        ]

        if no_reverse:
            cmd.append("--attack-tree-no-reverse")

        workdir = os.path.dirname(os.path.abspath(tool2_script)) or None

        try:
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
                merged_out_path = f"{merged_prefix}.{merged_fmt}"

                if proc.returncode == 0:
                    self._set_preview("graph", merged_out_path)

                    total_risk, path_count = self._read_attack_summary(str(self.fixed_out_with_risk_json))
                    self.var_total_risk.set(f"Total Risk: {total_risk}")
                    self.var_path_count.set(f"Attack Paths: {path_count}")

                    self.last_report_path = result_report
                    self.btn_open_report.config(state="normal")
                    self.btn_save_report_pdf.config(state="normal")

                    messagebox.showinfo(
                        "Done",
                        "완료!\n\n"
                        f"Attack Graph JSON:\n{out_json}\n\n"
                        f"Attack Graph Image:\n{merged_out_path}\n\n"
                        f"Report:\n{result_report}"
                    )
                else:
                    detail = ""
                    if err.strip():
                        detail = err.strip()
                    elif out.strip():
                        detail = out.strip()
                    else:
                        detail = f"return code={proc.returncode}"

                    messagebox.showerror("Failed", f"실행 실패.\n\n{detail}")

                self._set_running(False)

            self.after(0, done)

        except Exception as e:
            def fail():
                self._set_running(False)
                messagebox.showerror("Exception", str(e))
            self.after(0, fail)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TARA Threat Modeling GUI")
    parser.add_argument(
        "--backend",
        default=None,
        help="GUI와 연동할 백엔드 Python 스크립트 경로 (예: ../backend/parse_attack_graph_v29.py)"
    )
    args = parser.parse_args()

    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore
    except Exception:
        pass

    app = Tool2GUI(backend_script_path=args.backend, start_hidden=True)
    splash_img_path = (Path(__file__).resolve().parent / SPLASH_IMAGE_REL).resolve()

    show_splash_then(
        app,
        splash_img_path,
        total_ms=SPLASH_TOTAL_MS,
        fade_in_ms=FADE_IN_MS,
        fade_out_ms=FADE_OUT_MS,
    )
    app.mainloop()

'''
백엔드 지정 실행:
python tool_gui_v16.py --backend ../backend/parse_attack_graph_v30.py
'''
