"""SecureVault-style Tkinter GUI for the two-custodian encrypted backup project."""

from __future__ import annotations

import json
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from backup import create_backup
from backup_tool import BackupError
from database import (
    authenticate_user,
    initialise_database,
    record_event,
    register_user,
)
from logger import configure_logger
from recovery import restore_backup


ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

NAVY = "#0F172A"
BLUE = "#2563EB"
GREEN = "#15803D"
RED = "#B91C1C"
MUTED = "#64748B"


class SecureVaultApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SecureVault - Encrypted Backup")
        self.geometry("980x640")
        self.minsize(820, 560)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.logger = configure_logger()
        self.operator = ""
        self.page_frames: dict[str, ctk.CTkFrame] = {}
        initialise_database()

        self.build_sidebar()
        self.build_main()
        self.build_login()
        self.build_splash()

    def build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=210, corner_radius=0, fg_color=NAVY)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar,
            text="SecureVault",
            font=("Arial", 22, "bold"),
            text_color="white",
        ).pack(pady=(26, 26), padx=20)

        for name in ("Dashboard", "Setup", "Backup", "Restore", "Recovery"):
            ctk.CTkButton(
                sidebar,
                text=name,
                anchor="w",
                height=38,
                fg_color="transparent",
                hover_color="#1E293B",
                command=lambda page=name: self.show_page(page),
            ).pack(fill="x", padx=12, pady=3)

        self.operator_label = ctk.CTkLabel(
            sidebar, text="", text_color="#94A3B8"
        )
        self.operator_label.pack(side="bottom", pady=(0, 16))
        ctk.CTkButton(
            sidebar,
            text="Sign out",
            height=34,
            fg_color="#1E293B",
            hover_color="#334155",
            command=self.logout,
        ).pack(side="bottom", fill="x", padx=12, pady=(0, 8))

    def build_main(self) -> None:
        self.main = ctk.CTkFrame(self, fg_color="white", corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")

        for name in ("Dashboard", "Setup", "Backup", "Restore", "Recovery"):
            frame = ctk.CTkFrame(self.main, fg_color="white")
            ctk.CTkLabel(
                frame,
                text=name,
                font=("Arial", 24, "bold"),
                text_color=NAVY,
            ).pack(anchor="w", padx=30, pady=(26, 10))
            self.page_frames[name] = frame

        self.build_dashboard()
        self.build_setup()
        self.build_backup()
        self.build_restore()
        self.build_recovery()

    def build_splash(self) -> None:
        splash = ctk.CTkFrame(self, fg_color=NAVY, corner_radius=0)
        splash.place(x=0, y=0, relwidth=1, relheight=1)

        box = ctk.CTkFrame(splash, fg_color="transparent")
        box.place(relx=0.5, rely=0.46, anchor="center")
        self.logo(box, 96).pack()
        ctk.CTkLabel(
            box,
            text="SecureVault",
            font=("Arial", 36, "bold"),
            text_color="white",
        ).pack(pady=(18, 0))
        ctk.CTkLabel(
            box,
            text="Encrypted Backup & Two-Custodian Recovery",
            text_color="#94A3B8",
        ).pack(pady=(2, 0))

        self.progress = ctk.CTkProgressBar(
            box, width=300, progress_color="#3B82F6", fg_color="#1E293B"
        )
        self.progress.set(0)
        self.progress.pack(pady=(30, 0))
        ctk.CTkLabel(
            box,
            text="Initialising encryption engine...",
            text_color="#64748B",
        ).pack(pady=8)

        self.splash = splash
        self.tick_splash(0)

    def tick_splash(self, value: int) -> None:
        self.progress.set(value / 20)
        if value < 20:
            self.after(110, lambda: self.tick_splash(value + 1))
        else:
            self.splash.place_forget()

    def logo(self, parent: ctk.CTkFrame, size: int = 96) -> ctk.CTkFrame:
        box = ctk.CTkFrame(
            parent,
            width=size,
            height=size,
            corner_radius=size // 4,
            fg_color=BLUE,
        )
        box.pack_propagate(False)
        ctk.CTkLabel(
            box,
            text="SV",
            font=("Arial", max(18, size // 3), "bold"),
            text_color="white",
        ).pack(expand=True)
        return box

    def build_login(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="white", corner_radius=0)
        frame.place(x=0, y=0, relwidth=1, relheight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(frame, width=400, corner_radius=0, fg_color=NAVY)
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_propagate(False)
        self.logo(left, 56).pack(anchor="w", padx=40, pady=(40, 0))
        ctk.CTkLabel(
            left,
            text="Protect your backups.",
            font=("Arial", 26, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=40, pady=(110, 0))
        ctk.CTkLabel(
            left,
            text="Share the key.",
            font=("Arial", 26, "bold"),
            text_color="#60A5FA",
        ).pack(anchor="w", padx=40)

        benefits = (
            "AES-256-GCM encryption",
            "Integrity checked on every restore",
            "Two custodians required for recovery",
            "Every action recorded in an audit log",
        )
        for benefit in benefits:
            ctk.CTkLabel(
                left,
                text="✓  " + benefit,
                text_color="#CBD5E1",
            ).pack(anchor="w", padx=40, pady=(14, 0))

        right = ctk.CTkFrame(frame, fg_color="white", corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew")
        box = ctk.CTkFrame(right, fg_color="transparent")
        box.place(relx=0.5, rely=0.46, anchor="center")
        self.auth_title = ctk.CTkLabel(
            box,
            text="Welcome back",
            font=("Arial", 26, "bold"),
            text_color=NAVY,
        )
        self.auth_title.pack(anchor="w")
        self.auth_subtitle = ctk.CTkLabel(
            box,
            text="Sign in to continue to your vault",
            text_color=MUTED,
        )
        self.auth_subtitle.pack(anchor="w", pady=(0, 18))
        ctk.CTkLabel(box, text="Username", anchor="w").pack(fill="x")
        self.user_entry = ctk.CTkEntry(box, width=320, height=38)
        self.user_entry.pack(pady=(2, 14))
        ctk.CTkLabel(box, text="Password", anchor="w").pack(fill="x")
        self.password_entry = ctk.CTkEntry(
            box, width=320, height=38, show="•"
        )
        self.password_entry.pack(pady=(2, 14))
        self.password_entry.bind("<Return>", lambda event: self.submit_auth())
        self.confirm_label = ctk.CTkLabel(box, text="Confirm password", anchor="w")
        self.confirm_entry = ctk.CTkEntry(
            box, width=320, height=38, show="•"
        )
        self.confirm_entry.bind("<Return>", lambda event: self.submit_auth())
        self.auth_mode = "login"
        self.auth_submit_button = ctk.CTkButton(
            box, text="Sign in", height=40, command=self.submit_auth
        )
        self.auth_submit_button.pack(fill="x")
        self.auth_toggle_button = ctk.CTkButton(
            box,
            text="Create an account",
            height=34,
            fg_color="transparent",
            text_color=BLUE,
            hover_color="#EFF6FF",
            command=self.toggle_auth_mode,
        )
        self.auth_toggle_button.pack(fill="x", pady=(6, 0))
        self.login_message = ctk.CTkLabel(
            box, text="", wraplength=320, justify="left"
        )
        self.login_message.pack(anchor="w", pady=(10, 0))
        ctk.CTkLabel(
            box,
            text="Accounts are stored locally on this computer.",
            text_color=MUTED,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))
        self.login_frame = frame

    def toggle_auth_mode(self) -> None:
        self.login_message.configure(text="")
        if self.auth_mode == "login":
            self.auth_mode = "signup"
            self.auth_title.configure(text="Create an account")
            self.auth_subtitle.configure(text="Register local access to your vault")
            self.confirm_label.pack(fill="x", before=self.auth_submit_button)
            self.confirm_entry.pack(
                pady=(2, 14), before=self.auth_submit_button
            )
            self.auth_submit_button.configure(text="Create account")
            self.auth_toggle_button.configure(text="Back to sign in")
        else:
            self.auth_mode = "login"
            self.auth_title.configure(text="Welcome back")
            self.auth_subtitle.configure(text="Sign in to continue to your vault")
            self.confirm_label.pack_forget()
            self.confirm_entry.pack_forget()
            self.confirm_entry.delete(0, "end")
            self.auth_submit_button.configure(text="Sign in")
            self.auth_toggle_button.configure(text="Create an account")

    def submit_auth(self) -> None:
        if self.auth_mode == "signup":
            self.signup()
        else:
            self.login()

    def login(self) -> None:
        name = self.user_entry.get().strip()
        password = self.password_entry.get()
        if not name or not password:
            self.login_message.configure(
                text="Enter your username and password.", text_color=RED
            )
            return
        try:
            authenticated = authenticate_user(name, password)
        except (OSError, ValueError) as exc:
            self.login_message.configure(text=str(exc), text_color=RED)
            return
        if not authenticated:
            self.logger.warning("Login rejected for username: %s", name)
            record_event("login", "failure", f"username={name}")
            self.login_message.configure(
                text="Incorrect username or password.", text_color=RED
            )
            return

        self.operator = name
        self.operator_label.configure(text=f"Signed in: {name}")
        self.login_message.configure(text="")
        self.password_entry.delete(0, "end")
        self.login_frame.place_forget()
        self.show_page("Dashboard")
        self.logger.info("Operator signed in: %s", name)
        record_event("login", "success", f"username={name}")

    def signup(self) -> None:
        name = self.user_entry.get().strip()
        password = self.password_entry.get()
        confirmation = self.confirm_entry.get()
        if not name or not password or not confirmation:
            self.login_message.configure(
                text="Complete the username and both password fields.",
                text_color=RED,
            )
            return
        if password != confirmation:
            self.login_message.configure(
                text="The passwords do not match.", text_color=RED
            )
            return
        try:
            register_user(name, password)
        except (OSError, ValueError) as exc:
            record_event("signup", "failure", str(exc))
            self.logger.warning("Account registration rejected for %s: %s", name, exc)
            self.login_message.configure(text=str(exc), text_color=RED)
            return

        self.logger.info("Account registered: %s", name)
        record_event("signup", "success", f"username={name}")
        self.password_entry.delete(0, "end")
        self.confirm_entry.delete(0, "end")
        self.toggle_auth_mode()
        self.login_message.configure(
            text="Account created. Sign in with your new credentials.",
            text_color=GREEN,
        )

    def logout(self) -> None:
        self.logger.info("Operator signed out: %s", self.operator)
        self.operator = ""
        self.user_entry.delete(0, "end")
        self.password_entry.delete(0, "end")
        self.confirm_entry.delete(0, "end")
        if self.auth_mode != "login":
            self.toggle_auth_mode()
        self.operator_label.configure(text="")
        self.login_frame.place(x=0, y=0, relwidth=1, relheight=1)
        self.login_frame.lift()

    def show_page(self, name: str) -> None:
        for frame in self.page_frames.values():
            frame.pack_forget()
        self.page_frames[name].pack(fill="both", expand=True)
        if name == "Dashboard":
            self.refresh_dashboard()

    def field(
        self,
        parent: ctk.CTkFrame,
        label: str,
        default: str = "",
        browse: str | None = None,
        secret: bool = False,
    ) -> ctk.CTkEntry:
        ctk.CTkLabel(parent, text=label, anchor="w").pack(
            fill="x", padx=30, pady=(10, 0)
        )
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=30)
        entry = ctk.CTkEntry(
            row, show="•" if secret else "", height=34
        )
        entry.pack(side="left", fill="x", expand=True)
        entry.insert(0, default)
        if browse:
            ctk.CTkButton(
                row,
                text="Browse",
                width=80,
                command=lambda: self.choose(entry, browse),
            ).pack(side="left", padx=(8, 0))
        return entry

    def choose(self, entry: ctk.CTkEntry, mode: str) -> None:
        selected = ""
        if mode == "dir":
            selected = filedialog.askdirectory(title="Select folder")
        elif mode == "open":
            selected = filedialog.askopenfilename(title="Select file")
        elif mode == "save-bin":
            selected = filedialog.asksaveasfilename(
                title="Save encrypted backup",
                defaultextension=".bin",
                filetypes=[("Backup", "*.bin"), ("All files", "*.*")],
            )
        elif mode == "save-share":
            selected = filedialog.asksaveasfilename(
                title="Save recovery share",
                defaultextension=".key",
                filetypes=[("Key share", "*.key"), ("All files", "*.*")],
            )
        if selected:
            entry.delete(0, "end")
            entry.insert(0, selected)

    def action(
        self,
        parent: ctk.CTkFrame,
        text: str,
        command,
    ) -> ctk.CTkLabel:
        banner = ctk.CTkLabel(
            parent,
            text="",
            wraplength=620,
            anchor="w",
            justify="left",
        )
        ctk.CTkButton(
            parent,
            text=text,
            height=38,
            command=lambda: self.run_action(command, banner),
        ).pack(anchor="w", padx=30, pady=(18, 8))
        banner.pack(fill="x", padx=30)
        return banner

    def run_action(self, command, banner: ctk.CTkLabel) -> None:
        ok, message = command()
        banner.configure(
            text=("OK  " if ok else "FAILED  ") + message,
            text_color=GREEN if ok else RED,
        )

    def build_dashboard(self) -> None:
        frame = self.page_frames["Dashboard"]
        cards = ctk.CTkFrame(frame, fg_color="transparent")
        cards.pack(fill="x", padx=30, pady=10)
        self.card_values: list[ctk.CTkLabel] = []
        for title in ("Custody", "Last backup", "Log entries"):
            card = ctk.CTkFrame(cards, fg_color="#F1F5F9", corner_radius=10)
            card.pack(side="left", expand=True, fill="x", padx=(0, 12))
            ctk.CTkLabel(
                card, text=title, text_color=MUTED
            ).pack(anchor="w", padx=14, pady=(10, 0))
            value = ctk.CTkLabel(
                card,
                text="-",
                font=("Arial", 18, "bold"),
                text_color=NAVY,
            )
            value.pack(anchor="w", padx=14, pady=(0, 12))
            self.card_values.append(value)

        ctk.CTkLabel(
            frame, text="Recent activity", anchor="w"
        ).pack(fill="x", padx=30)
        self.log_box = ctk.CTkTextbox(frame, height=330)
        self.log_box.pack(fill="both", expand=True, padx=30, pady=(4, 24))

    def refresh_dashboard(self) -> None:
        log_path = Path(__file__).resolve().parent / "logs" / "activity.log"
        lines = (
            log_path.read_text(encoding="utf-8").splitlines()
            if log_path.exists()
            else []
        )
        backup_count = sum("Encrypted backup created" in line for line in lines)
        self.card_values[0].configure(text="2-of-2")
        self.card_values[1].configure(text=str(backup_count))
        self.card_values[2].configure(text=str(len(lines)))
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", "\n".join(reversed(lines[-50:])))
        self.log_box.configure(state="disabled")

    def build_setup(self) -> None:
        frame = self.page_frames["Setup"]
        ctk.CTkLabel(
            frame,
            text="Create a backup and store each generated share in a separate location.",
            text_color=MUTED,
            wraplength=650,
            justify="left",
        ).pack(anchor="w", padx=30)
        ctk.CTkButton(
            frame,
            text="Open Backup Setup",
            height=38,
            command=lambda: self.show_page("Backup"),
        ).pack(anchor="w", padx=30, pady=(18, 8))

    def build_backup(self) -> None:
        frame = self.page_frames["Backup"]
        source = self.field(frame, "Folder to back up", browse="dir")
        archive = self.field(
            frame,
            "Output backup file",
            str(Path("encrypted_backups") / "course-backup.bin"),
            browse="save-bin",
        )
        share1 = self.field(
            frame,
            "Custodian 1 share",
            str(Path("custodian1") / "recovery_share_1.key"),
            browse="save-share",
        )
        share2 = self.field(
            frame,
            "Custodian 2 share",
            str(Path("custodian2") / "recovery_share_2.key"),
            browse="save-share",
        )

        def command():
            if not all((source.get(), archive.get(), share1.get(), share2.get())):
                return False, "Complete all backup fields"
            if Path(share1.get()) == Path(share2.get()):
                return False, "Use separate files for Custodian 1 and Custodian 2"
            try:
                result = create_backup(
                    Path(source.get()),
                    Path(archive.get()),
                    Path(share1.get()),
                    Path(share2.get()),
                )
                record_event(
                    "create_backup",
                    "success",
                    f"{result['file_count']} files",
                )
                self.logger.info(
                    "Encrypted backup created: %s files",
                    result["file_count"],
                )
                return True, json.dumps(result, indent=2)
            except (BackupError, OSError, ValueError) as exc:
                record_event("create_backup", "failure", str(exc))
                self.logger.error("Backup failed: %s", exc)
                return False, str(exc)

        self.action(frame, "Encrypt & Backup", command)

    def build_restore(self) -> None:
        frame = self.page_frames["Restore"]
        archive = self.field(
            frame,
            "Backup file",
            str(Path("encrypted_backups") / "course-backup.bin"),
            browse="open",
        )
        destination = self.field(
            frame,
            "Restore to folder",
            str(Path("restored_files")),
            browse="dir",
        )
        share1 = self.field(
            frame,
            "Custodian 1 share",
            str(Path("custodian1") / "recovery_share_1.key"),
            browse="open",
        )
        share2 = self.field(
            frame,
            "Custodian 2 share",
            str(Path("custodian2") / "recovery_share_2.key"),
            browse="open",
        )

        def command():
            if not all((archive.get(), destination.get(), share1.get(), share2.get())):
                return False, "Complete all restore fields"
            try:
                result = restore_backup(
                    Path(archive.get()),
                    Path(destination.get()),
                    Path(share1.get()),
                    Path(share2.get()),
                )
                record_event(
                    "restore_backup",
                    "success",
                    f"{result['restored_file_count']} files",
                )
                self.logger.info(
                    "Restore completed: %s files",
                    result["restored_file_count"],
                )
                return True, json.dumps(result, indent=2)
            except (BackupError, OSError, ValueError) as exc:
                record_event("restore_backup", "failure", str(exc))
                self.logger.error("Restore failed: %s", exc)
                return False, str(exc)

        self.action(frame, "Restore & Verify", command)

    def build_recovery(self) -> None:
        frame = self.page_frames["Recovery"]
        ctk.CTkLabel(
            frame,
            text="Two-custodian recovery",
            font=("Arial", 18, "bold"),
            text_color=NAVY,
        ).pack(anchor="w", padx=30)
        ctk.CTkLabel(
            frame,
            text=(
                "Use the Restore page with both share files present. "
                "The application rejects missing, wrong, and unauthorised shares."
            ),
            text_color=MUTED,
            wraplength=650,
            justify="left",
        ).pack(anchor="w", padx=30, pady=(8, 12))
        ctk.CTkButton(
            frame,
            text="Open Recovery/Restore",
            height=38,
            command=lambda: self.show_page("Restore"),
        ).pack(anchor="w", padx=30)


def main() -> int:
    app = SecureVaultApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
