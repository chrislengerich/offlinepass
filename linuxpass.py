#!/usr/bin/env python3
"""linuxpass — TUI for searching Proton Pass entries and displaying QR codes."""

from __future__ import annotations

import curses
import json
import os
import subprocess
import sys

from passlib import (
    PasswordStore, ProtonItem,
    generate_password, generate_alias,
    generate_totp, totp_secret_from_input,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _qr_ansiutf8(text: str) -> str:
    """Render QR code as ANSI UTF-8 string using qrencode (Unicode blocks + colors)."""
    result = subprocess.run(
        ["qrencode", "-t", "ANSIUTF8", "-o", "-", "-l", "L", "-m", "2"],
        input=text, capture_output=True, text=True,
    )
    return result.stdout if result.stdout else ""


# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

class TUI:
    MENU_ITEMS = [
        ("Search", "action_search"),
        ("Add entry", "action_add_entry"),
        ("Show git repo location", "action_git_location"),
        ("Quit", "action_quit"),
    ]

    def __init__(self, store: PasswordStore):
        self.store = store
        self.items: list[ProtonItem] = []
        self.stdscr = None

    # -- curses lifecycle --------------------------------------------------

    def run(self, stdscr) -> None:
        self.stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        self._load_items()
        self._main_menu()

    def _load_items(self) -> None:
        try:
            self.items = self.store.load()
        except Exception as e:
            self._show_message(f"Failed to load: {e}")
            self.items = []

    # -- generic UI primitives ---------------------------------------------

    def _show_message(self, msg: str) -> None:
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        wrapped = self._wrap(msg, w - 4)
        for i, line in enumerate(wrapped[:h - 3]):
            self.stdscr.addstr(i + 1, 2, line)
        self.stdscr.addstr(h - 2, 2, "[Press any key]")
        self.stdscr.getch()

    def _wrap(self, text: str, width: int) -> list[str]:
        lines: list[str] = []
        for paragraph in text.split("\n"):
            words = paragraph.split()
            line = ""
            for word in words:
                if len(line) + len(word) + 1 <= width:
                    line = (line + " " + word).strip()
                else:
                    lines.append(line)
                    line = word
            lines.append(line)
        return lines

    def _menu(self, title: str, options: list[tuple[str, str]], last: int = 0) -> int:
        """Display a menu and return selected index. Returns -1 on cancel."""
        sel = last
        while True:
            h, w = self.stdscr.getmaxyx()
            self.stdscr.erase()
            self.stdscr.addstr(0, 0, title[:w - 1], curses.A_BOLD)
            max_visible = min(len(options), h - 3)
            offset = max(0, sel - max_visible + 1) if sel >= max_visible else 0
            for i in range(max_visible):
                idx = i + offset
                label, _ = options[idx]
                attr = curses.A_REVERSE if idx == sel else curses.A_NORMAL
                self.stdscr.addstr(i + 2, 0, f"  {label[:w - 3]}", attr)
            self.stdscr.addstr(h - 1, 0, "↑↓ navigate  Enter select  q cancel"[:w - 1], curses.A_DIM)
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                sel = max(0, sel - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                sel = min(len(options) - 1, sel + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return sel
            elif key in (ord("q"), 27):
                return -1

    def _text_input(self, prompt: str, prefill: str = "") -> str:
        """Inline text input at bottom of screen."""
        h, w = self.stdscr.getmaxyx()
        curses.curs_set(1)
        buf = list(prefill)
        while True:
            self.stdscr.move(h - 2, 0)
            self.stdscr.clrtoeol()
            self.stdscr.addstr(h - 2, 0, f"{prompt}: ", curses.A_BOLD)
            text = "".join(buf)
            self.stdscr.addstr(h - 2, len(prompt) + 2, text[:w - len(prompt) - 4])
            self.stdscr.move(h - 2, len(prompt) + 2 + min(len(buf), w - len(prompt) - 4))
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in (curses.KEY_ENTER, 10, 13):
                curses.curs_set(0)
                return "".join(buf)
            elif key in (27,):
                curses.curs_set(0)
                return ""
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
            elif 32 <= key <= 126:
                buf.append(chr(key))

    def _qr_display(self, text: str, title: str = "QR Code") -> None:
        """Display QR code as a terminal image.

        Exits curses, prints the QR using qrencode ANSIUTF8 (Unicode blocks
        + ANSI colors), waits for a keypress, then re-enters curses.
        """
        qr = _qr_ansiutf8(text)
        curses.endwin()
        print(f"\n  {title}")
        print(f"  Scan with QR Autofill app\n")
        print(qr)
        print(f"\n  [Press Enter to return]")
        sys.stdin.readline()
        self.stdscr = curses.initscr()
        curses.curs_set(0)
        self.stdscr.keypad(True)
        self.stdscr.redrawln(0, self.stdscr.getmaxyx()[0])
        self.stdscr.refresh()

    # -- main menu ---------------------------------------------------------

    def _main_menu(self) -> None:
        while True:
            sel = self._menu("linuxpass", self.MENU_ITEMS)
            if sel < 0:
                break
            _, action = self.MENU_ITEMS[sel]
            getattr(self, action)()

    # -- actions -----------------------------------------------------------

    def action_quit(self) -> None:
        raise KeyboardInterrupt

    def action_git_location(self) -> None:
        git_dir = self.store.git_dir
        has_git = os.path.isdir(os.path.join(git_dir, ".git"))
        status = "active" if has_git else "not initialized"
        self._show_message(
            f"Git repo: {git_dir}\n"
            f"Status: {status}\n"
            f"Data file: {self.store.path}"
        )

    def action_search(self) -> None:
        query = self._text_input("Search (website / user / email)")
        if not query:
            return
        results = [it for it in self.items if it.matches(query)]
        if not results:
            self._show_message("No matching entries found.")
            return
        self._show_results(results)

    def action_add_entry(self) -> None:
        choice = self._menu("Add entry — identity type", [
            ("Username", "user"),
            ("Email alias (SimpleLogin)", "alias"),
        ])
        if choice < 0:
            return
        url = self._text_input("URL")
        if not url:
            return
        username = ""
        email = ""
        note = ""
        if choice == 0:
            username = self._text_input("Username")
        else:
            email = generate_alias()
            self._show_message(f"SimpleLogin alias generated:\n{email}\n\n(Stub — not actually registered)\n\nPress any key.")
            note = "Created via linuxpass (SimpleLogin stub)"
        pw = generate_password()
        self._show_message(f"Generated password:\n{pw}\n\nPress any key to confirm, then save.")
        item = ProtonItem(
            name="", username=username, email=email,
            password=pw, urls=[url], note=note,
        )
        self.items.append(item)
        self.items.sort(key=lambda i: i.display_name.lower())
        self._save_and_confirm(f"Added entry: {item.display_name}")

    # -- results / detail view --------------------------------------------

    def _show_results(self, results: list[ProtonItem]) -> None:
        sel = 0
        while True:
            options = []
            for it in results:
                ident = it.identity or "(no identity)"
                options.append((f"{it.display_name:30s}  {ident}", ""))
            sel = self._menu(f"Results ({len(results)})", [(o[0], "") for o in options], sel)
            if sel < 0:
                return
            self._show_detail(results[sel])

    def _show_detail(self, item: ProtonItem) -> None:
        while True:
            detail_lines = [
                f"Name:     {item.display_name}",
                f"Username: {item.username or '-'}",
                f"Email:    {item.email or '-'}",
                f"URLs:     {', '.join(item.urls) or '-'}",
                f"Note:     {item.note or '-'}",
                f"TOTP:     {'enrolled' if item.totp_uri else 'not enrolled'}",
            ]
            options = [
                ("Display QR code", "qr"),
                ("Show credentials", "creds"),
                ("Update password", "update"),
                ("Enroll TOTP", "totp"),
                ("Back", "back"),
            ]
            h, w = self.stdscr.getmaxyx()
            self.stdscr.erase()
            self.stdscr.addstr(0, 0, "Entry Detail", curses.A_BOLD)
            for i, line in enumerate(detail_lines):
                self.stdscr.addstr(i + 2, 2, line[:w - 3])
            sel = self._menu_offset("Actions", options, start_row=len(detail_lines) + 4)
            if sel < 0:
                return
            _, action = options[sel]
            if action == "qr":
                qr_text = json.dumps(item.to_proton_json(), separators=(",", ":"))
                self._qr_display(qr_text, f"QR: {item.display_name}")
            elif action == "creds":
                self._show_credentials(item)
            elif action == "update":
                new_pw = generate_password()
                self.stdscr.erase()
                h, w = self.stdscr.getmaxyx()
                lines = [
                    f"Updating: {item.display_name}",
                    "",
                    f"Old password: {item.password}",
                    f"New password: {new_pw}",
                    "",
                    "Enter = confirm    Esc = cancel",
                ]
                for i, line in enumerate(lines):
                    if i + 1 < h - 1:
                        self.stdscr.addstr(i + 1, 2, line[:w - 3])
                self.stdscr.refresh()
                key = self.stdscr.getch()
                if key == 27:
                    self._show_message("Password update cancelled.")
                else:
                    item.password = new_pw
                    self._save_and_confirm(f"Updated password for: {item.display_name}")
            elif action == "totp":
                self._enroll_totp(item)
            elif action == "back":
                return

    def _enroll_totp(self, item: ProtonItem) -> None:
        raw = self._text_input("TOTP secret (base32) or otpauth:// URI")
        if not raw:
            return
        try:
            uri = totp_secret_from_input(raw)
            code, remaining = generate_totp(uri)
            self._show_message(
                f"TOTP enrolled for: {item.display_name}\n\n"
                f"Test code: {code}  (expires in {remaining}s)\n\n"
                f"Press any key to save."
            )
            item.totp_uri = uri
            self._save_and_confirm(f"Enrolled TOTP for: {item.display_name}")
        except Exception as e:
            self._show_message(f"TOTP enrollment failed:\n{e}")

    def _show_credentials(self, item: ProtonItem) -> None:
        """Show username/email/password, plus live TOTP if enrolled."""
        if not item.totp_uri:
            lines = [f"Name:     {item.display_name}"]
            if item.username:
                lines.append(f"Username: {item.username}")
            if item.email:
                lines.append(f"Email:    {item.email}")
            lines.append(f"Password: {item.password}")
            self._show_message("\n".join(lines))
            return

        curses.halfdelay(10)
        try:
            while True:
                try:
                    code, remaining = generate_totp(item.totp_uri)
                except Exception as e:
                    self._show_message(f"TOTP error:\n{e}")
                    return
                self.stdscr.erase()
                h, w = self.stdscr.getmaxyx()
                row = 1
                lines = [
                    f"Name:     {item.display_name}",
                ]
                if item.username:
                    lines.append(f"Username: {item.username}")
                if item.email:
                    lines.append(f"Email:    {item.email}")
                lines.append(f"Password: {item.password}")
                lines.append("")
                lines.append(f"TOTP:     {code}")
                for line in lines:
                    if row < h - 3:
                        self.stdscr.addstr(row, 2, line[:w - 3])
                        row += 1
                bar_len = 20
                filled = int(bar_len * remaining / 30)
                bar = "█" * filled + "░" * (bar_len - filled)
                if row < h - 2:
                    self.stdscr.addstr(row, 2, f"Refresh:  {bar} {remaining}s")
                    row += 1
                self.stdscr.addstr(h - 2, 2, "[Press any key to exit]", curses.A_DIM)
                self.stdscr.refresh()
                key = self.stdscr.getch()
                if key != -1:
                    break
        finally:
            curses.cbreak()

    def _menu_offset(self, title: str, options: list[tuple[str, str]], start_row: int = 0) -> int:
        """Menu that starts at a specific row offset."""
        sel = 0
        while True:
            h, w = self.stdscr.getmaxyx()
            self.stdscr.addstr(start_row, 0, title[:w - 1], curses.A_BOLD)
            for i, (label, _) in enumerate(options):
                attr = curses.A_REVERSE if i == sel else curses.A_NORMAL
                row = start_row + 2 + i
                if row < h - 1:
                    self.stdscr.addstr(row, 2, f"  {label[:w - 5]}", attr)
            self.stdscr.addstr(h - 1, 0, "↑↓ navigate  Enter select  q back"[:w - 1], curses.A_DIM)
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                sel = max(0, sel - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                sel = min(len(options) - 1, sel + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return sel
            elif key in (ord("q"), 27):
                return -1

    # -- save --------------------------------------------------------------

    def _save_and_confirm(self, msg: str) -> None:
        try:
            self.store.save(self.items)
            self._show_message(f"✓ {msg}\n\nSaved and committed to git.")
        except Exception as e:
            self._show_message(f"Save failed: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    # Config — override with env vars
    data_path = os.environ.get("LINUXPASS_FILE", os.path.expanduser("~/linuxpass/test_data.json"))
    # Multi-recipient (comma-separated), with back-compat for the single form.
    recipients = (os.environ.get("LINUXPASS_GPG_RECIPIENTS")
                  or os.environ.get("LINUXPASS_GPG_RECIPIENT"))
    recipient_list = (
        [r.strip() for r in recipients.split(",") if r.strip()]
        if recipients else None
    )
    use_gpg = os.environ.get("LINUXPASS_USE_GPG", "0") == "1"
    git_dir = os.environ.get("LINUXPASS_GIT_DIR")

    store = PasswordStore(
        path=data_path,
        gpg_recipients=recipient_list,
        use_gpg=use_gpg,
        git_dir=git_dir,
    )

    try:
        store.git_pull()  # best-effort sync before use
    except Exception:
        pass

    try:
        curses.wrapper(TUI(store).run)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            # The TUI is down: the tty is free for any ssh key touch.
            store.git_push(timeout=120)
        except Exception:
            pass


if __name__ == "__main__":
    main()
