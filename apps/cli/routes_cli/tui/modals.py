"""Dialogs: permission confirmation, hidden token entry, repository match."""

from __future__ import annotations

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ConfirmModal(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def __init__(self, title: str, body: str, *, yes: str = "Confirm", no: str = "Cancel"):
        super().__init__()
        self.title_text, self.body, self.yes, self.no = title, body, yes, no

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(escape(self.title_text), classes="dialog-title")
            yield Static(self.body, classes="dialog-body")
            with Horizontal(classes="buttons"):
                yield Button(self.no, id="no")
                yield Button(self.yes, id="yes", classes="primary")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class TokenModal(ModalScreen[str | None]):
    """Hidden entry. The value goes straight to the caller, never to prompt history."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    def __init__(self, repo_label: str):
        super().__init__()
        self.repo_label = repo_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("GitHub access token", classes="dialog-title")
            yield Static(f"Private repository [b]{escape(self.repo_label)}[/b]. Use a fine-grained token with "
                         "[b]Contents: Read-only[/b] for this repository only. It is handed to the engine in memory, "
                         "used once by the network gateway and never stored.", classes="dialog-body")
            yield Input(password=True, placeholder="github_pat_…", id="token")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="no")
                yield Button("Continue", id="yes", classes="primary")

    def on_mount(self) -> None:
        self.query_one("#token", Input).focus()

    def _finish(self, ok: bool) -> None:
        field = self.query_one("#token", Input)
        value = field.value if ok else None
        field.value = ""
        self.dismiss(value or None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._finish(True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._finish(event.button.id == "yes")


class MatchModal(ModalScreen[str]):
    BINDINGS = [Binding("escape", "dismiss('pending')", "Skip", show=False)]

    def __init__(self, question: str):
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static("Repository and website", classes="dialog-title")
            yield Static(escape(self.question) + "\n\n[dim]If yes, ROUTES links website endpoints to the route "
                         "handlers it finds in the code.[/dim]", classes="dialog-body")
            with Horizontal(classes="buttons"):
                yield Button("Not sure", id="pending")
                yield Button("No", id="rejected")
                yield Button("Yes", id="confirmed", classes="primary")

    def on_mount(self) -> None:
        self.query_one("#pending", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id)
