import rich
from rich.prompt import Prompt,Confirm, IntPrompt
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

import lib


class UI:
    def __init__(self, console, settings):
        self.console = console
        self.settings = settings
        self.cache = []
        self.layout = self.make_layout(settings)




    # FOOTER
    def make_output(self):
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", no_wrap=True)
        grid.add_row(lib.stylize("Starting run...", 'status'))
        self.cache.append(lib.stylize("Starting run...", 'status'))
        message_panel = Panel(
            Align.left(
                Group(Align.center(grid)),
                vertical="top",
            ),
            padding=(1, 2),
            border_style="#00afd7",
            title="Settings",
        )
        return message_panel
    def make_settings(self, settings):
        #
        # Title Table
        #
        caption = f"""[#EA549F]General YARA Rules Enabled:[/#EA549F] [bold white]{settings['rule_count'][0]}[/bold white]
        [#EA549F]Binary YARA Rules Enabled:[/#EA549F] [bold white]{settings['rule_count'][1]}[/bold white]"""
        settings_table = Table(leading=1, caption=caption, caption_style="default", caption_justify="center")
        if settings['workpath'] == 'Not Set':
            settings_table.add_column("[bold #EA549F]Setting[/bold #EA549F]", width=25,
                                      justify="center")
            settings_table.add_column("[bold #EA549F]Value[/bold #EA549F]", width=25, no_wrap=True,
                                      justify="center")
        else:
            settings_table.add_column("[bold #EA549F]Setting[/bold #EA549F]", max_width=25, justify="left")
            settings_table.add_column("[bold #EA549F]Value[/bold #EA549F]", max_width=25, no_wrap=True,
                                      justify="center")
        for x in settings.keys():
            if x not in ['search_rules', 'binary_rules', 'rule_count']:
                settings_table.add_row(f"[bold]{x}[/bold]",
                                       Syntax(f"{settings[x]}", 'python', background_color="default"))

        message_panel = Panel(
            Align.center(
                Group(Align.center(settings_table), Align.center("\n")),
                vertical="middle",
            ),
            padding=(1, 2),
            border_style="#00afd7",
            title="Settings"
        )
        return message_panel
    def make_title(self) -> Panel:
        """Some example content."""
        sponsor_message = Table.grid(padding=1)
        sponsor_message.add_column(style="#EA549F", justify="left")
        sponsor_message.add_column(no_wrap=True, justify="right")
        sponsor_message.add_row(
            "My Github:",
            "[u blue link=https://github.com/Mili-NT/]https://github.com/Mili-NT/",
        )
        sponsor_message.add_row(
            "Project Page:",
            "[u blue link=https://github.com/Mili-NT/BinBot]https://github.com/Mili-NT/BinBot",
        )
        sponsor_message.add_row(
            "Supported Services:",
            "[blue]Pastebin[/blue], [blue]Slexy[/blue], [blue]Ix.io[/blue]",
        )
        intro_message = Text.from_markup(
            """[#EA549F]Welcome to BinBot![/#EA549F]"""
        )

        message = Table.grid(padding=1)
        message.add_column(justify="center")
        message.add_column(no_wrap=True, justify="center")
        message.add_row(intro_message, sponsor_message)

        message_panel = Panel(
            Align.center(
                Group(Align.center(intro_message), "\n", Align.center(sponsor_message)),
                vertical="middle",
            ),
            padding=(1, 2),
            title="[bold #EA549F]Made By Mili-NT[/bold #EA549F]",
            border_style="#00afd7",
        )
        return message_panel
    def make_layout(self, settings) -> Layout:
        """Define the layout."""
        layout = Layout(name="root")
        layout.split(
            Layout(name="main", ratio=1),
        )
        layout["main"].split_row(
            Layout(name="Sidebar"),
            Layout(name="Output", ratio=2, minimum_size=60),
        )

        layout["Sidebar"].split(Layout(name="Title"), Layout(name="Settings"))
        layout["Output"].update(self.make_output())
        layout["Settings"].update(self.make_settings(settings))
        layout["Title"].update(self.make_title())
        return layout
    def update_settings(self, settings):
        self.layout["settings"].update(self.make_settings(settings))
    def update_output(self, message):
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", no_wrap=True)
        if len(self.cache) <= 44:
            for cached_message in self.cache:
                grid.add_row(cached_message)
        else:
            self.cache = []
        grid.add_row(message)
        self.cache.append(message)
        message_panel = Panel(
            Align.left(
                Group(Align.center(grid)),
                vertical="top",
            ),
            padding=(1, 2),
            border_style="#00afd7",
            title="Settings",
        )
        self.layout["Output"].update(message_panel)
