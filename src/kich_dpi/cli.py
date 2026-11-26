"""Command table and top-level error envelope.

The panel only ever sees one JSON object per line, so every command is a plain
callable. One row in COMMANDS defines the name, the handler and the help line;
the dispatcher and `kich-dpi --help` are both rendered from those rows.
"""
from __future__ import annotations

import sys
from collections import namedtuple

from . import constants as C
from . import core
from . import engine
from . import repair
from . import status
from . import strategies
from . import warp

Command = namedtuple("Command", "name usage help section handler")

INTRO = """kich-dpi: a small zapret2 DPI bypass manager for Omarchy.

The plugin generates nfqws2 configurations from a handful of primitives,
measures them against blocked services, and keeps the best one. WARP is an
optional second engine. Everything the panel needs is one JSON object."""

SECTIONS = {
    "main": "Commands:",
    "warp": "WARP (MASQUE, необязательно):",
}


def _arg(argv, index, usage):
    if len(argv) <= index:
        raise core.Fail(usage)
    return argv[index]


# Aliases share a help line by repeating its `usage`; only the first row needs
# `help`. Commands with an empty help text are callable but undocumented.
COMMANDS = (
    Command("status", "status", "состояние для панели (JSON)", "main",
            lambda argv: status.cmd_status),
    Command("on", "on | off | toggle", "включить/выключить службу", "main",
            lambda argv: strategies.cmd_on),
    Command("off", "on | off | toggle", "", "main",
            lambda argv: strategies.cmd_off),
    Command("toggle", "on | off | toggle", "", "main",
            lambda argv: strategies.cmd_toggle),
    Command("check", "check", "проверить YouTube, Discord и Google", "main",
            lambda argv: strategies.cmd_check),
    Command("check-all", "check-all", "проверить только включённые сервисы + систему",
            "main", lambda argv: status.cmd_check_all),
    Command("generate", "generate", "собрать и измерить стратегии, оставить лучшую",
            "main", lambda argv: lambda: strategies.cmd_generate("--force" in argv)),
    Command("strategies", "strategies", "сохранённые стратегии", "main",
            lambda argv: status.cmd_strategies),
    Command("use", "use <id>", "применить сохранённую стратегию", "main",
            lambda argv: lambda: strategies.cmd_use(
                _arg(argv, 2, "использование: use <id>"))),
    Command("setup", "setup [archive]", "установить движок (pkexec)", "main",
            lambda argv: lambda: engine.cmd_setup(
                _arg(argv, 2, "") if len(argv) > 2 else "")),
    Command("update", "update", "обновить движок (pkexec)", "main",
            lambda argv: lambda: engine.cmd_setup("")),
    Command("remove", "remove [--purge]", "удалить системную часть (pkexec)", "main",
            lambda argv: lambda: engine.cmd_remove("--purge" in argv)),
    Command("logs", "logs [N]", "последние строки журнала", "main",
            lambda argv: lambda: status.cmd_logs(
                int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 80)),
    Command("doctor", "doctor", "диагностика", "main",
            lambda argv: status.cmd_doctor),
    Command("repair", "repair", "исправить известные поломки одной командой", "main",
            lambda argv: repair.cmd_repair),
    Command("restart", "", "", "main", lambda argv: strategies.cmd_restart),

    Command("warp-on", "warp-on | warp-off | warp-toggle", "", "warp",
            lambda argv: warp.cmd_warp_on),
    Command("warp-off", "warp-on | warp-off | warp-toggle", "", "warp",
            lambda argv: warp.cmd_warp_off),
    Command("warp-toggle", "warp-on | warp-off | warp-toggle", "", "warp",
            lambda argv: warp.cmd_warp_toggle),
    Command("warp-register", "warp-register", "перерегистрировать аккаунт Cloudflare",
            "warp", lambda argv: lambda: warp.cmd_warp_register("--force" in argv)),
    Command("warp-check", "warp-check", "проверить, идёт ли трафик через WARP",
            "warp", lambda argv: warp.cmd_warp_check),
    Command("warp-config", "warp-config", "пересобрать конфиг из текущего шаблона",
            "warp", lambda argv: lambda: warp.cmd_warp_config("--force" in argv)),

    Command("_run", "", "", None, lambda argv: engine.cmd_run),
    Command("_fw-down", "", "", None, lambda argv: engine.cmd_fw_down),
)

INTERNAL_COMMANDS = tuple(c.name for c in COMMANDS if c.name.startswith("_"))


HELP_USAGE_WIDTH = 22


def _help_text():
    lines = INTRO.splitlines()
    lines.append("")
    section = None
    shown = set()
    for command in COMMANDS:
        if not command.usage or command.section is None or command.usage in shown:
            continue
        shown.add(command.usage)
        if command.section != section:
            if section is not None:
                lines.append("")
            lines.append(SECTIONS[command.section])
            section = command.section
        if len(command.usage) > HELP_USAGE_WIDTH or not command.help:
            lines.append("  " + command.usage)
        else:
            lines.append("  %-*s %s" % (HELP_USAGE_WIDTH, command.usage, command.help))
    return "\n".join(lines) + "\n"


HELP_TEXT = _help_text()


def command_handlers(argv):
    return {command.name: command.handler(argv) for command in COMMANDS}


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        sys.stdout.write(HELP_TEXT)
        return 0

    try:
        warp.migrate_account(C.HOME)
        handlers = command_handlers(argv)
        command = argv[1]
        if command not in handlers:
            raise core.Fail("неизвестная команда: %s" % command)
        handler = handlers[command]
        if command in INTERNAL_COMMANDS:
            return handler()
        handler()
    except core.Fail as exc:
        core.out({"ok": False, "error": str(exc)})
    except KeyboardInterrupt:
        core.out({"ok": False, "error": "прервано"})
    except Exception as exc:  # never take the panel down with a stack trace
        core.out({"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)})
    return 0
