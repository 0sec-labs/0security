"""Tools the research assistant can call. Planted flaws are intentional: this is a benchmark fixture."""
import json
import subprocess
import urllib.request

ALLOWED_DIAGNOSTICS = {"disk": ["df", "-h"], "uptime": ["uptime"]}


def fetch_page(url: str) -> str:
    # Public web pages: the text is written by whoever owns the page.
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read(200_000).decode("utf-8", "replace")


def run_diagnostic(name: str) -> str:
    command = ALLOWED_DIAGNOSTICS.get(name)
    if command is None:
        return "unknown diagnostic"
    return subprocess.run(command, capture_output=True, text=True, timeout=10).stdout


def run_shell(cmd: str) -> str:
    # Lets the assistant fix problems on the host. Runs whatever the model asks for.
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def run_python(code: str) -> str:
    # "Calculator": the model writes a snippet and the host runs it.
    scope = {}
    exec(code, scope)
    return json.dumps(scope.get("result"))


TOOL_TABLE = {"fetch_page": fetch_page, "run_diagnostic": run_diagnostic, "run_shell": run_shell, "run_python": run_python}
TOOL_SPECS = [{"name": name, "description": fn.__doc__ or name} for name, fn in TOOL_TABLE.items()]
