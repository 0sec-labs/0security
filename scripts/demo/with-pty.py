#!/usr/bin/env python3
"""Run a command inside a pseudo-terminal so it behaves as if run from a real terminal.
Usage: with-pty.py <command> [args...]. Output is discarded (asciinema records it)."""
import fcntl, os, pty, struct, sys, termios

pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 100, 0, 0))
while True:
    try:
        if not os.read(fd, 65536):
            break
    except OSError:
        break
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
