"""
ATLAS Terminal WebSocket Route

Provides a real shell terminal over WebSocket using PTY.
Restricted to pentester and admin roles only.
"""

import os
import pty
import select
import signal
import struct
import fcntl
import termios
import subprocess
import asyncio
import logging
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from api.routes.auth import get_session, get_db

logger = logging.getLogger("atlas.terminal")

router = APIRouter(prefix="/terminal", tags=["Terminal"])


async def authenticate_ws(token: str) -> dict | None:
    """Validate WebSocket token and return user info if authorized."""
    session = get_session(token)
    if not session:
        return None

    db = get_db()
    user = db.get_user_by_username(session["username"])
    if not user:
        return None

    # Only pentester and admin can use terminal
    if user.role not in ("pentester", "admin"):
        return None

    return {
        "username": user.username,
        "name": user.name,
        "role": user.role,
    }


def set_winsize(fd: int, rows: int, cols: int):
    """Set the terminal window size on the PTY."""
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


@router.websocket("/ws")
async def terminal_ws(websocket: WebSocket, token: str = Query(...)):
    """
    WebSocket endpoint that spawns a real bash shell via PTY.

    Query params:
        token: Session auth token

    Messages FROM client:
        - Plain text: stdin data (keystrokes)
        - JSON {"type": "resize", "cols": N, "rows": N}: resize terminal

    Messages TO client:
        - Plain text: stdout/stderr data from the shell
    """
    # Authenticate
    user = await authenticate_ws(token)
    if not user:
        await websocket.close(code=4003, reason="Unauthorized")
        return

    await websocket.accept()
    logger.info(f"Terminal session opened for {user['username']} ({user['role']})")

    # Create PTY
    master_fd, slave_fd = pty.openpty()

    # Spawn bash shell
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["SHELL"] = "/bin/bash"
    env["USER"] = user["username"]
    env["HOME"] = os.path.expanduser("~")

    process = subprocess.Popen(
        ["/bin/bash", "--login"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=os.setsid,
        env=env,
        cwd=os.path.expanduser("~"),
    )

    # Close slave in parent — child owns it now
    os.close(slave_fd)

    # Set default size
    set_winsize(master_fd, 24, 80)

    async def read_pty():
        """Read PTY output and send to WebSocket."""
        loop = asyncio.get_event_loop()
        try:
            while True:
                # Wait for data on master_fd
                await loop.run_in_executor(
                    None, lambda: select.select([master_fd], [], [], 0.1)
                )
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except OSError:
                    break
        except Exception as e:
            logger.debug(f"PTY read ended: {e}")

    async def write_pty():
        """Read WebSocket messages and write to PTY."""
        try:
            while True:
                message = await websocket.receive_text()

                # Check for JSON control messages
                if message.startswith("{"):
                    try:
                        msg = json.loads(message)
                        if msg.get("type") == "resize":
                            cols = msg.get("cols", 80)
                            rows = msg.get("rows", 24)
                            set_winsize(master_fd, rows, cols)
                            continue
                    except json.JSONDecodeError:
                        pass

                # Regular stdin data
                os.write(master_fd, message.encode("utf-8"))
        except WebSocketDisconnect:
            logger.info(f"Terminal disconnected for {user['username']}")
        except Exception as e:
            logger.debug(f"PTY write ended: {e}")

    # Run both tasks concurrently
    read_task = asyncio.create_task(read_pty())
    write_task = asyncio.create_task(write_pty())

    try:
        # Wait for either task to complete (disconnect or process exit)
        done, pending = await asyncio.wait(
            [read_task, write_task], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        # Cleanup: kill the shell process
        try:
            os.kill(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except Exception:
            try:
                os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
            except Exception:
                pass

        try:
            os.close(master_fd)
        except OSError:
            pass

        logger.info(f"Terminal session closed for {user['username']}")
