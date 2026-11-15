"""L5 · Executive sandbox: white-list tools, confined to a directory, with time limit.

Nothing leaves the sandbox: `send_message` leaves the message in a INBOX of OUTPUT local (outbox.jsonl); it does not connect to any real service.
"""
import ast
import json
import operator
import os
import threading
from fractions import Fraction

from .root.useful import sha256


class SandboxError(Exception):
    pass


def with_limit(fn, seconds=2.0):
    """Linux Subprocess: a timeout ends the worker, leaves no late effects of a thread."""
    def wrapped(**kw):
        import multiprocessing
        ctx = multiprocessing.get_context("fork")
        rx, tx = ctx.Pipe(duplex=False)
        def run():
            rx.close()
            try:
                tx.send((True, fn(**kw)))
            except BaseException as e:
                tx.send((False, f"{type(e).__name__}: {e}"))
            finally:
                tx.close()
        p = ctx.Process(target=run, daemon=True)
        p.start()
        tx.close()
        try:
            if not rx.poll(seconds):
                p.terminate()
                p.join(0.2)
                if p.is_alive():
                    p.kill()
                    p.join()
                raise TimeoutError(f"exceeded {seconds}s (I10): finished worker")
            ok, output = rx.recv()
            if not ok:
                raise SandboxError(output)
            return output
        finally:
            rx.close()
            p.join(0.2)
            if p.is_alive():
                p.kill()
                p.join()
    return wrapped


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.Pow: operator.pow, ast.Mod: operator.mod, ast.FloorDiv: operator.floordiv}


def _eval(node, num):
    if isinstance(node, ast.Expression):
        return _eval(node.body, num)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return num(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        a, b = _eval(node.left, num), _eval(node.right, num)
        if isinstance(node.op, ast.Pow) and abs(b) > 64:
            raise SandboxError("exponent too big")
        return _OPS[type(node.op)](a, b)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = _eval(node.operand, num)
        return -v if isinstance(node.op, ast.USub) else v
    raise SandboxError(f"expression not permitted: {type(node).__name__}")


def calculate(expression: str):
    """Safe arithmetic (AST in white list, without eval)."""
    if len(expression) > 200:
        raise SandboxError("expression too long")
    return float(_eval(ast.parse(expression, mode="eval"), float))


def calculate_exact(expression: str):
    """Independent recalculation with exact fractions (uses VERIFIER, not the executor)."""
    return _eval(ast.parse(expression, mode="eval"), lambda v: Fraction(str(v)))


class Sandbox:
    def __init__(self, root_dir: str):
        self.dir = os.path.realpath(root_dir)
        os.makedirs(self.dir, exist_ok=True)
        self.outbox = os.path.join(self.dir, "outbox.jsonl")

    def _path(self, name_: str) -> str:
        r = os.path.realpath(os.path.join(self.dir, name_))
        if not r.startswith(self.dir + os.sep):
            raise SandboxError(f"path outside the sandbox: {name_}")
        return r

    def write_file(self, name_: str, content: str):
        r = self._path(name_)
        os.makedirs(os.path.dirname(r), exist_ok=True)     # sandbox subfolders INSIDE (finding DEV)
        with open(r, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        return {"path_": os.path.relpath(r, self.dir), "sha256": sha256(content), "bytes": len(content.encode())}

    def read_file(self, name_: str):
        with open(self._path(name_), encoding="utf-8") as f:
            return f.read()

    def send_message(self, for_: str, subject: str, body_: str):
        reg = {"for_": for_, "subject": subject, "body_": body_}
        with open(self.outbox, "a", encoding="utf-8") as f:
            f.write(json.dumps(reg, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return {"in_inbox": True, "sha256": sha256(reg), **reg}

    def inbox(self):
        if not os.path.exists(self.outbox):
            return []
        with open(self.outbox, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
