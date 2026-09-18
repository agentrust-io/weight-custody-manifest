"""Owner-controlled durable epoch floor; not resistant to database rollback.

Place this database on trusted owner storage, never the broker's hostile host.
Deletion, snapshot restoration and cloned databases require external prevention.
"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class OwnerEpochStore:
    """Serialize policy admission and provisioning across owner processes.

    One namespace identifies one broker policy lineage, including key rotations.
    Reusing a new namespace bypasses the old floor and must be access-controlled.
    """

    def __init__(self, path: str | Path, namespace: str) -> None:
        if not namespace or str(path) == ":memory:":
            raise ValueError("persistent path and nonempty namespace required")
        self._path = str(Path(path).resolve())
        self._namespace = namespace
        connection = sqlite3.connect(self._path)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS policy_floor "
                "(namespace TEXT PRIMARY KEY, epoch TEXT NOT NULL, digest TEXT NOT NULL)"
            )
            connection.commit()
        finally:
            connection.close()

    @contextmanager
    def guard(self, epoch: int, context: bytes, *, admit: bool = False) -> Iterator[None]:
        """Hold the write transaction until the guarded operation finishes.

        Admission may advance the floor; ordinary operations require an exact
        match. Failed guarded operations roll back changes to the floor.
        """
        digest = hashlib.sha256(context).hexdigest()
        connection = sqlite3.connect(self._path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT epoch, digest FROM policy_floor WHERE namespace = ?",
                (self._namespace,),
            ).fetchone()
            if row is None:
                if not admit:
                    raise ValueError("owner policy floor missing")
                connection.execute("INSERT INTO policy_floor VALUES (?, ?, ?)",
                                   (self._namespace, str(epoch), digest))
            else:
                floor = int(row[0])
                if epoch < floor or (epoch == floor and digest != row[1]):
                    raise ValueError("owner policy rollback or same-epoch substitution")
                if epoch > floor:
                    if not admit:
                        raise ValueError("owner policy epoch not admitted")
                    connection.execute(
                        "UPDATE policy_floor SET epoch = ?, digest = ? WHERE namespace = ?",
                        (str(epoch), digest, self._namespace),
                    )
            yield
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
