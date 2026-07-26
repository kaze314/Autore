import json
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS functions (
    address      TEXT PRIMARY KEY, 
    orig_name    TEXT,               
    name         TEXT,               
    category     TEXT,               -- crypto / network / file_io / ...
    summary      TEXT,               -- one-line purpose 
    confidence   REAL,               -- 0.0 - 1.0 
    evidence_json TEXT,              -- {"strings":[], "apis":[], "constants":[]}
    decomp       TEXT,               -- cached decompilation 
    decomp_hash  TEXT,              
    status       TEXT,               -- indexed / analyzed / applied / skipped
    updated_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_functions_hash   ON functions(decomp_hash);
CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(status);

CREATE TABLE IF NOT EXISTS edges (
    caller TEXT,
    callee TEXT,
    UNIQUE(caller, callee)
);
CREATE INDEX IF NOT EXISTS idx_edges_callee ON edges(callee);
CREATE INDEX IF NOT EXISTS idx_edges_caller ON edges(caller);

CREATE TABLE IF NOT EXISTS strings (
    address TEXT PRIMARY KEY,
    value   TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class LongTermMemory:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ----- functions -----
    def get(self, address):
        row = self.db.execute(
            "SELECT * FROM functions WHERE address=?", (address,)
        ).fetchone()
        return dict(row) if row else None

    def upsert(self, address, **fields):
        fields["address"] = address
        fields.setdefault("updated_at", time.time())
        cols = ", ".join(fields)
        ph = ", ".join("?" for _ in fields)
        upd = ", ".join(f"{k}=excluded.{k}" for k in fields if k != "address")
        self.db.execute(
            f"INSERT INTO functions ({cols}) VALUES ({ph}) "
            f"ON CONFLICT(address) DO UPDATE SET {upd}",
            tuple(fields.values()),
        )

    def summary_of(self, address):
        """What a neighbor needs: {name, summary} or None."""
        row = self.db.execute(
            "SELECT name, summary FROM functions WHERE address=? AND summary IS NOT NULL",
            (address,),
        ).fetchone()
        return dict(row) if row else None

    def by_hash(self, decomp_hash):
        """An already-analyzed function with identical decomp (dedup)."""
        row = self.db.execute(
            "SELECT * FROM functions WHERE decomp_hash=? AND status='analyzed' LIMIT 1",
            (decomp_hash,),
        ).fetchone()
        return dict(row) if row else None

    def count(self, status=None):
        if status:
            return self.db.execute(
                "SELECT COUNT(*) FROM functions WHERE status=?", (status,)
            ).fetchone()[0]
        return self.db.execute("SELECT COUNT(*) FROM functions").fetchone()[0]

    def add_edge(self, caller, callee):
        self.db.execute(
            "INSERT OR IGNORE INTO edges (caller, callee) VALUES (?, ?)",
            (caller, callee),
        )

    def callees_of(self, address):
        return [r[0] for r in self.db.execute(
            "SELECT callee FROM edges WHERE caller=?", (address,))]

    def callers_of(self, address):
        return [r[0] for r in self.db.execute(
            "SELECT caller FROM edges WHERE callee=?", (address,))]

    def all_edges(self):
        return self.db.execute("SELECT caller, callee FROM edges")

    def put_strings(self, items):
        self.db.executemany(
            "INSERT OR REPLACE INTO strings (address, value) VALUES (?, ?)",
            list(items),
        )
        self.db.commit()

    def strings_map(self):
        return {r[0]: r[1] for r in self.db.execute("SELECT address, value FROM strings")}

    def strings_count(self):
        return self.db.execute("SELECT COUNT(*) FROM strings").fetchone()[0]

    def meta_get(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def meta_set(self, key, value):
        self.db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        self.db.commit()

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()
