import hashlib

GENESIS = "0" * 64


def compute_hash(prev_hash, *fields):
    values = (prev_hash, *fields)
    joined = "|".join("" if value is None else str(value) for value in values)
    return hashlib.sha256(joined.encode()).hexdigest()


def get_last_ballot_hash(db):
    row = db.execute("SELECT hash FROM ballots ORDER BY rowid DESC LIMIT 1").fetchone()
    return row["hash"] if row else GENESIS