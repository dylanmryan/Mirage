from mirage.honeytokens import HoneytokenMinter, HoneytokenStore


def _counter():
    n = {"i": 0}
    def gen():
        v = f"tok{n['i']}"
        n["i"] += 1
        return v
    return gen


def test_minter_embeds_token_id_and_is_deterministic():
    m = HoneytokenMinter(id_gen=_counter())
    t = m.mint("aws_key", "s1", "read_secrets")
    assert t.token_id == "tok0"
    assert t.token_id in t.value           # embedded tag -> scannable
    assert t.value.startswith("AKIA")
    assert t.template == "aws_key"
    assert t.session_id == "s1"
    assert t.tool == "read_secrets"


def test_minter_templates():
    m = HoneytokenMinter(id_gen=_counter())
    assert m.mint("bearer_token", "s", "t").value.startswith("sk-")
    assert "@examplecorp.com" in m.mint("pii_email", "s", "t").value


def test_store_record_and_find():
    store = HoneytokenStore(":memory:")
    m = HoneytokenMinter(id_gen=_counter())
    tok = m.mint("aws_key", "s1", "read_secrets")
    store.record(tok)
    assert store.find("tok0").value == tok.value
    assert store.find("nope") is None


def test_store_scan_finds_planted_token():
    store = HoneytokenStore(":memory:")
    m = HoneytokenMinter(id_gen=_counter())
    tok = m.mint("aws_key", "s1", "read_secrets")
    store.record(tok)
    hits = store.scan(f"here is the key {tok.value} lol")
    assert [h.token_id for h in hits] == ["tok0"]
    assert store.scan("nothing here") == []
