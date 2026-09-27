"""Unit tests for `rwdiscovery.drainlite` -- the Drain-lite clustering
algorithm, platform-contract log-patterns-v0 §7.1, against synthetic
already-masked messages (never real log content)."""

from __future__ import annotations

from rwdiscovery.drainlite import DrainLite


def test_identical_messages_cluster_together():
    drain = DrainLite()
    a = drain.add("connection refused to database host")
    b = drain.add("connection refused to database host")
    assert a.id == b.id
    assert a.template == "connection refused to database host"


def test_one_differing_variable_token_becomes_a_wildcard():
    drain = DrainLite()
    a = drain.add("upload failed for file report.csv")
    b = drain.add("upload failed for file invoice.pdf")
    assert a.id == b.id
    assert a.template == "upload failed for file <*>"


def test_different_first_token_never_merges():
    drain = DrainLite()
    a = drain.add("alpha bravo charlie delta")
    b = drain.add("zulu bravo charlie delta")
    assert a.id != b.id
    assert a.template == "alpha bravo charlie delta"
    assert b.template == "zulu bravo charlie delta"


def test_different_second_token_never_merges():
    drain = DrainLite()
    a = drain.add("alpha bravo charlie delta")
    b = drain.add("alpha zulu charlie delta")
    assert a.id != b.id
    assert a.template == "alpha bravo charlie delta"
    assert b.template == "alpha zulu charlie delta"


def test_messages_under_four_tokens_only_join_an_identical_template():
    drain = DrainLite()
    a = drain.add("err code 500")
    b = drain.add("err code 501")
    c = drain.add("err code 500")
    assert a.id != b.id  # one differing token, but < 4 tokens: no similarity band
    assert a.id == c.id  # exact repeat still joins
    assert a.template == "err code 500"
    assert b.template == "err code 501"


def test_exception_token_guard_keeps_different_exception_classes_separate():
    drain = DrainLite()
    a = drain.add("ERROR call PAPIError: failed")
    b = drain.add("ERROR call HTTPStatusError: failed")
    # Same token count, same first two tokens, 3/4 positions equal (0.75
    # similarity) -- would merge without the guard, since the only
    # differing position is the exception-class token.
    assert a.id != b.id
    assert a.template == "ERROR call PAPIError: failed"
    assert b.template == "ERROR call HTTPStatusError: failed"


def test_similarity_exactly_at_threshold_joins():
    drain = DrainLite()
    a = drain.add("a b c1 d1")
    b = drain.add("a b c2 d2")
    # Positions 0,1 always match (bucketed on); 2,3 both differ ->
    # similarity = 2/4 = 0.5, exactly the threshold -- joins.
    assert a.id == b.id
    assert a.template == "a b <*> <*>"


def test_similarity_below_threshold_does_not_join():
    drain = DrainLite()
    a = drain.add("a b c1 d1 e1")
    b = drain.add("a b c2 d2 e2")
    # Positions 0,1 match; 2,3,4 all differ -> similarity = 2/5 = 0.4,
    # below the threshold -- stays a separate cluster.
    assert a.id != b.id
    assert a.template == "a b c1 d1 e1"
    assert b.template == "a b c2 d2 e2"


def test_already_wildcarded_positions_count_as_equal():
    drain = DrainLite()
    first = drain.add("a b c1 d")
    second = drain.add("a b c2 d")
    assert first.id == second.id
    assert first.template == "a b <*> d"

    # Position 2 is already `<*>` -- a third, unrelated token there still
    # counts as equal (full similarity), so it joins the same cluster
    # without the template changing further.
    third = drain.add("a b c3 d")
    assert third.id == first.id
    assert third.template == "a b <*> d"


def test_ties_join_the_older_cluster():
    drain = DrainLite()
    a = drain.add("a b p1 p2 p3 p4")
    b = drain.add("a b q1 q2 q3 q4")
    assert a.id != b.id  # fully disjoint free tokens: 2/6 similarity, no merge

    # Matches `a` at positions 2,3 and `b` at positions 4,5: 4/6 similarity
    # against both -- a tie, broken toward the older cluster (`a`).
    tied = drain.add("a b p1 p2 q3 q4")
    assert tied.id == a.id
