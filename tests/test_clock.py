"""Clock drift on a disconnected host: detection, and the logged way back.

A clock that has gone backwards makes age and ordering checks meaningless, so imports are refused.
Clocks do drift on air-gapped systems, so there has to be a way to recover that does not involve
deleting the ledger: an explicit, signed, hash-chained clock adjustment.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from superscrubber104.cli import main
from superscrubber104.core.model import Disposition, Result, Verdict
from superscrubber104.core.policy import Policy
from superscrubber104.ledger import EVENT_CLOCK, Ledger
from superscrubber104.pack import pack
from superscrubber104.session import EXIT_OK, EXIT_REFUSED, exit_code
from superscrubber104.summary import render
from superscrubber104.verify import VerifyResult, verify
from tests.helpers import NOW, Site, disposition, failed, make_delivery, make_site

DAY = timedelta(days=1)
HOUR = timedelta(hours=1)


@pytest.fixture
def site(tmp_path: Path) -> Site:
    return make_site(tmp_path / "site")


def bundle_at(site: Site, tmp_path: Path, name: str, when: datetime) -> Path:
    delivery = tmp_path / "delivery"
    if not delivery.exists():
        make_delivery(delivery)
    return pack(
        [delivery],
        tmp_path / name,
        signer=site.pack_key,
        policy=Policy.default(),
        request_path=site.request,
        now=when,
    ).bundle


def check(site: Site, bundle: Path, state: Path, when: datetime) -> VerifyResult:
    return verify(
        bundle, policy=site.policy(), state=state, receipt_signer=site.receipt_key, now=when
    )


def test_regression_is_refused_until_a_signed_adjustment(site: Site, tmp_path: Path) -> None:
    state = tmp_path / "state"
    first = bundle_at(site, tmp_path, "first", NOW)
    second = bundle_at(site, tmp_path, "second", NOW + DAY)

    # The host's clock is three days fast when the first bundle is imported.
    assert check(site, first, state, NOW + 4 * DAY).assessment.summary.verdict is Verdict.PASSED

    # The clock is then corrected. The next import sees a clock earlier than the ledger.
    refused = check(site, second, state, NOW + DAY + HOUR)
    [finding] = failed(refused.assessment)["replay.clock.regression"]
    assert finding.result is Result.FAIL
    assert "superscrubber104 ledger adjust-clock" in str(finding.detail["hint"])
    assert disposition(refused.assessment, "replay.clock.regression") is Disposition.BLOCK
    assert exit_code(refused.assessment) == EXIT_REFUSED
    assert "hint: correct the system clock" in render(refused.assessment)

    # Trying again does not make it go away: the refused attempt must not lower the mark.
    again = check(site, second, state, NOW + DAY + 2 * HOUR)
    assert "replay.clock.regression" in failed(again.assessment)
    assert again.assessment.summary.verdict is Verdict.REFUSED

    # The recovery path: an explicit, signed entry saying the clock was set back, and why.
    ledger = Ledger(state)
    receipt_key = site.receipt_key.verify_key
    assert ledger.load({receipt_key.key_id: receipt_key}.get, require_signed=True) == []
    assert ledger.high_water == NOW + 4 * DAY
    event = ledger.adjust_clock(
        now=NOW + DAY + 3 * HOUR,
        reason="RTC battery replaced; clock was 3 days fast since 2026-11-01",
        signer=site.receipt_key,
    )
    assert event.type == EVENT_CLOCK
    assert event.sig is not None
    assert event.data["previousHighWater"] == "2026-11-14T12:00:00Z"

    # Imports resume, and the adjustment is shown, with its reason, in the next assessment.
    resumed = check(site, second, state, NOW + DAY + 4 * HOUR)
    assert "replay.clock.regression" not in failed(resumed.assessment)
    assert resumed.assessment.summary.verdict is Verdict.PASSED
    assert exit_code(resumed.assessment) == EXIT_OK
    [noted] = failed(resumed.assessment)["replay.clock.adjusted"]
    assert "RTC battery replaced" in str(noted.detail["reason"])
    assert noted.detail["by"] == site.receipt_key.key_id
    assert disposition(resumed.assessment, "replay.clock.adjusted") is Disposition.ALLOW

    # It is reported once, stays in the ledger for good, and the ledger still verifies.
    third = bundle_at(site, tmp_path, "third", NOW + 2 * DAY)
    later = check(site, third, state, NOW + 2 * DAY + HOUR)
    assert "replay.clock.adjusted" not in failed(later.assessment)
    assert "integrity.ledger.broken" not in failed(later.assessment)
    types = [
        json.loads(line)["type"] for line in (state / "ledger.jsonl").read_bytes().splitlines()
    ]
    assert types == ["receipt", "receipt", "receipt", "clock-adjusted", "receipt", "receipt"]


def test_small_drift_is_tolerated(site: Site, tmp_path: Path) -> None:
    state = tmp_path / "state"
    first = bundle_at(site, tmp_path, "first", NOW)
    second = bundle_at(site, tmp_path, "second", NOW + HOUR)
    check(site, first, state, NOW + 2 * HOUR)
    # Five minutes behind the last entry: inside the default ten-minute tolerance.
    result = check(site, second, state, NOW + 2 * HOUR - timedelta(minutes=5))
    assert "replay.clock.regression" not in failed(result.assessment)
    # Eleven minutes behind: outside it.
    third = bundle_at(site, tmp_path, "third", NOW + HOUR + timedelta(minutes=1))
    result = check(site, third, state, NOW + 2 * HOUR - timedelta(minutes=11))
    assert "replay.clock.regression" in failed(result.assessment)


def test_bundle_from_the_future_warns_that_a_clock_is_off(site: Site, tmp_path: Path) -> None:
    """An early sign of drift, before it turns into a regression."""
    bundle = bundle_at(site, tmp_path, "bundle", NOW + 3 * HOUR)
    result = verify(bundle, policy=site.policy(), now=NOW)
    assert disposition(result.assessment, "replay.clock.skew") is Disposition.WARN
    assert result.assessment.summary.verdict is Verdict.PASSED
    on_time = verify(bundle, policy=site.policy(), now=NOW + 3 * HOUR - timedelta(minutes=5))
    assert "replay.clock.skew" not in failed(on_time.assessment)


def test_adjust_clock_command(site: Site, tmp_path: Path) -> None:
    state = tmp_path / "state"
    key = tmp_path / "receipt.key"
    key.write_bytes(site.receipt_key.pem())
    bundle = bundle_at(site, tmp_path, "bundle", NOW)

    def run(*args: object) -> tuple[int, str]:
        result = CliRunner().invoke(main, [str(a) for a in args])
        return result.exit_code, result.output

    # Imported while the clock was far in the future (the real clock is "now" for the CLI).
    future = datetime.now(NOW.tzinfo) + 30 * DAY
    result = check(site, bundle, state, future)
    assert result.receipt is not None  # recorded in the ledger, whatever the verdict

    code, output = run("ledger", "adjust-clock", "--state", state, "--reason", " ")
    assert code == 2
    assert "reason is required" in output

    code, output = run(
        "ledger", "adjust-clock", "--state", state, "--key", key,
        "--reason", "clock was a month fast; corrected against the site time source",
    )  # fmt: skip
    assert code == 0, output
    assert "recorded clock adjustment" in output
    events = Ledger(state)
    assert events.load(lambda _key_id: site.receipt_key.verify_key, require_signed=True) == []
    assert events.events[-1].type == EVENT_CLOCK
    assert "site time source" in str(events.events[-1].data["reason"])

    # Nothing to do when the clock is not behind the ledger.
    code, output = run("ledger", "adjust-clock", "--state", state, "--reason", "again")
    assert code == 0
    assert "nothing recorded" in output
    assert len(Ledger(state).path.read_bytes().splitlines()) == 2
