#!/usr/bin/env python3
"""Run the sound model and mutations that must produce counterexamples."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

MODEL = Path(__file__).with_name("tarako-attestation.pv")
PROCESS_START = "\nprocess\n"
EXPECTED_SECURITY_QUERIES = 12
REACHABILITY_QUERY = """
(* Diagnostics: successful acceptance and two distinct TQs under one cache
 * must be reachable. Fact-only queries must be false (a trace exists). *)
query request: bitstring, digest: bitstring;
  event(ClientAcceptedIntegrity(request, digest)).

query cache: bitstring, first: bitstring, second: bitstring, digest: bitstring;
  event(TarakoQuoteAccepted(cache, first, digest)) &&
  event(TarakoQuoteAccepted(cache, second, digest)) && first <> second.
"""
REQUEST_BINDING = """   let request_binding =
       hash(cached_request_context(ima_answer_binding,
                                   client_request,
                                   request_nonce)) in"""
TARAKO_ORIGIN = (
    "event(TarakoQuoteAccepted(cache,binding,digest)) ==> "
    "event(TarakoQuoteIssued"
)
TARAKO_FRESHNESS = (
    "inj-event(TarakoQuoteAccepted(cache,binding,digest)) ==> "
    "inj-event(TarakoQuoteIssued"
)


@dataclass(frozen=True)
class Scenario:
    name: str
    replacements: tuple[tuple[str, str], ...]
    false_result: str


def replace_once(model: str, old: str, new: str) -> str:
    count = model.count(old)
    if count != 1:
        raise RuntimeError(f"mutation target occurs {count} times, expected once:\n{old}")
    return model.replace(old, new)


def public_key_scenario(key: str, false_result: str) -> Scenario:
    return Scenario(
        f"public-{key.replace('_', '-')}",
        ((f"free {key}: signing_key [private].", f"free {key}: signing_key."),),
        false_result,
    )


SCENARIOS = (
    public_key_scenario("tdx_attestation_key", "TdxQuoteVerified"),
    public_key_scenario("tdx_verifier_key", "TdxAnswerAccepted"),
    public_key_scenario("ima_verifier_key", "ImaAnswerAccepted"),
    public_key_scenario("tarako_signing_key", TARAKO_ORIGIN),
    public_key_scenario("relying_verifier_key", "ClientAcceptedIntegrity(request,digest)) ==> event(IntegrityVerdictIssued"),
    Scenario(
        "tdx-service-skips-quote-signature",
        ((
            """let tdx_claim(challenge, =approved_tdx_measurement, quoted_rtmr) =
       verify(received_quote, public_key(tdx_attestation_key)) in""",
            """let tdx_claim(challenge, =approved_tdx_measurement, quoted_rtmr) =
       received_quote in""",
        ),),
        "TdxQuoteVerified",
    ),
    Scenario(
        "ima-service-skips-tdx-verifier-signature",
        ((
            """let tdx_appraisal_answer(_, _, quoted_rtmr) =
       verify(received_tdx_answer, public_key(tdx_verifier_key)) in""",
            """let tdx_appraisal_answer(_, _, quoted_rtmr) =
       received_tdx_answer in""",
        ),),
        "ImaEvidenceVerified(tdx_binding,root,key)) ==> event(TdxAnswerIssued",
    ),
    Scenario(
        "ima-service-skips-rtmr-comparison",
        ((
            "   let rtmr_with_ima(=replayed_ima_root) = quoted_rtmr in\n",
            "",
        ),),
        "ImaEvidenceVerified(tdx_binding,root,key)) ==> event(TdxAnswerIssued",
    ),
    Scenario(
        "ima-service-skips-log-membership",
        ((
            """   get ima_log(=replayed_ima_root,
               =ima_key_entry(tarako_public_key)) in
""",
            "",
        ),),
        "ImaEvidenceVerified(tdx_binding,root,key)) ==> event(ImaLogCommitted",
    ),
    Scenario(
        "relying-verifier-skips-tdx-service-signature",
        ((
            """let tdx_appraisal_answer(=hash(received_tdx_quote),
                            =tdx_challenge,
                            quoted_rtmr) =
       verify(received_tdx_answer, public_key(tdx_verifier_key)) in""",
            """let tdx_appraisal_answer(=hash(received_tdx_quote),
                            =tdx_challenge,
                            quoted_rtmr) =
       received_tdx_answer in""",
        ),),
        "TdxAnswerAccepted",
    ),
    Scenario(
        "relying-verifier-skips-ima-service-signature",
        ((
            """let ima_appraisal_answer(=tdx_answer_binding,
                            =hash(received_ima_evidence),
                            tarako_public_key) =
       verify(received_ima_answer, public_key(ima_verifier_key)) in""",
            """let ima_appraisal_answer(=tdx_answer_binding,
                            =hash(received_ima_evidence),
                            tarako_public_key) =
       received_ima_answer in""",
        ),),
        "ImaAnswerAccepted",
    ),
    Scenario(
        "relying-verifier-skips-tarako-signature",
        ((
            """let tarako_claim(=request_binding, measured_ta_digest) =
       verify(received_tarako_quote, tarako_public_key) in""",
            """let tarako_claim(=request_binding, measured_ta_digest) =
       received_tarako_quote in""",
        ),),
        TARAKO_ORIGIN,
    ),
    Scenario(
        "cached-request-reuses-static-appraisal-binding",
        ((REQUEST_BINDING, "   let request_binding = ima_answer_binding in"),),
        TARAKO_FRESHNESS,
    ),
    Scenario(
        "cached-request-omits-verifier-nonce",
        ((REQUEST_BINDING, """   let request_binding =
       hash(session_context(ima_answer_binding, client_request)) in"""),),
        TARAKO_FRESHNESS,
    ),
    Scenario(
        "relying-verifier-skips-request-binding",
        ((
            "let tarako_claim(=request_binding, measured_ta_digest) =",
            "let tarako_claim(unchecked_binding, measured_ta_digest) =",
        ),),
        TARAKO_FRESHNESS,
    ),
    Scenario(
        "relying-verifier-skips-approved-digest",
        (("   if measured_ta_digest = approved_ta_digest then\n", ""),),
        "ClientAcceptedIntegrity(request,digest)) ==> digest =",
    ),
    Scenario(
        "client-skips-relying-verifier-signature",
        ((
            """let integrity_verdict(=client_request, measured_ta_digest) =
       verify(received_verdict, public_key(relying_verifier_key)) in""",
            """let integrity_verdict(=client_request, measured_ta_digest) =
       received_verdict in""",
        ),),
        "ClientAcceptedIntegrity(request,digest)) ==> event(IntegrityVerdictIssued",
    ),
)


def run(proverif: str, path: Path) -> tuple[list[str], str]:
    completed = subprocess.run(
        [proverif, str(path)], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    results = [line for line in completed.stdout.splitlines() if line.startswith("RESULT ")]
    if completed.returncode != 0:
        raise RuntimeError(
            f"ProVerif exited with {completed.returncode} for {path}:\n{completed.stdout}"
        )
    return results, completed.stdout


def main() -> int:
    proverif = sys.argv[1] if len(sys.argv) > 1 else "proverif"
    source = MODEL.read_text()

    baseline_results, baseline_output = run(proverif, MODEL)
    bad_baseline = [line for line in baseline_results if not line.endswith(" is true.")]
    if len(baseline_results) != EXPECTED_SECURITY_QUERIES or bad_baseline:
        print(
            f"sound model must prove all {EXPECTED_SECURITY_QUERIES} queries; "
            f"received {len(baseline_results)} results",
            file=sys.stderr,
        )
        print("\n".join(bad_baseline) or baseline_output, file=sys.stderr)
        return 1
    print(f"PASS sound model ({len(baseline_results)} queries true)")
    baseline_queries = {
        line.removeprefix("RESULT ").rsplit(" is ", 1)[0]
        for line in baseline_results
    }
    falsified_queries: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="tarako-proverif-") as directory:
        root = Path(directory)

        # The ProVerif manual recommends an event reachability query to catch
        # vacuous correspondence proofs caused by unreachable protocol code.
        reachability_model = replace_once(
            source, PROCESS_START, REACHABILITY_QUERY + PROCESS_START
        )
        reachability_path = root / "successful-run-reachability.pv"
        reachability_path.write_text(reachability_model)
        reachability_results, reachability_output = run(proverif, reachability_path)
        reachability_fragments = (
            "not event(ClientAcceptedIntegrity(request,digest))",
            "event(TarakoQuoteAccepted(cache,first,digest))",
        )
        reachability_false = [
            line for line in reachability_results
            if any(fragment in line for fragment in reachability_fragments)
            and line.endswith(" is false.")
        ]
        other_bad_results = [
            line for line in reachability_results
            if line not in reachability_false and not line.endswith(" is true.")
        ]
        if (
            len(reachability_false) != 2
            or not all(
                any(fragment in line for line in reachability_false)
                for fragment in reachability_fragments
            )
            or len(reachability_results) != len(baseline_results) + 2
            or other_bad_results
        ):
            print("FAIL client acceptance or cached-session reuse is not reachable",
                  file=sys.stderr)
            print("\n".join(reachability_results) or reachability_output,
                  file=sys.stderr)
            return 1
        print("PASS successful end-to-end run is reachable")
        print("PASS two distinct TQs under one cached appraisal are reachable")

        for scenario in SCENARIOS:
            mutated = source
            for old, new in scenario.replacements:
                mutated = replace_once(mutated, old, new)
            path = root / f"{scenario.name}.pv"
            path.write_text(mutated)
            results, output = run(proverif, path)
            falsified_queries.update(
                line.removeprefix("RESULT ").rsplit(" is ", 1)[0]
                for line in results if line.endswith(" is false.")
            )
            expected_fragments = [scenario.false_result]
            if scenario.name == "public-tdx-attestation-key":
                expected_fragments.append("not attacker(tdx_attestation_key")
            if scenario.name == "public-tarako-signing-key":
                expected_fragments.append("not attacker(tarako_signing_key")
            if scenario.name == "public-ima-verifier-key":
                expected_fragments.append(
                    "TarakoQuoteAccepted(cache,binding,digest)) ==> event(ImaAnswerIssued"
                )
            if scenario.name in {
                "public-relying-verifier-key",
                "client-skips-relying-verifier-signature",
            }:
                # This also guards against making the end-to-end query
                # tautological by repeating the digest check in Client.
                expected_fragments.append(
                    "ClientAcceptedIntegrity(request,digest)) ==> digest ="
                )

            expected = []
            for fragment in expected_fragments:
                matches = [
                    line for line in results
                    if fragment in line and line.endswith(" is false.")
                ]
                if not matches:
                    print(f"FAIL {scenario.name}: expected a false result containing "
                          f"{fragment!r}", file=sys.stderr)
                    print("\n".join(results) or output, file=sys.stderr)
                    return 1
                expected.extend(matches)
            print(f"PASS {scenario.name}: {len(expected)} expected counterexample(s)")

    unchecked = baseline_queries - falsified_queries
    if unchecked:
        print("FAIL positive queries without a negative control:", file=sys.stderr)
        print("\n".join(sorted(unchecked)), file=sys.stderr)
        return 1
    print("PASS every positive query is falsified by at least one negative control")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
