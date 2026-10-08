"""FS0 preflight only. No absent mount case can qualify as passed."""
import argparse
import pathlib
import sys

from preflight import check
from report import MANDATORY, save
from resources import OwnedOutput


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        owned = OwnedOutput(args.output)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    facts = check()
    cases = {case: "not-run" for case in MANDATORY}
    errors = owned.cleanup(remove_output=False)
    cases["cleanup"] = "failed" if errors else "passed"
    result = save(owned.path / "report.json", facts, cases, errors)
    print(owned.path / "report.json")
    return facts["exit_code"] or (0 if result["passed"] else 2)


if __name__ == "__main__":
    sys.exit(main())
