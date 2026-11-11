"""Manual check: python -m guardrails "kubectl delete pod web-0" """

import os
import sys

from .engine import context_from_env, evaluate_command


def main() -> int:
    if len(sys.argv) < 2:
        print('usage: python -m guardrails "<command>"', file=sys.stderr)
        return 2
    verdict = evaluate_command(" ".join(sys.argv[1:]), context_from_env(os.getcwd()))
    if verdict is None:
        print("allow")
        return 0
    print(f"{verdict.decision} [{verdict.rule}] {verdict.reason}")
    return 1 if verdict.decision == "deny" else 0


if __name__ == "__main__":
    sys.exit(main())
