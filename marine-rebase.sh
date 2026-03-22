#!/bin/bash
HELP_MESSAGE="Usage: $0 <new-base-branch>

Automatically all marine commits on a new wireshark tag.
Examples:
  $0 --onto=wireshark-3.4.16
  $0 --onto=wireshark-4.0.0 --interactive

--help - show this message"
if [[ $# -lt 1 ]]; then
  echo "$HELP_MESSAGE" >&2
  exit 1
elif [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo "$HELP_MESSAGE"
  exit 0
fi
FIRST_MARINE_COMMIT=$(git log --author tom.legkov --pretty=%H | tail -n1)
git rebase -m "$FIRST_MARINE_COMMIT"~ "$@"
