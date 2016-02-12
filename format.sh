#!/bin/bash

# formats all python files according to PEP 8.

# this script can be used as commit-hook,
# simply move it to .git/hooks/pre-commit

autopep8 -r --in-place --aggressive --aggressive *.py
