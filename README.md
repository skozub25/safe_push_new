safe push new


## TODO IDEAS

- Intense evaluation: Make a folder several true and false positive tests, measure accuracy, precision, recall; analyze accuracy by each time of error - e.g. entropy accuracy vs provider patterns - chat called this a "Labeled corpus"
- Better remediation hints
- UI??
- Canary token experiment (stretch)
- Dedupe (don't flag the same line of code for multiple reasons, only highest severity)

## NOTES
- If we flag something for known provider pattern, then we won't flag it for anything else as well

- labeled corpus has been started , tests/corpus, we test for entropy and pattern cases (needs more work)

- canary tokens working / dedupe done