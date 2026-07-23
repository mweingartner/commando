# Deploy readiness: Quality-adjusted cost and time maturity

## Actor

Deployer-Terra-44

## Readiness

Deployment is user-authorized but remains blocked until all gates pass, archive and commit
are coherent, the immutable commit passes the activated high-risk profile, and the normal
pre-push hook authorizes transport. The typed Deploy gate copies the exact Candidate Build
output to `.mpd/local/bin/mpd`; those verified bytes may then be installed to the user
binary with a timestamped rollback copy. Reopen and compare SHA-256, size, and mode before
executing the verified binary.

## Rollback

Retain the prior installed binary as an explicit backup. On post-install failure, restore
the backup, reopen/hash/mode-check it, and report the candidate as not deployed. Never
force-push, bypass hooks, or conflate gate, transport, parity, and install facts.

## Verdict

PASS
