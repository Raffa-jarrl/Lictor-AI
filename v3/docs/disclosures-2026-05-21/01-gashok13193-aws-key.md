# Disclosure 1 of 4 — AWS access key leak

**Target:** https://github.com/gashok13193/DevOps-Docs (181 stars)
**File:** `Terraform/modules/main.tf` (commit `bb041ffa0315d58d6ae10828d1d9184ca17d2c28`)
**Action:** Open GitHub issue + email AWS security

---

## Step A — open GitHub issue

URL: https://github.com/gashok13193/DevOps-Docs/issues/new

**Title** (copy):
```
Security: AWS access key + secret pair committed to Terraform/modules/main.tf — rotate immediately
```

**Body** (copy):
```markdown
Hi — quick security note.

`Terraform/modules/main.tf` (commit `bb041ffa0315d58d6ae10828d1d9184ca17d2c28`) contains an AWS access key starting with `AKIAXEFU…` together with its paired secret access key. Both are currently visible in the public main branch.

**Action items (in order):**

1. **Rotate the key NOW** at https://console.aws.amazon.com/iam → Users → your user → Security credentials → make the old key Inactive, create a new one. AWS support article: https://repost.aws/knowledge-center/rotate-access-keys-iam-user
2. **Check CloudTrail** for any unauthorized API calls under that access key — crypto-mining bots scrape GitHub for `AKIA…` keys within seconds of push. Look for unexpected EC2 instance launches, S3 bucket creations, or IAM user creations.
3. **Rewrite git history** to remove the key from past commits too: `git filter-repo --invert-paths --path Terraform/modules/main.tf` (or use BFG Repo-Cleaner). Even after a force-push, the GitHub-archived commit will keep the key visible until you do this.
4. **Switch to env vars** going forward: pass AWS credentials via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars or via the AWS CLI's `~/.aws/credentials` file. NEVER commit them.

The leak was detected by Lictor (https://lictor-ai.com), an open-source security scanner under Apache 2.0. No data was accessed using the key. This is a one-time courtesy notification.
```

## Step B — email AWS Trust & Safety

To: `aws-security@amazon.com`

Subject:
```
Leaked AWS access key on public GitHub — request investigation
```

Body:
```
Hello,

A public GitHub repository contains an active AWS access key + paired secret
in plaintext:

  Repository: https://github.com/gashok13193/DevOps-Docs
  File:       Terraform/modules/main.tf
  Commit:     bb041ffa0315d58d6ae10828d1d9184ca17d2c28
  Access Key Prefix: AKIAXEFU... (full key intentionally redacted in this email)
  Pushed:     2026-05-15 (still in current main branch as of 2026-05-21)

The key has been there for 6 days; GitHub Secret Scanning may have flagged
it, but as of this writing the key is still in the file. The repository
owner has been separately notified via a GitHub issue.

Request: please investigate the key via your standard leaked-credential process
and disable it if your records show it is still active and at risk.

Discovered via Lictor (https://lictor-ai.com), open-source security scanner,
Apache 2.0. No use of the key was attempted on my end.

Thank you.
```
