# Fixture: a filled agent prompt block

Parsed by `tests/validate.py::check_agent_prompt_parses`. This is the machine-readability gate for
`references/agent-prompt.md`: if a change to the template breaks the parser, this fixture fails.
Three findings across three severities, each with a usable literal anchor.

## Agent prompt

```
Verify each finding against current code. Fix only still-valid issues, skip the rest with a
brief reason, keep changes minimal, and validate.

[F1] Critical · @internal/auth/session.go, ~L112-118
  Anchor: `if err == nil { return tok, nil }`
  Issue:  The parsed token is returned as soon as parsing succeeds, before the signature
          check below it runs, so a token signed with any key is accepted as valid.
  Expect: Signature verification runs and its error propagates before any return path
          yields a token to the caller.

[F2] High · @scripts/deploy.sh, ~L23
  Anchor: `rm -rf $DEST/$RELEASE`
  Issue:  Both variables are unquoted and RELEASE comes from a positional parameter, so a
          value containing whitespace or an empty value expands to extra arguments and the
          command deletes a path nobody asked for.
  Expect: Every expansion in the destructive path is quoted, and the script refuses to run
          when the release argument is absent or empty.

[F3] Medium · @web/src/components/Feed.vue, ~L44
  Anchor: `<div v-html="post.body" />`
  Issue:  Post bodies are author-controlled and reach v-html with no sanitisation, giving
          stored XSS in the session of every reader who loads the feed.
  Expect: Post bodies render as text, or pass through a sanitiser whose allow-list excludes
          script, style, and event-handler attributes.

After fixing, run: go build ./... && go vet ./... && bash -n scripts/deploy.sh
Report a table: ID | FIXED | SKIPPED-STALE | SKIPPED-DISAGREE | reason.
```
