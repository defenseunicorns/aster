# Aster repository instructions

Follow the project's Clean Room policy and source exclusions.

## Before editing

- Work on a dedicated branch for the task.
- Read `CONTRIBUTING.md` before making changes.
- Follow the product requirements in `DESIGN.md`.

## Code

- **Make simple tasks simple:** Don’t turn small changes into large refactors or
  elaborate workflows.
- **Less is more:** Prefer the smallest clear solution that meets the requirements.
- **Avoid unnecessary abstractions:** Don’t introduce design patterns or
  abstractions unless they are genuinely needed.
- **Build for current requirements:** Don’t add features or flexibility for
  hypothetical future needs.
- **Keep code readable:** Prefer straightforward solutions that are easy to
  understand and maintain.
- **Keep Functions Short:** Keep each function focused on one task and easy to read.
- **Use Familiar Constructs:** Stick to patterns and data structures that are
  widely recognized in your language's ecosystem.
- **Simple Algorithms:** Choose straightforward algorithms when they meet
  performance requirements.
- **Reuse existing solutions:** Use existing code and standard tools when they
  fit the task.
- **Don't Oversimplify Critical Systems:** Don’t sacrifice correctness, security,
  or reliability for shorter code.

## Tests and checks

- Reuse or extend existing tests before adding new ones.
- Avoid tests that rerun suites and duplicate CI execution.

## Documentation

- Use plain language and established terms. Avoid repetition and unnecessary disclaimers.
