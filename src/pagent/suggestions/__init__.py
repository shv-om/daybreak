"""Infrastructure that helps the local model generate better-targeted, context-specific test
suggestions. Nothing in this package executes a tool, calls the policy gateway, or produces
anything with ``requires_approval`` / ``execution_state`` semantics itself - it only prepares
input for, and validates the shape of, the existing proposal-only AI integration (see
``pagent.proposals``).
"""
