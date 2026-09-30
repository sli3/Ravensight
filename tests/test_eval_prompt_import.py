"""Import smoke test for scripts/eval_prompt.py — must not touch the LLM."""


def test_eval_prompt_imports_cleanly() -> None:
    """Importing scripts.eval_prompt has no side effects and succeeds."""
    import scripts.eval_prompt  # noqa: F401
