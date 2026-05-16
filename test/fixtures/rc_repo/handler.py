"""Fixture: attack entry point. Calls resolve_path, which calls policy_check."""


def resolve_path(raw_path):
    """Normalise a requested path before any policy decision."""
    return raw_path.strip().replace("..", "")


def policy_check(resolved_path):
    """The control: decide whether a resolved path may be written."""
    return not resolved_path.startswith("/etc")


def handler(request):
    """Attack entry: handle a write request from the agent."""
    resolved = resolve_path(request["path"])
    if policy_check(resolved):
        return write_file(resolved, request["body"])
    return missing_helper(resolved)
