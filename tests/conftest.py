import pytest


@pytest.fixture
def manifest_dict():
    return {
        "principal": {"agent": "claude-code"},
        "task": {"repo": "acme/backend", "issue": 482, "objective": "fix_and_open_pr"},
        "tools": {
            "allow": ["github.repo.read", "github.branch.create",
                      "github.commit.write", "github.pull_request.create", "npm.*"],
            "deny": ["aws.*", "github.repository.delete", "github.secrets.read"],
        },
        "filesystem": {
            "read": ["workspace/**"],
            "write": ["workspace/src/**"],
            "deny": ["**/.env", "**/.ssh/**"],
        },
        "network": {"allow": ["github.com", "registry.npmjs.org"]},
        "delegation": {"max_depth": 1},
        "expiry_minutes": 60,
    }
