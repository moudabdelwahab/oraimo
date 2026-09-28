import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.harness import Env  # noqa: E402


@pytest.fixture
def make_env():
    envs = []

    def factory(*mock_flags, agent_args=(), start_mock=True, system_address=None, extra_env=None):
        env = Env()
        envs.append(env)
        if start_mock:
            env.start_mock(*mock_flags)
        env.start_agent(*agent_args, system_address=system_address, extra_env=extra_env)
        return env

    yield factory
    for env in envs:
        env.stop()


@pytest.fixture
def env(make_env):
    return make_env()
