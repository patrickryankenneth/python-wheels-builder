import shutil

import pytest


def pytest_addoption(parser):
    parser.addoption("--integration", action="store_true",
                     help="also run the slow podman image-build tests")


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: builds the real image with podman")


def pytest_collection_modifyitems(config, items):
    skip = None
    if not config.getoption("--integration"):
        skip = pytest.mark.skip(reason="needs --integration")
    elif shutil.which("podman") is None:
        skip = pytest.mark.skip(reason="podman not installed")
    if skip:
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)