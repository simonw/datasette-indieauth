from setuptools import setup
import os

VERSION = "0.3.2"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="datasette-indieauth",
    description="Datasette authentication using IndieAuth and RelMeAuth",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/datasette-indieauth",
    project_urls={
        "Issues": "https://github.com/simonw/datasette-indieauth/issues",
        "CI": "https://github.com/simonw/datasette-indieauth/actions",
        "Changelog": "https://github.com/simonw/datasette-indieauth/releases",
    },
    license="Apache License, Version 2.0",
    version=VERSION,
    packages=["datasette_indieauth"],
    entry_points={"datasette": ["indieauth = datasette_indieauth"]},
    install_requires=["datasette"],
    extras_require={
        "test": ["pytest", "pytest-asyncio", "httpx", "pytest-httpx", "mf2py"]
    },
    tests_require=["datasette-indieauth[test]"],
    package_data={"datasette_indieauth": ["templates/*.html"]},
    python_requires=">=3.6",
)
