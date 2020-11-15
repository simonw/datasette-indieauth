# datasette-indieauth

[![PyPI](https://img.shields.io/pypi/v/datasette-indieauth.svg)](https://pypi.org/project/datasette-indieauth/)
[![Changelog](https://img.shields.io/github/v/release/simonw/datasette-indieauth?include_prereleases&label=changelog)](https://github.com/simonw/datasette-indieauth/releases)
[![Tests](https://github.com/simonw/datasette-indieauth/workflows/Test/badge.svg)](https://github.com/simonw/datasette-indieauth/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-indieauth/blob/main/LICENSE)

**Alpha**. Datasette authentication using [IndieAuth](https://indieauth.net/) and [RelMeAuth](http://microformats.org/wiki/RelMeAuth).

This initial version depends on [IndieAuth.com](https://indieauth.com/).

## Installation

Install this plugin in the same environment as Datasette.

    $ datasette install datasette-indieauth

## Usage

Ensure you have a website with a domain that supports IndieAuth or RelMeAuth.

Visit `/-/indieauth` to begin the sign-in progress.

## Development

To set up this plugin locally, first checkout the code. Then create a new virtual environment:

    cd datasette-indieauth
    python3 -mvenv venv
    source venv/bin/activate

Or if you are using `pipenv`:

    pipenv shell

Now install the dependencies and tests:

    pip install -e '.[test]'

To run the tests:

    pytest
