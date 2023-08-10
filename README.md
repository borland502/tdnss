# tdnss

A Python API wrapper for
[Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer)'s
HTTP API.

## Notice

This project is a work in progress. A list of features will be added, for now
some basic methods of 
[API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)
such as login/logout are implemented, with work on the [zone
API](src/tdnss/zone_api.py) and the [settings API](src/tdnss/settings_api.py) is
ongoing.

Any feedback is welcome!

## Why?

TL;DR: the main reason I use this DNS server is its API, since it gives full
control over the server without having to login to the web console. The idea is
that scripts/CLIs/other tools can be built upon a library that wraps the API.

## Installation

The `tdnss` package is [available on PyPI](https://pypi.org/project/tdnss/).

For development, use the provided Pipfile:

```bash
pipenv install --dev
```
This creates a [virtual
environment](https://docs.python.org/3/library/venv.html), installs the
dependencies to run the package, the development tools, and the package itself
as an editable dependency in order to test the changes live.

If you don't use Pipenv, there's a `requirements.txt` provided to install
runtime dependencies and a `requirements-dev.txt` to install development tools
and `tdnss` as an editable package.

## Contributing

Do you want to contribute to this project? Great! We welcome any contributions,
from code to documentation through feedback. Read
[CONTRIBUTING](./CONTRIBUTING.md) for more information.

## License

This project is licensed under the GNU General Public License v3.0 only.

See [COPYING](./COPYING) to see the full text.

## Versioning

This project follows
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
