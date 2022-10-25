# tdnss

A Python API wrapper for
[Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer)'s
HTTP API.

## Notice
This project is currently a work in progress: only the basic methods of the 
[API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md)
are implemented (login, logout, etc.). They are working, if you want to test
them.

## Why?

TL;DR: the main reason I use this DNS server is its API, since it gives full
control over the server without having to login to the web console.
For a slightly more detailed answer, see
[here](https://www.julioloayzam.com/blog/tdnss/).

## Installation

There is a package on PyPI (`tdnss`) but as the version number indicates, this
wrapper is still a work in progress.

For development, use the provided Pipfile:
```bash
pipenv install --dev
```
This installs the only dependency, `requests`.  The `--dev` flag installs some
dev tools (`flake8`, `black`, `pytest`) and `tdnss` as an editable dependency in
order to test it.

If you don't use Pipenv, there's also a provided `requirements.txt` to ensure
`requests` is installed and a `requirements-dev.txt` that corresponds to the
execution of `pipenv install --dev`.

## Contributing

Currently a good part of all API calls is covered, but the code was written for
the previous version of the API so I'm currently in the process of updating it.
So testing is a good way to contribute.

If you want to contribute code, please open an issue indicating which section
you would like to work on so that I can check if there isn't already some code
written for it.

For more information, see [CONTRIBUTING](./CONTRIBUTING.md).

## License

This project is licensed under the GNU General Public License v3.0 only.

See [COPYING](./COPYING) to see the full text.

## Versioning

This project follows
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
