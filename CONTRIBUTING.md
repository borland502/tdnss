# Contributing to tdnss

First off, thank you for considering contributing to tdnss! :)

The following is a set of guidelines for contributing to the repository.  These
are guidelines, not hard rules.

- [Contributing to tdnss](#contributing-to-tdnss)
  - [This is too much to read, I just want to ask a question!](#this-is-too-much-to-read-i-just-want-to-ask-a-question)
  - [What type of contributions are allowed?](#what-type-of-contributions-are-allowed)
  - [Your first contribution](#your-first-contribution)
  - [Code guidelines](#code-guidelines)
    - [Docstring examples](#docstring-examples)
    - [Being explicit](#being-explicit)
  - [Contributing code](#contributing-code)
  - [Code review process](#code-review-process)
  - [Reporting bugs](#reporting-bugs)
    - [Security disclosures](#security-disclosures)
    - [Regular bugs](#regular-bugs)
  - [Suggesting a feature or enhancement](#suggesting-a-feature-or-enhancement)

## This is too much to read, I just want to ask a question!

You can [open an issue](https://codeberg.org/JulioLoayzaM/tdnss/issues) and use
the `question` label.

## What type of contributions are allowed?

All contributions are welcome: share suggestions, feature ideas and bug
reports by [opening an issue](https://codeberg.org/JulioLoayzaM/tdnss/issues).

Code contributions are also welcome, fork the repo and
[create a pull request](https://codeberg.org/JulioLoayzaM/tdnss/pulls).

See below for more information.

## Your first contribution

You want to contribute but don't know where to start? You can check if there are
issues with:

-  The [good first issue label](https://codeberg.org/JulioLoayzaM/tdnss/issues?q=&state=open&labels=73949)
   for issues that usually require just a few lines of code and where steps
   towards the solution may be provided.
-  The [help wanted label](https://codeberg.org/JulioLoayzaM/tdnss/issues?q=&state=open&labels=73944)
   for issues that require more attention and/or time, but aren't necessarily
   harder than first issues.

Working on your first pull request? Check out
[this guide](https://opensource.guide/how-to-contribute/).
If you still have some doubts, feel free to ask for help. :)

## Code guidelines

Some things to consider before submitting code:

1. Document and comment your code (examples below):

   -  In general, functions must be type-hinted and have a clear description in
      its docstring. The docstrings are written
      [Google style](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html).
      See below for an example.
   -  Don't hesitate to comment: if there are too many (unnecessary) comments,
      they can be cleaned before merging.
   -  Remember,
      [explicit is better than implicit](https://www.python.org/dev/peps/pep-0020/#the-zen-of-python).
   -  Use spaces.

2. Test your changes if possible. If not, indicate it with a comment below the
   docstring. For example: `# TODO: test this`.
3. Begin your commit message with an action in the present tense:
   add \| remove \| change \| fix \| deprecate.

### Docstring examples

Most of the methods will return a `ConnectionResponse`, which inherits from
`BaseResponse`. To see how to document this, refer to the
[definition of BaseResponse](https://codeberg.org/JulioLoayzaM/tdnss/src/branch/main/src/tdnss/baseresponse.py).

A Google style docstring, at least in this repo, will look like this:
```python
def _get(
   self, path: str, params: Dict[str, str] = dict(), stream=False
) -> requests.Response:
   """Perform the GET request.

   If a token is set, use it without checking whether it is valid. Otherwise,
   it means that the user has not logged in so an exception is raised.

   Args:
      path:
            The API path to GET. It is the last part of the URL, after '/api/'.
            For example, if the URL is https://<server address>/api/user/login,
            path corresponds to the 'user/login' part.
      params:
            The parameters to use. Defaults to an empty Dict. Normally, there is no
            need to include the token in these parameters, see note below.
      stream:
            It is passed as is to requests' get. Defaults to False.

   Returns:
      requests.Response: The response received.

   Raises:
      Exception: If the token is not set, i.e. the user has not logged in.

   Note:
      If the Connection has an API token, set either when it was created or by
      _auto_login, it is automatically added to the params. However, there may be
      cases where another API token or a session token must be used. To do so,
      simply include the token in the params dict and it will be used instead of
      the API token.
      If the Connection does not have an API token, then a token *must* be in the
      given params.
   """
```

This example is taken from the
[Connection.\_get method](https://codeberg.org/JulioLoayzaM/tdnss/src/commit/d7f3209464a866647a9271f98ba2bf1d03212276/src/tdnss/connection.py#L188)

We see that the function:

-  Is type-hinted, i.e. the type of the parameters and the return values
   are indicated.
-  Has a description of its behaviour.
-  Explains the different parameters, return values, and possible
   exceptions, whenever it applies.

Type-hinting outside of docstrings is encouraged, especially for imported
classes, since IDEs usually use the hints to show suggestions.

## Contributing code

The following guide was adapted from
https://github.com/MarcDiethelm/contributing/blob/master/README.md:

-  Create a personal fork of the project on Codeberg.
-  Clone the fork on your local machine. Your remote repo on Codeberg is called
   `origin`.
-  Add the original repository as a remote called `upstream`.
-  If you created your fork a while ago be sure to **pull upstream changes**
   into your local repository.
-  Create a new branch to work on! Branch from `develop`, preferably with a
   distinctive name such as `develop/translation`.
-  Implement/fix your feature, comment your code.
-  Follow the code style of the project: see the
   [code guidelines](./CONTRIBUTING.md#code-guidelines).
-  Add or change the documentation as needed.
-  If you have many smaller commits, you can squash them with git's
   [interactive rebase](https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase).
   Create a new branch if necessary.
-  Push your branch to your fork on Codeberg, the remote `origin`.
-  From your fork open a pull request in the `develop` branch.
-  Wait for it.
-  If a maintainer requests further changes just push them to your branch. The
   PR will be updated automatically.
-  Once the pull request is approved and merged you can pull the changes from
   `upstream` to your local repo and delete your extra branch(es).

For more information on the related commands, you can check this gist:
https://gist.github.com/adamloving/5690951.

## Code review process

I will review all submitted code as soon as possible, which may be not that soon.

All tags/releases are to be signed by me.

## Reporting bugs

### Security disclosures

I don't really expect this project to have a (significant) security issue, but
better safe than sorry: if you find one, **do not open an issue**. Email me at
julio [plus] tdnss [at] loayzameneses [dot] com.

### Regular bugs

Create an issue. Currently there's no bug template. Try to give as much
information as possible: logs, what were you doing when the bug appeared, etc.

Create a pull request if you have found a fix!

## Suggesting a feature or enhancement

Create an issue. Currently there's no template for this either.

Create a pull request if you have already started implementing it!
