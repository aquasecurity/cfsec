## Using as a command line tool

The easiest way to run `cfsec` is to run it in the directory you want to scan.

```bash
cfsec
```

`cfsec` will traverse the directory till it finds a valid [CloudFormation] file; the directory it finds this file in will be considered to the working directory.

If you want to run on a specific location, this can be passed as an argument;

```bash
cfsec ./stacks/prod
```


The exit status will be non-zero if cfsec finds problems, otherwise the exit status will be zero.



## Use with Docker

As an alternative to installing and running cfsec on your system, you may
run cfsec in a Docker container.

To run:

```bash
docker run --rm -it -v "$(pwd):/src" aquasec/cfsec /src
```

## Using in CI

`cfsec` can be added to any CI pipeline as a command with the exit code dictating if it breaks the build.

We do provide a [GitHub Action] that will also upload the results to GitHub code scanning UI.


## Passing Arguments

This page only covers the basics of what `cfsec` can do - much more is achievable using the arguments on the [Parameters] page.



[CloudFormation]: https://aws.amazon.com/cloudformation/
[Parameters]: ../usage
