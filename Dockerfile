FROM alpine:3.14

USER nobody
# work somewhere where we can write
COPY cfsec /usr/bin/cfsec
# set the default entrypoint -- when this container is run, use this command
ENTRYPOINT [ "cfsec" ]
# as we specified an entrypoint, this is appended as an argument (i.e., `cfsec --help`)
CMD [ "--help" ]