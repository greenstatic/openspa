FROM alpine
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY bin/echo-ip_container /echo-ip
ENTRYPOINT ["/echo-ip"]
CMD ["-p", "8080"]
