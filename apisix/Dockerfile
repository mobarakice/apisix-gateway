FROM apache/apisix:latest

WORKDIR = /usr/local/apisix

COPY conf/config.yaml ./apisix/conf/config.yaml
COPY plugins/csrf.lua ./apisix/apisix/plugins/csrf.lua

ENTRYPOINT ["apisix", "start"]