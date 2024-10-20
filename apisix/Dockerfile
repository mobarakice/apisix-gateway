# Use the official Apache APISIX image as a base
FROM apache/apisix:3.10.0-debian

# Set the working directory
WORKDIR /usr/local/apisix

# Copy the custom configuration file into the container
COPY conf/config.yaml  ./conf/config.yaml
COPY plugins/csrf.lua  ./apisix/plugins/csrf.lua
# Expose the necessary ports
EXPOSE 9080 9091 9180 9443

# Command to start APISIX
CMD ["apisix", "start"]