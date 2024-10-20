# Use the official Apache APISIX image as a base
FROM apache/apisix-dashboard:3.0.1-alpine

# Set the working directory
WORKDIR /usr/local/apisix-dashboard

# Copy the custom configuration file into the container
COPY conf/config.yaml  ./conf/config.yaml
COPY conf/schema.json  ./conf/schema.json
COPY conf/customize_schema.json  ./conf/customize_schema.json

 # Create the logs directory
RUN mkdir -p /usr/local/apisix-dashboard/logs
COPY logs/error.log ./logs/error.log
COPY logs/access.log ./logs/access.log

# Expose the necessary ports
EXPOSE 9080 9443 2379 2380 9000

ENTRYPOINT [ "/usr/local/apisix-dashboard/manager-api" ]

# Command to start APISIX
CMD ["--config", "conf/config.yaml"]