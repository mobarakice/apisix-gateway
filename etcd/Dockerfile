# Use the bitnami/etcd:latest as the base image
FROM bitnami/etcd:latest

# Set environment variables (optional, customize as per your requirement)
ENV BITNAMI_DEBUG=true

# Copy the custom etcd configuration file
COPY etcd.config.yaml /opt/bitnami/etcd/conf/etcd.config.yaml

# Set entrypoint for etcd, using custom configuration
ENTRYPOINT [ "/opt/bitnami/scripts/etcd/entrypoint.sh" ]

# Command to run etcd with the new configuration
CMD [ "/opt/bitnami/etcd/bin/etcd", "--config-file=/opt/bitnami/etcd/conf/etcd.config.yaml" ]
