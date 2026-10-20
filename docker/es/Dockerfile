# Elasticsearch 8.13.4, but with its bundled JDK 21.0.2 replaced by Temurin
# 21.0.12. Reason: JDK 21.0.2 SIGILLs at JVM init on Apple Silicon under Docker
# Desktop because it probes the ARM SVE (Scalable Vector Extension) vector
# length, which the guest does not expose. Temurin 21.0.12 backports the fix
# (JDK-8318445) and simply disables SVE instead of crashing.
FROM eclipse-temurin:21-jdk AS jdk

FROM docker.elastic.co/elasticsearch/elasticsearch:8.13.4
USER root
RUN rm -rf /usr/share/elasticsearch/jdk
COPY --from=jdk /opt/java/openjdk /usr/share/elasticsearch/jdk
RUN chown -R elasticsearch:root /usr/share/elasticsearch/jdk
USER elasticsearch
