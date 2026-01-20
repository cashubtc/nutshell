FROM debian:stable

RUN apt-get update && \
    apt-get install -y tor && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/tor/hidden_service 
USER root

# Entry script will fix permissions THEN start Tor
CMD chown -R debian-tor:debian-tor /var/lib/tor && \
    chmod -R 700 /var/lib/tor && \
    su debian-tor -s /bin/sh -c "tor -f /etc/tor/torrc"
