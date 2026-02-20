FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc

# Fix ownership of torrc and data dir, then run as debian-tor (not root)
RUN chown debian-tor:debian-tor /etc/tor/torrc \
    && chown -R debian-tor:debian-tor /var/lib/tor

EXPOSE 9050 9051

USER debian-tor

CMD ["tor", "-f", "/etc/tor/torrc"]
