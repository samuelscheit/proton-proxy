FROM --platform=linux/amd64 node:24

LABEL maintainer="Proton-Multi-Tunnel"

EXPOSE 8100-8200

ENV PVPN_USERNAME="" \
    PVPN_PASSWORD="" \
    DNS_SERVERS_OVERRIDE="" \
    MAX_CONNECTIONS="0" \
    BASE_PROXY_PORT="8100" \
    PORT_GAP="1" \
    REQUIRE_TUN_IP="true" \
    RESET_CREDENTIALS_ON_START="false"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dbus \
        build-essential \
        fonts-liberation \
        iproute2 \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libgbm-dev \
        libgtk-3-0 \
        libnss3 \
        libx11-xcb1 \
        libxss1 \
        openresolv \
        openvpn \
        procps \
        python3 \
        wget \
    && mkdir -p /etc/openvpn/configs \
    && wget -q --https-only \
        https://raw.githubusercontent.com/ProtonVPN/scripts/master/update-resolv-conf.sh \
        -O /etc/openvpn/update-resolv-conf \
    && chmod 0755 /etc/openvpn/update-resolv-conf \
    && rm -rf /var/lib/apt/lists/*

# Build the native per-socket tunnel dialer before installing the app. The
# package preinstall hook runs npm install in this sibling directory.
COPY tundialer-native /tundialer-native
COPY app/package.json app/package-lock.json /app/
WORKDIR /app
RUN npm ci \
    && npx patchright install chrome

COPY app /app

# OpenVPN profiles and credentials are runtime inputs. Mount profiles at
# /etc/openvpn/configs instead of baking private .ovpn material into an image.
RUN mkdir -p /etc/openvpn/configs \
    && chmod 0755 /app/start.sh

ENV DBUS_SESSION_BUS_ADDRESS=autolaunch:

CMD ["/app/start.sh"]
