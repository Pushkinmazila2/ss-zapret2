ARG ALPINE_VERSION=3.21
ARG ZAPRET_TAG=v0.9.5
ARG CURL_VERSION=8.13.0

FROM alpine:${ALPINE_VERSION} AS build
ARG ZAPRET_TAG
ARG CURL_VERSION
ARG TARGETPLATFORM

WORKDIR /opt

RUN case "$TARGETPLATFORM" in \
      "linux/amd64") echo "linux-x86_64" > /tmp/zapret_arch && echo "x86_64" > /tmp/curl_arch ;; \
      "linux/arm64") echo "linux-arm64" > /tmp/zapret_arch && echo "aarch64" > /tmp/curl_arch ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac

RUN wget -qO- "https://github.com/bol-van/zapret2/releases/download/${ZAPRET_TAG}/zapret2-${ZAPRET_TAG}.tar.gz" | tar xz && \
    mv zapret2-* zapret2-src

WORKDIR /opt/zapret2-build

RUN src=/opt/zapret2-src && \
    ZAPRET_ARCH=$(cat /tmp/zapret_arch) && \
    mkdir -p binaries/${ZAPRET_ARCH} && \
    cp ${src}/binaries/${ZAPRET_ARCH}/ip2net \
       ${src}/binaries/${ZAPRET_ARCH}/mdig \
       ${src}/binaries/${ZAPRET_ARCH}/nfqws2 \
       binaries/${ZAPRET_ARCH}/ && \
    chmod +x binaries/${ZAPRET_ARCH}/*

RUN src=/opt/zapret2-src && \
    cp -a ${src}/init.d ${src}/common ${src}/ipset ${src}/blockcheck2.d ${src}/blockcheck2.sh . && \
    cp -a ${src}/files files && \
    mv files/fake files/fake.dist && \
    cp -a ${src}/lua lua.dist && \
    mv init.d/custom.d.examples.linux init.d/custom.d.examples.linux.dist && \
    find init.d -mindepth 1 -maxdepth 1 -type d \
      ! -name "sysv" \
      ! -name "files" \
      ! -name "custom.d.examples.*" \
      -exec rm -rf {} +

RUN ZAPRET_BASE=/opt/zapret2-build /opt/zapret2-src/install_bin.sh

RUN CURL_ARCH=$(cat /tmp/curl_arch) && \
    wget -qO- "https://github.com/stunnel/static-curl/releases/download/${CURL_VERSION}/curl-linux-${CURL_ARCH}-glibc-${CURL_VERSION}.tar.xz" | \
    tar -xJf - -C /opt && \
    chmod +x /opt/curl

FROM alpine:${ALPINE_VERSION}

RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk add --no-cache \
      ipset \
      iptables \
      ip6tables \
      nftables \
      netcat-openbsd \
      shadowsocks-libev

EXPOSE 1080 8388

WORKDIR /opt

COPY --from=build /opt/zapret2-build /opt/zapret2
COPY --from=build /opt/curl /usr/bin/curl
COPY entrypoint.sh /opt/entrypoint.sh

RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
