# ipadecrypt credmint toolchain: builds the arm64 iOS credential-mint programs
# on Linux (clang -> arm64-apple-ios, ldid for ad-hoc signing, iPhoneOS SDK).
# Unlike the old helper image this keeps System/Library/Frameworks, because the
# device programs link CoreFoundation and IOKit.

ARG DEBIAN_TAG=bookworm-slim
ARG LLVM_VERSION=18
ARG LDID_REV=v2.1.5-procursus7
ARG SDKS_REPO=xybp888/iOS-SDKs
ARG SDKS_COMMIT=dfc736746932759181e879ceae02e12f314c5510
ARG SDK_VERSION=26.4


#----- stage: build ldid from source ---------------------------------------
FROM debian:${DEBIAN_TAG} AS ldid-builder
ARG LDID_REV
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential pkg-config libssl-dev libplist-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "$LDID_REV" --recurse-submodules \
        https://github.com/ProcursusTeam/ldid /tmp/ldid \
    && make -C /tmp/ldid -j"$(nproc)" \
    && install -Dm 755 /tmp/ldid/ldid /out/ldid


#----- stage: fetch + trim iPhoneOS SDK ------------------------------------
FROM debian:${DEBIAN_TAG} AS sdk-fetcher
ARG SDKS_REPO
ARG SDKS_COMMIT
ARG SDK_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# Keeping System/Library/Frameworks makes the on-demand blob fetch large, so
# harden the transfer (big buffer, no low-speed abort) and retry it.
RUN git config --global http.postBuffer 1048576000 \
    && git config --global http.lowSpeedLimit 0 \
    && git config --global http.lowSpeedTime 999999 \
    && git clone --filter=blob:none --sparse "https://github.com/${SDKS_REPO}" /tmp/sdks \
    && cd /tmp/sdks \
    && git checkout "$SDKS_COMMIT" \
    && for i in 1 2 3 4 5; do \
           git sparse-checkout set "iPhoneOS${SDK_VERSION}.sdk" && break; \
           echo "sparse-checkout retry $i"; sleep 5; \
       done \
    && test -d "iPhoneOS${SDK_VERSION}.sdk" \
    && rm -rf .git \
    && mv "iPhoneOS${SDK_VERSION}.sdk" /out \
    # Keep usr/ and System/ (frameworks), drop only the developer tree.
    && rm -rf /out/Developer


#----- stage: final runtime image ------------------------------------------
FROM debian:${DEBIAN_TAG}
ARG LLVM_VERSION
ARG SDK_VERSION

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        libssl3 libplist3 \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
         | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VERSION} main" \
         > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        clang-${LLVM_VERSION} \
        lld-${LLVM_VERSION} \
    && ln -sf /usr/bin/clang-${LLVM_VERSION}    /usr/bin/clang \
    && ln -sf /usr/bin/ld64.lld-${LLVM_VERSION} /usr/bin/ld64.lld \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
              /etc/apt/sources.list.d/llvm.list \
              /usr/share/keyrings/llvm.gpg

COPY --from=ldid-builder /out/ldid /usr/local/bin/ldid
COPY --from=sdk-fetcher  /out      /opt/iphoneos.sdk

ENV IPHONEOS_SDK=/opt/iphoneos.sdk \
    IPHONEOS_SDK_VERSION=${SDK_VERSION} \
    IPHONEOS_DEPLOYMENT_TARGET=10.0

WORKDIR /workspace
