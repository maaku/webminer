FROM ubuntu:18.04 as builder

# Install Bazel
RUN apt-get update && \
    apt-get install -y apt-transport-https curl gnupg && \
    curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > /usr/share/keyrings/bazel-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list && \
    apt-get update && \
    apt-get install -y bazel
	
# Install webminer
RUN apt-get install -y build-essential autoconf automake libtool git && \
    git clone https://github.com/maaku/webminer && \
    cd webminer && bazel build -c opt webminer


FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=builder /webminer/bazel-bin /webminer

WORKDIR /host
ENTRYPOINT ["/webminer/webminer"]
