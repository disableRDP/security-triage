FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Fake credentials the samples may try to read. Obvious canaries, not real secrets.
RUN useradd -m -u 1000 sandbox \
 && mkdir -p /home/sandbox/.aws /home/sandbox/.ssh /workspace /out \
 && printf '[default]\naws_access_key_id = CANARY_NOT_A_REAL_KEY\naws_secret_access_key = CANARY_NOT_A_REAL_SECRET\n' > /home/sandbox/.aws/credentials \
 && printf 'CANARY NOT A REAL PRIVATE KEY\n' > /home/sandbox/.ssh/id_rsa \
 && chmod 600 /home/sandbox/.aws/credentials /home/sandbox/.ssh/id_rsa \
 && chown -R sandbox:sandbox /home/sandbox /workspace /out
COPY monitor /monitor
RUN chmod +x /monitor/*.sh
USER sandbox
WORKDIR /workspace
