# Lictor Isolation — red-zone AI sandbox (v0.1, container form)
# The AI agent runs here. It can reach the model provider on the public internet,
# but the entrypoint locks all egress to private (RFC1918) networks — so a hijacked
# agent cannot touch your LAN, domain controller, or prod ("the black zone").
FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*

# (At launch: bake in Airlock in enforce mode so every action is brokered too.
#  Until @lictor/airlock is on npm, mount it or `npm i` it inside /work.)
COPY redzone-entrypoint.sh /usr/local/bin/redzone-entrypoint
RUN chmod +x /usr/local/bin/redzone-entrypoint

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/redzone-entrypoint"]
CMD ["bash"]
