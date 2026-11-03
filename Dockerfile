FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY bin ./bin
RUN pip install --no-cache-dir .
# Glama only needs the process to start and answer MCP introspection.
# Harnis is a proxy; point it at a tiny stdio echo upstream for health checks.
RUN printf '%s\n' '#!/usr/bin/env python3' \
  'import json,sys' \
  'def send(msg):' \
  '  data=json.dumps(msg).encode()' \
  '  sys.stdout.buffer.write(data+b"\\n"); sys.stdout.buffer.flush()' \
  'for line in sys.stdin.buffer:' \
  '  req=json.loads(line)' \
  '  mid=req.get("id")' \
  '  method=req.get("method")' \
  '  if method=="initialize":' \
  '    send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"harnis-health","version":"0"}}})' \
  '  elif method=="notifications/initialized":' \
  '    continue' \
  '  elif method=="tools/list":' \
  '    send({"jsonrpc":"2.0","id":mid,"result":{"tools":[]}})' \
  '  elif mid is not None:' \
  '    send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"Method not found"}})' \
  > /usr/local/bin/harnis-health-upstream && chmod +x /usr/local/bin/harnis-health-upstream
RUN useradd --create-home app
USER app
CMD ["harnis", "mcp", "--preset", "readonly", "--", "/usr/local/bin/harnis-health-upstream"]
