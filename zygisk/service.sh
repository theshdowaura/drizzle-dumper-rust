#!/system/bin/sh
# Sync the latest gadget deployment prepared by drizzle-dumper into the module directory.
MODDIR=${0%/*}
SRC_DIR=/data/local/tmp/drizzle_gadget/latest
DEST_DIR="$MODDIR/frida"

mkdir -p "$DEST_DIR"

if [ -d "$SRC_DIR" ]; then
  cp -f "$SRC_DIR"/frida-gadget.so "$DEST_DIR"/frida-gadget.so 2>/dev/null
  cp -f "$SRC_DIR"/frida-gadget.config "$DEST_DIR"/frida-gadget.config 2>/dev/null
fi

RUN_DIR="$MODDIR/run"
mkdir -p "$RUN_DIR"

if [ -f "$MODDIR/bin/drizzle_dumper" ]; then
  chmod 0755 "$MODDIR/bin/drizzle_dumper"
fi

# Auto-start drizzle_dumper MCP server if not already running
MCP_BIND="0.0.0.0:45831"
if [ -f "$MODDIR/config/mcp_bind" ]; then
  read -r MCP_BIND < "$MODDIR/config/mcp_bind"
fi

PID_FILE="$RUN_DIR/mcp-server.pid"

if [ -x "$MODDIR/bin/drizzle_dumper" ]; then
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    :
  else
    "$MODDIR/bin/drizzle_dumper" mcp-server --bind "$MCP_BIND" >/dev/null 2>&1 &
    echo $! > "$PID_FILE"
  fi
fi
