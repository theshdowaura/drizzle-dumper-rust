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

if [ -f "$MODDIR/bin/drizzle_dumper" ]; then
  chmod 0755 "$MODDIR/bin/drizzle_dumper"
fi
