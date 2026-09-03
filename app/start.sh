#!/usr/bin/env sh

set -eu

# Docker restarts preserve this container's writable layer.  A previous
# system bus can therefore leave /run/dbus/pid behind even though Docker has
# already terminated the daemon; a bare `dbus-daemon --system` then exits and
# puts the whole proxy into a restart loop.  Reuse a live bus when one exists,
# otherwise remove only stale bus runtime files and fork a fresh daemon without
# creating another persistent PID file.
if ! dbus-send --system --type=method_call \
	--dest=org.freedesktop.DBus \
	/org/freedesktop/DBus \
	org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
	rm -f /run/dbus/pid /var/run/dbus/pid /run/dbus/system_bus_socket
	mkdir -p /run/dbus
	dbus-daemon --system --fork --nopidfile
fi

rm -f /.user_data/SingletonLock
rm -f /.user_data/SingletonSocket
rm -f /.user_data/SingletonCookie

exec node /app/index.ts
