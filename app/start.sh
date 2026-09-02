#!/usr/bin/env sh

set -e
dbus-daemon --system

rm -f /.user_data/SingletonLock
rm -f /.user_data/SingletonSocket
rm -f /.user_data/SingletonCookie

exec node /app/index.ts
