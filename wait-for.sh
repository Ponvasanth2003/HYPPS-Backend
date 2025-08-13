#!/bin/sh

# Usage: ./wait-for.sh host:port -- command-to-run-after

set -e

host_port=$1
shift       # shift once to remove host:port
shift       # shift again to remove the '--' separator

cmd="$@"

host=$(echo $host_port | cut -d: -f1)
port=$(echo $host_port | cut -d: -f2)

echo "⏳ Waiting for $host:$port to be available..."

while ! nc -z $host $port; do
  sleep 1
done

echo "✅ $host:$port is available. Running command: $cmd"
exec $cmd