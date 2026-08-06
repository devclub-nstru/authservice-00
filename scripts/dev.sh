#!/bin/sh

# Kill child processes on exit
trap 'kill 0' EXIT

# Start server and worker in the background
./tmp/server &
./tmp/worker &

# Wait for both processes
wait
