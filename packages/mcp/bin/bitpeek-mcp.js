#!/usr/bin/env node
import { runMcpServer } from '../src/server.js'

runMcpServer().catch((err) => {
  process.stderr.write(`Fatal MCP error: ${err.message}\n`)
  process.exit(1)
})
