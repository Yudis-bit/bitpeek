#!/usr/bin/env node
import { tsImport } from 'tsx/esm/api'

tsImport('../src/server.ts', import.meta.url).then(({ runMcpServer }) => runMcpServer()).catch((err) => {
  process.stderr.write(`Fatal MCP error: ${err.message}\n`)
  process.exit(1)
})
