/**
 * Bitpeek Ultra - QEMU Debug Configuration Generator
 *
 * Implements Section 11 (TRACE-05, AC057):
 * - Generates structured argv array without shell interpolation
 * - Restricts GDB server endpoint to localhost (127.0.0.1)
 * - Pins architecture, CPU model, memory, and devices
 */

export interface QemuConfig {
  arch: 'x86_64' | 'aarch64' | 'arm' | 'riscv64'
  machine?: string
  cpu?: string
  memoryMb?: number
  kernelPath?: string
  diskImagePath?: string
  gdbPort?: number // defaults to 1234
  freezeAtStartup?: boolean // -S flag
  extraArgs?: string[]
}

export class QemuConfigBuilder {
  /**
   * Builds a safe argv array for launching QEMU with an attached GDB server.
   * Never uses shell string interpolation.
   */
  public static buildArgv(config: QemuConfig): string[] {
    const binary = `qemu-system-${config.arch}`
    const argv: string[] = [binary]

    if (config.machine) {
      argv.push('-M', config.machine)
    }

    if (config.cpu) {
      argv.push('-cpu', config.cpu)
    }

    const mem = config.memoryMb ?? 512
    argv.push('-m', `${mem}M`)

    if (config.kernelPath) {
      argv.push('-kernel', config.kernelPath)
    }

    if (config.diskImagePath) {
      argv.push('-drive', `file=${config.diskImagePath},format=raw,if=virtio`)
    }

    argv.push('-nographic')

    // Always bind GDB server strictly to 127.0.0.1 (local only)
    const port = config.gdbPort ?? 1234
    argv.push('-gdb', `tcp:127.0.0.1:${port}`)

    if (config.freezeAtStartup !== false) {
      argv.push('-S') // Freeze CPU at startup
    }

    if (config.extraArgs) {
      argv.push(...config.extraArgs)
    }

    return argv
  }
}
