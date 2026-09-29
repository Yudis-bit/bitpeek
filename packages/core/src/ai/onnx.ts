/**
 * Bitpeek Ultra - ONNX Model Metadata & Protobuf Wire Parser
 *
 * Implements Section 16 (AI-02, AC071):
 * - Bounded protobuf wire parsing for ModelProto and GraphProto
 * - Extracts ir_version, opset, node counts, input/output tensors
 * - Strictly bounded inspection without loading custom operators or tensor buffers
 */

import { BoundedCheckedReader } from '../reader'

export interface OnnxTensorInfo {
  name: string
  elemType?: number
  shape?: number[]
}

export interface OnnxNodeInfo {
  name?: string
  opType: string
  inputs: string[]
  outputs: string[]
}

export interface OnnxModelMetadata {
  irVersion: number
  producerName?: string
  producerVersion?: string
  graphName?: string
  nodeCount: number
  inputTensors: OnnxTensorInfo[]
  outputTensors: OnnxTensorInfo[]
  nodes: OnnxNodeInfo[]
  opsetVersions: Array<{ domain: string; version: number }>
}

export class OnnxProtobufParser {
  /**
   * Parses ONNX ModelProto metadata from raw protobuf bytes.
   */
  public static parse(bytes: Uint8Array): OnnxModelMetadata {
    const reader = new BoundedCheckedReader(bytes)

    let irVersion = 0
    let producerName: string | undefined
    let producerVersion: string | undefined
    let graphName: string | undefined
    let nodeCount = 0
    const inputTensors: OnnxTensorInfo[] = []
    const outputTensors: OnnxTensorInfo[] = []
    const nodes: OnnxNodeInfo[] = []
    const opsetVersions: Array<{ domain: string; version: number }> = []

    // Read ModelProto fields
    while (reader.position < bytes.length) {
      const tag = this.readVarint(reader)
      const fieldNum = tag >>> 3
      const wireType = tag & 0x07

      if (fieldNum === 1 && wireType === 0) {
        // ir_version (int64)
        irVersion = this.readVarint(reader)
      } else if (fieldNum === 2 && wireType === 2) {
        // producer_name (string)
        producerName = this.readString(reader)
      } else if (fieldNum === 3 && wireType === 2) {
        // producer_version (string)
        producerVersion = this.readString(reader)
      } else if (fieldNum === 7 && wireType === 2) {
        // graph (GraphProto)
        const gLen = this.readVarint(reader)
        const gStart = reader.position
        const gEnd = gStart + gLen

        // Parse GraphProto fields inside bounds
        while (reader.position < gEnd && reader.position < bytes.length) {
          const gTag = this.readVarint(reader)
          const gFieldNum = gTag >>> 3
          const gWireType = gTag & 0x07

          if (gFieldNum === 1 && gWireType === 2) {
            // node (NodeProto repeated)
            nodeCount++
            const nodeLen = this.readVarint(reader)
            const nodeBytes = reader.readBytesSync(nodeLen)
            const nodeInfo = this.parseNode(nodeBytes)
            if (nodes.length < 100) {
              nodes.push(nodeInfo)
            }
          } else if (gFieldNum === 2 && gWireType === 2) {
            // graph name (string)
            graphName = this.readString(reader)
          } else if (gFieldNum === 11 && gWireType === 2) {
            // input (ValueInfoProto repeated)
            const viLen = this.readVarint(reader)
            const viBytes = reader.readBytesSync(viLen)
            inputTensors.push(this.parseValueInfo(viBytes))
          } else if (gFieldNum === 12 && gWireType === 2) {
            // output (ValueInfoProto repeated)
            const viLen = this.readVarint(reader)
            const viBytes = reader.readBytesSync(viLen)
            outputTensors.push(this.parseValueInfo(viBytes))
          } else {
            this.skipField(reader, gWireType)
          }
        }
        reader.seek(gEnd)
      } else if (fieldNum === 8 && wireType === 2) {
        // opset_import (OperatorSetIdProto repeated)
        const opLen = this.readVarint(reader)
        const opBytes = reader.readBytesSync(opLen)
        opsetVersions.push(this.parseOpset(opBytes))
      } else {
        this.skipField(reader, wireType)
      }
    }

    return {
      irVersion,
      producerName,
      producerVersion,
      graphName,
      nodeCount,
      inputTensors,
      outputTensors,
      nodes,
      opsetVersions,
    }
  }

  private static parseNode(bytes: Uint8Array): OnnxNodeInfo {
    const reader = new BoundedCheckedReader(bytes)
    const inputs: string[] = []
    const outputs: string[] = []
    let opType = 'UNKNOWN'
    let name: string | undefined

    while (reader.position < bytes.length) {
      const tag = this.readVarint(reader)
      const fieldNum = tag >>> 3
      const wireType = tag & 0x07

      if (fieldNum === 1 && wireType === 2) {
        inputs.push(this.readString(reader))
      } else if (fieldNum === 2 && wireType === 2) {
        outputs.push(this.readString(reader))
      } else if (fieldNum === 3 && wireType === 2) {
        name = this.readString(reader)
      } else if (fieldNum === 4 && wireType === 2) {
        opType = this.readString(reader)
      } else {
        this.skipField(reader, wireType)
      }
    }

    return { name, opType, inputs, outputs }
  }

  private static parseValueInfo(bytes: Uint8Array): OnnxTensorInfo {
    const reader = new BoundedCheckedReader(bytes)
    let name = ''

    while (reader.position < bytes.length) {
      const tag = this.readVarint(reader)
      const fieldNum = tag >>> 3
      const wireType = tag & 0x07

      if (fieldNum === 1 && wireType === 2) {
        name = this.readString(reader)
      } else {
        this.skipField(reader, wireType)
      }
    }

    return { name }
  }

  private static parseOpset(bytes: Uint8Array): { domain: string; version: number } {
    const reader = new BoundedCheckedReader(bytes)
    let domain = ''
    let version = 0

    while (reader.position < bytes.length) {
      const tag = this.readVarint(reader)
      const fieldNum = tag >>> 3
      const wireType = tag & 0x07

      if (fieldNum === 1 && wireType === 2) {
        domain = this.readString(reader)
      } else if (fieldNum === 2 && wireType === 0) {
        version = this.readVarint(reader)
      } else {
        this.skipField(reader, wireType)
      }
    }

    return { domain, version }
  }

  private static readVarint(reader: BoundedCheckedReader): number {
    let result = 0
    let shift = 0
    let count = 0

    while (count < 10 && reader.remaining > 0) {
      const b = reader.readU8Sync()
      count++
      result |= (b & 0x7f) << shift
      shift += 7
      if ((b & 0x80) === 0) {
        return result
      }
    }
    return result
  }

  private static readString(reader: BoundedCheckedReader): string {
    const len = this.readVarint(reader)
    const strBytes = reader.readBytesSync(len)
    return new TextDecoder('utf-8', { fatal: false }).decode(strBytes)
  }

  private static skipField(reader: BoundedCheckedReader, wireType: number): void {
    if (wireType === 0) {
      this.readVarint(reader)
    } else if (wireType === 1) {
      reader.skip(8)
    } else if (wireType === 2) {
      const len = this.readVarint(reader)
      reader.skip(len)
    } else if (wireType === 5) {
      reader.skip(4)
    }
  }
}
