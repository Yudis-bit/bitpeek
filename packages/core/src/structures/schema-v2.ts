import type { StructureField, StructureParseResult, FieldStatus } from './types'
import { formatHex } from '../bytes'
import type { Endian } from './schema'

// --- Declarative Expression AST ---
export type SchemaV2Expr =
  | { type: 'literal'; value: number | string | boolean }
  | { type: 'ref'; path: string }
  | { type: 'unary'; op: 'not' | 'neg' | 'bit_not'; expr: SchemaV2Expr }
  | {
      type: 'binary'
      op:
        | 'add'
        | 'sub'
        | 'mul'
        | 'div'
        | 'mod'
        | 'bit_and'
        | 'bit_or'
        | 'bit_xor'
        | 'shl'
        | 'shr'
        | 'eq'
        | 'neq'
        | 'lt'
        | 'lte'
        | 'gt'
        | 'gte'
      left: SchemaV2Expr
      right: SchemaV2Expr
    }
  | {
      type: 'conditional'
      condition: SchemaV2Expr
      consequent: SchemaV2Expr
      alternate: SchemaV2Expr
    }

export type ScalarFieldTypeV2 =
  | 'u8'
  | 'i8'
  | 'u16'
  | 'i16'
  | 'u24'
  | 'u32'
  | 'i32'
  | 'u64'
  | 'i64'
  | 'f32'
  | 'f64'

export interface BaseFieldV2 {
  id: string
  label: string
  offset?: number | SchemaV2Expr
  relativeTo?: 'parent' | 'previous' | 'absolute'
  description?: string
  specLink?: string
  condition?: SchemaV2Expr
  assertions?: Array<{
    condition: SchemaV2Expr
    message: string
    severity?: 'error' | 'warning'
  }>
}

export interface ScalarFieldV2 extends BaseFieldV2 {
  type: ScalarFieldTypeV2
  endian?: Endian
}

export interface BytesFieldV2 extends BaseFieldV2 {
  type: 'bytes' | 'ascii' | 'utf8'
  length: number | SchemaV2Expr
}

export interface BitfieldV2 extends BaseFieldV2 {
  type: 'bitfield'
  containerType: 'u8' | 'u16' | 'u32' | 'u64'
  lsb: number
  width: number
  endian?: Endian
}

export interface StructFieldV2 extends BaseFieldV2 {
  type: 'struct'
  fields: CustomFieldV2[]
  endian?: Endian
  boundedSize?: number | SchemaV2Expr
}

export interface ArrayFieldV2 extends BaseFieldV2 {
  type: 'array'
  count: number | SchemaV2Expr
  itemType: CustomFieldV2
}

export interface TaggedUnionFieldV2 extends BaseFieldV2 {
  type: 'union'
  tagExpr: SchemaV2Expr
  cases: Array<{
    tagValue: number | string
    field: CustomFieldV2
  }>
  defaultCase?: CustomFieldV2
}

export type CustomFieldV2 =
  | ScalarFieldV2
  | BytesFieldV2
  | BitfieldV2
  | StructFieldV2
  | ArrayFieldV2
  | TaggedUnionFieldV2

export interface CustomStructureSchemaV2 {
  schemaVersion: 2
  name: string
  description?: string
  defaultEndian?: Endian
  fields: CustomFieldV2[]
  maxFuel?: number
  maxRecursionDepth?: number
}

export class SchemaV2Interpreter {
  private fuel: number
  private maxDepth: number
  private env = new Map<string, any>()
  private warnings: string[] = []

  constructor(
    private readonly bytes: Uint8Array,
    private readonly schema: CustomStructureSchemaV2,
  ) {
    this.fuel = schema.maxFuel ?? 50_000
    this.maxDepth = schema.maxRecursionDepth ?? 32
  }

  private consumeFuel(amount = 1): void {
    this.fuel -= amount
    if (this.fuel <= 0) {
      throw new Error(`Schema execution fuel exhausted (limit: ${this.schema.maxFuel ?? 50_000})`)
    }
  }

  public evaluateExpr(expr: SchemaV2Expr, depth = 0): any {
    if (depth > this.maxDepth) {
      throw new Error(`Expression recursion depth exceeded (${this.maxDepth})`)
    }
    this.consumeFuel(1)

    switch (expr.type) {
      case 'literal':
        return expr.value

      case 'ref': {
        const val = this.resolveRef(expr.path)
        if (val === undefined) {
          throw new Error(`Unresolved reference in schema expression: "${expr.path}"`)
        }
        return val
      }

      case 'unary': {
        const inner = this.evaluateExpr(expr.expr, depth + 1)
        switch (expr.op) {
          case 'not':
            return !inner
          case 'neg':
            return typeof inner === 'bigint' ? -inner : -Number(inner)
          case 'bit_not':
            return typeof inner === 'bigint' ? ~inner : ~Number(inner)
        }
        break
      }

      case 'binary': {
        const left = this.evaluateExpr(expr.left, depth + 1)
        const right = this.evaluateExpr(expr.right, depth + 1)

        if (typeof left === 'bigint' || typeof right === 'bigint') {
          const l = BigInt(left)
          const r = BigInt(right)
          switch (expr.op) {
            case 'add': return l + r
            case 'sub': return l - r
            case 'mul': return l * r
            case 'div': {
              if (r === 0n) throw new Error('Division by zero in schema expression')
              return l / r
            }
            case 'mod': {
              if (r === 0n) throw new Error('Modulo by zero in schema expression')
              return l % r
            }
            case 'bit_and': return l & r
            case 'bit_or': return l | r
            case 'bit_xor': return l ^ r
            case 'shl': return l << r
            case 'shr': return l >> r
            case 'eq': return l === r
            case 'neq': return l !== r
            case 'lt': return l < r
            case 'lte': return l <= r
            case 'gt': return l > r
            case 'gte': return l >= r
          }
        }

        const l = Number(left)
        const r = Number(right)
        switch (expr.op) {
          case 'add': return l + r
          case 'sub': return l - r
          case 'mul': return l * r
          case 'div': {
            if (r === 0) throw new Error('Division by zero in schema expression')
            return Math.floor(l / r)
          }
          case 'mod': {
            if (r === 0) throw new Error('Modulo by zero in schema expression')
            return l % r
          }
          case 'bit_and': return (l & r) >>> 0
          case 'bit_or': return (l | r) >>> 0
          case 'bit_xor': return (l ^ r) >>> 0
          case 'shl': return (l << r) >>> 0
          case 'shr': return l >>> r
          case 'eq': return left === right
          case 'neq': return left !== right
          case 'lt': return l < r
          case 'lte': return l <= r
          case 'gt': return l > r
          case 'gte': return l >= r
        }
        break
      }

      case 'conditional': {
        const cond = this.evaluateExpr(expr.condition, depth + 1)
        return cond
          ? this.evaluateExpr(expr.consequent, depth + 1)
          : this.evaluateExpr(expr.alternate, depth + 1)
      }
    }

    throw new Error(`Unsupported expression type: ${(expr as any).type}`)
  }

  private resolveRef(path: string): any {
    return this.env.get(path)
  }

  public parse(): StructureParseResult {
    const fields: StructureField[] = []
    const seenIds = new Set<string>()

    let prevEnd = 0

    const view = new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset,
      this.bytes.byteLength,
    )

    const parseFieldRecursive = (
      def: CustomFieldV2,
      parentStart: number,
      parentEnd: number,
      depth: number,
      pathPrefix: string,
    ): StructureField | null => {
      if (depth > this.maxDepth) {
        throw new Error(`Schema struct recursion depth exceeded (${this.maxDepth})`)
      }
      this.consumeFuel(1)

      const fullId = pathPrefix ? `${pathPrefix}.${def.id}` : def.id
      if (seenIds.has(fullId)) {
        this.warnings.push(`Duplicate field ID: "${fullId}"`)
      }
      seenIds.add(fullId)

      // Check condition
      if (def.condition) {
        const cond = Boolean(this.evaluateExpr(def.condition, depth + 1))
        if (!cond) {
          return null
        }
      }

      // Determine offset
      let relOffset = 0
      if (typeof def.offset === 'number') {
        relOffset = def.offset
      } else if (def.offset) {
        relOffset = Number(this.evaluateExpr(def.offset, depth + 1))
      }

      let absOffset = 0
      const relMode = def.relativeTo ?? 'parent'
      if (relMode === 'parent') {
        absOffset = parentStart + relOffset
      } else if (relMode === 'previous') {
        absOffset = prevEnd + relOffset
      } else {
        absOffset = relOffset
      }

      const endian =
        ('endian' in def && def.endian) ? def.endian : this.schema.defaultEndian ?? 'big'
      const le = endian === 'little'

      // Check parent bound
      if (absOffset < parentStart || absOffset > parentEnd) {
        this.warnings.push(
          `Field "${fullId}" offset 0x${absOffset.toString(16)} escapes parent bounds [0x${parentStart.toString(16)}, 0x${parentEnd.toString(16)}].`,
        )
      }

      const makeField = (
        size: number,
        type: string,
        value: any,
        status: FieldStatus = 'valid',
        reason?: string,
        children?: StructureField[],
      ): StructureField => {
        const end = Math.min(absOffset + size, this.bytes.length)
        const hex = formatHex(this.bytes.slice(absOffset, end))

        // Check assertions
        if (def.assertions) {
          for (const assertion of def.assertions) {
            this.env.set('_val', value)
            const passed = Boolean(this.evaluateExpr(assertion.condition, depth + 1))
            if (!passed) {
              const msg = `Assertion failed for "${fullId}": ${assertion.message}`
              if (assertion.severity === 'error') {
                status = 'invalid'
                reason = reason ? `${reason}; ${msg}` : msg
              } else {
                this.warnings.push(msg)
              }
            }
          }
        }

        const res: StructureField = {
          id: fullId,
          label: def.label,
          range: { start: absOffset, end: absOffset + size },
          rawHex: hex,
          interpretedValue: value,
          type,
          endian,
          status,
          reason,
          specLink: def.specLink,
          children,
        }

        prevEnd = absOffset + size
        this.env.set(fullId, value)
        return res
      }

      // Check bounds against bytes length
      if (absOffset >= this.bytes.length) {
        return makeField(
          0,
          def.type,
          'Out of bounds',
          'truncated',
          `Offset 0x${absOffset.toString(16)} exceeds file length (${this.bytes.length} bytes)`,
        )
      }

      switch (def.type) {
        case 'u8': {
          if (absOffset + 1 > this.bytes.length) return makeField(1, 'u8', 0, 'truncated')
          const v = this.bytes[absOffset]!
          return makeField(1, 'u8', v)
        }
        case 'i8': {
          if (absOffset + 1 > this.bytes.length) return makeField(1, 'i8', 0, 'truncated')
          const v = view.getInt8(absOffset)
          return makeField(1, 'i8', v)
        }
        case 'u16': {
          if (absOffset + 2 > this.bytes.length) return makeField(2, 'u16', 0, 'truncated')
          const v = view.getUint16(absOffset, le)
          return makeField(2, 'u16', v)
        }
        case 'i16': {
          if (absOffset + 2 > this.bytes.length) return makeField(2, 'i16', 0, 'truncated')
          const v = view.getInt16(absOffset, le)
          return makeField(2, 'i16', v)
        }
        case 'u24': {
          if (absOffset + 3 > this.bytes.length) return makeField(3, 'u24', 0, 'truncated')
          const b0 = this.bytes[absOffset]!
          const b1 = this.bytes[absOffset + 1]!
          const b2 = this.bytes[absOffset + 2]!
          const v = le ? b0 | (b1 << 8) | (b2 << 16) : (b0 << 16) | (b1 << 8) | b2
          return makeField(3, 'u24', v)
        }
        case 'u32': {
          if (absOffset + 4 > this.bytes.length) return makeField(4, 'u32', 0, 'truncated')
          const v = view.getUint32(absOffset, le)
          return makeField(4, 'u32', v)
        }
        case 'i32': {
          if (absOffset + 4 > this.bytes.length) return makeField(4, 'i32', 0, 'truncated')
          const v = view.getInt32(absOffset, le)
          return makeField(4, 'i32', v)
        }
        case 'u64': {
          if (absOffset + 8 > this.bytes.length) return makeField(8, 'u64', 0n, 'truncated')
          const v = view.getBigUint64(absOffset, le)
          return makeField(8, 'u64', v)
        }
        case 'i64': {
          if (absOffset + 8 > this.bytes.length) return makeField(8, 'i64', 0n, 'truncated')
          const v = view.getBigInt64(absOffset, le)
          return makeField(8, 'i64', v)
        }
        case 'f32': {
          if (absOffset + 4 > this.bytes.length) return makeField(4, 'f32', 0, 'truncated')
          const v = view.getFloat32(absOffset, le)
          return makeField(4, 'f32', v)
        }
        case 'f64': {
          if (absOffset + 8 > this.bytes.length) return makeField(8, 'f64', 0, 'truncated')
          const v = view.getFloat64(absOffset, le)
          return makeField(8, 'f64', v)
        }
        case 'bytes':
        case 'ascii':
        case 'utf8': {
          const len =
            typeof def.length === 'number'
              ? def.length
              : Number(this.evaluateExpr(def.length, depth + 1))
          if (len < 0) {
            return makeField(0, def.type, '', 'invalid', `Negative length: ${len}`)
          }
          if (absOffset + len > this.bytes.length) {
            return makeField(len, def.type, '', 'truncated', 'Truncated by end of document')
          }
          const slice = this.bytes.subarray(absOffset, absOffset + len)
          let val: any = formatHex(slice)
          if (def.type === 'ascii' || def.type === 'utf8') {
            try {
              val = new TextDecoder(def.type === 'ascii' ? 'ascii' : 'utf-8', {
                fatal: false,
              }).decode(slice)
            } catch {
              val = formatHex(slice)
            }
          }
          return makeField(len, def.type, val)
        }
        case 'bitfield': {
          const containerSize =
            def.containerType === 'u8'
              ? 1
              : def.containerType === 'u16'
              ? 2
              : def.containerType === 'u32'
              ? 4
              : 8
          if (absOffset + containerSize > this.bytes.length) {
            return makeField(containerSize, 'bitfield', 0, 'truncated')
          }
          let rawVal: bigint
          if (containerSize === 1) rawVal = BigInt(this.bytes[absOffset]!)
          else if (containerSize === 2) rawVal = BigInt(view.getUint16(absOffset, le))
          else if (containerSize === 4) rawVal = BigInt(view.getUint32(absOffset, le))
          else rawVal = view.getBigUint64(absOffset, le)

          const mask = (1n << BigInt(def.width)) - 1n
          const extracted = (rawVal >> BigInt(def.lsb)) & mask
          return makeField(containerSize, 'bitfield', Number(extracted))
        }
        case 'struct': {
          const childFields: StructureField[] = []
          const structBound =
            def.boundedSize !== undefined
              ? typeof def.boundedSize === 'number'
                ? def.boundedSize
                : Number(this.evaluateExpr(def.boundedSize, depth + 1))
              : parentEnd - absOffset

          const structEnd = Math.min(absOffset + structBound, this.bytes.length)
          let localPrevEnd = absOffset

          for (const childDef of def.fields) {
            const child = parseFieldRecursive(
              childDef,
              absOffset,
              structEnd,
              depth + 1,
              fullId,
            )
            if (child) {
              childFields.push(child)
              localPrevEnd = Math.max(localPrevEnd, child.range.end)
            }
          }

          const actualSize =
            def.boundedSize !== undefined ? structBound : localPrevEnd - absOffset
          return makeField(actualSize, 'struct', `{${childFields.length} fields}`, 'valid', undefined, childFields)
        }
        case 'array': {
          const count =
            typeof def.count === 'number'
              ? def.count
              : Number(this.evaluateExpr(def.count, depth + 1))
          if (count < 0) {
            return makeField(0, 'array', '[]', 'invalid', `Negative array count: ${count}`)
          }
          if (count > 10_000) {
            return makeField(0, 'array', '[]', 'invalid', `Array count ${count} exceeds safety limit (10000)`)
          }

          const items: StructureField[] = []
          let curOffset = absOffset
          for (let i = 0; i < count; i++) {
            this.consumeFuel(1)
            const itemField = parseFieldRecursive(
              {
                ...def.itemType,
                id: `${i}`,
                label: `[${i}]`,
                offset: curOffset - absOffset,
                relativeTo: 'parent',
              },
              absOffset,
              parentEnd,
              depth + 1,
              fullId,
            )
            if (itemField) {
              items.push(itemField)
              curOffset = itemField.range.end
            }
          }

          return makeField(curOffset - absOffset, 'array', `[${items.length} items]`, 'valid', undefined, items)
        }
        case 'union': {
          const tagVal = this.evaluateExpr(def.tagExpr, depth + 1)
          const matchedCase = def.cases.find((c) => c.tagValue === tagVal)
          const selected = matchedCase ? matchedCase.field : def.defaultCase
          if (!selected) {
            return makeField(
              0,
              'union',
              `Unhandled union tag: ${tagVal}`,
              'invalid',
              `No matching union case for tag value ${tagVal}`,
            )
          }

          const innerField = parseFieldRecursive(
            selected,
            absOffset,
            parentEnd,
            depth + 1,
            fullId,
          )
          if (!innerField) {
            return makeField(0, 'union', 'null', 'valid')
          }
          return makeField(
            innerField.range.end - absOffset,
            'union',
            innerField.interpretedValue,
            innerField.status,
            innerField.reason,
            [innerField],
          )
        }
      }
    }

    for (const def of this.schema.fields) {
      const f = parseFieldRecursive(def, 0, this.bytes.length, 0, '')
      if (f) {
        fields.push(f)
      }
    }

    return {
      format: `custom-v2:${this.schema.name}`,
      confidence: 1.0,
      fields,
      warnings: this.warnings,
      diagnostics: [],
    }
  }
}

export function parseCustomStructureV2(
  bytes: Uint8Array,
  schema: CustomStructureSchemaV2,
): StructureParseResult {
  const interp = new SchemaV2Interpreter(bytes, schema)
  return interp.parse()
}
