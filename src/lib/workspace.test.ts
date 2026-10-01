import { describe, expect, it } from 'vitest'
import { decodeProject, encodeProject, type SavedWorkspace } from './workspace'

describe('project container', () => {
  it('round trips multiple binary files and annotations without text encoding loss', async () => {
    const original: SavedWorkspace = {
      version: 1,
      activeId: 'b',
      documents: [
        {
          id: 'a',
          name: 'first.bin',
          blob: new Blob([Uint8Array.of(0, 255, 128)]),
          reference: new Blob(['reference']),
          referenceName: 'original.bin',
          format: 'png',
          notes: [
            {
              id: 'n',
              title: 'Header',
              body: 'Checked',
              start: 1,
              end: 2,
              createdAt: '2026-10-01',
            },
          ],
          dirty: true,
          selection: { anchor: 2, focus: 1 },
        },
        {
          id: 'b',
          name: 'empty.bin',
          blob: new Blob([]),
          notes: [],
          dirty: false,
          selection: null,
        },
      ],
    }
    const restored = await decodeProject(encodeProject(original))
    expect(restored.activeId).toBe('b')
    expect(new Uint8Array(await restored.documents[0]!.blob.arrayBuffer())).toEqual(
      Uint8Array.of(0, 255, 128),
    )
    expect(restored.documents[0]!.notes).toEqual(original.documents[0]!.notes)
    expect(await restored.documents[0]!.reference?.text()).toBe('reference')
    expect(restored.documents[0]!.format).toBe('png')
    expect(restored.documents[1]!.blob.size).toBe(0)
  })
  it('rejects truncation and trailing data before restoring any file', async () => {
    const project = encodeProject({
      version: 1,
      activeId: 'a',
      documents: [
        { id: 'a', name: 'a', blob: new Blob(['ABC']), dirty: false, notes: [], selection: null },
      ],
    })
    await expect(decodeProject(project.slice(0, project.size - 1))).rejects.toThrow(
      'Invalid project document',
    )
    await expect(decodeProject(new Blob([project, 'extra']))).rejects.toThrow('trailing')
    await expect(decodeProject(new Blob(['bad']))).rejects.toThrow('Not a Bitpeek')
  })
  it('rejects annotations outside their document', async () => {
    const project = encodeProject({
      version: 1,
      activeId: 'a',
      documents: [
        {
          id: 'a',
          name: 'a',
          blob: new Blob(['ABC']),
          dirty: false,
          selection: null,
          notes: [{ id: 'n', title: 'Bad', body: '', createdAt: '', start: 1, end: 9 }],
        },
      ],
    })
    await expect(decodeProject(project)).rejects.toThrow('annotation range')
  })
  it('refuses to export metadata larger than the importer can restore', () => {
    expect(() =>
      encodeProject({
        version: 1,
        activeId: 'a',
        documents: [
          {
            id: 'a',
            name: 'a',
            blob: new Blob(['A']),
            dirty: false,
            selection: null,
            notes: Array.from({ length: 220 }, (_, i) => ({
              id: String(i),
              title: 'Note',
              body: 'x'.repeat(20000),
              createdAt: '',
              start: 0,
              end: 0,
            })),
          },
        ],
      }),
    ).toThrow('exceed 4 MiB')
  })
})
