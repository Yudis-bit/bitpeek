# bitpeek

A local-first binary workbench for inspecting and editing raw bytes in the browser.

[Live demo](https://bitpeek-seven.vercel.app)

## Features

- Parse hex, binary, decimal, UTF-8 text, and Base64
- Open, edit, and save local binary files without uploads
- Find exact or wildcard byte patterns and jump directly to offsets
- Inspect signed integers, endianness, floats, text, checksums, entropy, and file signatures
- Edit bytes and bits directly with selection transforms and undo/redo
- Navigate large inputs through a virtualized hex and ASCII view

## Screenshot

![bitpeek byte inspector](docs/bitpeek-desktop.png)

## Local development

```sh
npm install
npm run dev
```

## Quality

```sh
npm test
npm run lint
npm run build
```

bitpeek is entirely client-side. No data leaves the browser.

## License

[MIT](LICENSE)
