# bitpeek

A local-first binary workbench for inspecting and editing raw bytes in the browser.

[Live demo](https://bitpeek-seven.vercel.app)

## Features

- Parse hex, binary, decimal, UTF-8 text, and Base64
- Open, edit, and save local binary files without uploads
- Compare two buffers by offset, navigate changes, and export reproducible patches
- Find exact or wildcard byte patterns and jump directly to offsets
- Inspect signed integers, floats, text, CRCs, cryptographic hashes, entropy, and file signatures
- Extract printable ASCII and UTF-16 strings with their byte offsets
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

## Support

If bitpeek saves you time, you can [support its development](https://bitpeek-seven.vercel.app/#support) with ETH on Ethereum Mainnet.

`0xb9030ab08Fb47b310aBe3D4Be7680807C10deba5`

Always verify the network and full address in your wallet before confirming.

## License

[MIT](LICENSE)
