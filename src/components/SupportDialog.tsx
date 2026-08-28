import { useEffect, useRef } from 'react'
import {
  ETHEREUM_ADDRESS,
  ETHEREUM_CHAIN_ID,
  ETHEREUM_NETWORK,
  ETHEREUM_PAYMENT_URI,
  ETHERSCAN_ADDRESS_URL,
} from '../lib/support'

interface SupportDialogProps {
  open: boolean
  onClose: () => void
  onCopyAddress: () => void
}

export function SupportDialog({
  open,
  onClose,
  onCopyAddress,
}: SupportDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])

  return (
    <dialog
      ref={dialogRef}
      className="support-dialog"
      aria-labelledby="support-heading"
      onClose={onClose}
      onCancel={onClose}
    >
      <div className="dialog-heading">
        <div>
          <h2 id="support-heading">Support bitpeek</h2>
          <p>Optional funding for maintenance and new binary tooling</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close support dialog">
          Close
        </button>
      </div>

      <div className="support-content">
        <p>
          bitpeek is free, open source, and runs locally. If it saves you time,
          you can support continued development with ETH.
        </p>

        <dl className="support-details">
          <div>
            <dt>Network</dt>
            <dd>
              {ETHEREUM_NETWORK} <span>· chain ID {ETHEREUM_CHAIN_ID}</span>
            </dd>
          </div>
          <div>
            <dt>Address</dt>
            <dd>
              <code>{ETHEREUM_ADDRESS}</code>
            </dd>
          </div>
        </dl>

        <div className="support-actions">
          <button type="button" className="support-primary" onClick={onCopyAddress}>
            Copy address
          </button>
          <a href={ETHEREUM_PAYMENT_URI}>Open wallet</a>
          <a href={ETHERSCAN_ADDRESS_URL} target="_blank" rel="noreferrer">
            Verify on Etherscan
          </a>
        </div>

        <p className="support-warning">
          Verify the network and full address in your wallet before confirming.
          Blockchain transactions cannot be reversed. bitpeek never connects to
          your wallet or creates a transaction.
        </p>
      </div>
    </dialog>
  )
}
