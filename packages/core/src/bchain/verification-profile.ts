/** The Phase 3 reference specification and the published Bitcoin BIPs differ.
 * Callers must opt in to published rules; specification behavior remains the default.
 */
export type BitcoinVerificationProfile = 'specification' | 'published-bip'

export function resolveBitcoinVerificationProfile(profile?: BitcoinVerificationProfile): BitcoinVerificationProfile {
  if (profile !== undefined && profile !== 'specification' && profile !== 'published-bip') {
    throw new RangeError('profile must be specification or published-bip')
  }
  return profile ?? 'specification'
}
