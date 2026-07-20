# Threshold encryption with `yonago`

`yonago` provides an algorithm for _threshold_ en-/decryption scheme. This can be useful for POA blockchain network for implementing, for example, anti MEV transactions.

Provided threshold encryption scheme works on every curve support pairing operation: $E: G1 * G2 \rightarrow GT$.

## Definitions:
- $g1$ - generator of `G1` group
- $g2$ - generator of `G2` group
- $r$ - random scalar
- $U$ (or $u$ in codebase) - equals to $r * g2$
- $M$ - encryptable message (represents as raw bytes).
- $W$ - encryptable message hash, for example $W = keccak256(M)$.
- $K$ - symmetric key encryptable key
- $P$ - participants aggregated public key, equals to $P = s * g2$
- $D_i$ - decryption share, decryption share equals to $D_i = L_i * U$, where $L_i$ is a _Lagrange coefficient_ at `0`: $L_i = y_i * \prod_{j \in S, j != i}{\frac{x_j}{x_j - x_i}}$, where $S$ is the set of decryption shares contributing to reconstruction, with at least `threshold` elements ($|S| \geq threshold$)

## Algorithm

User: 
1. Chose random scalar `r` and provide its encrypted version `U`.
2. User maps message hash to curve G1 point: $H = HashToG1(W)$
3. User calculates $K = e(H, P * r) = e(H, s * g2 * r) = e(H, g2)^{s * r}$
4. User encrypts message $E = M \oplus K$ and provides three parameters: `{E, W, U}`

Participants (required to have at least `threshold` decryption shares):
1. Combine `threshold` shares $C = \sum{D_i} = \sum{L_i * U} = \sum{L_i * r * g2} = r * g2 * \sum{L_i} = r * g2 * s$
2. Recompute message hash point from the published $W$: $H = HashToG1(W)$
3. Computes symmetric key $K = e(H, C) = e(H, r * s * g2) = e(H, g2)^{s * r}$
4. Decrypt message: $M = E \oplus K = M \oplus K \oplus K = M$
5. Verify statement $hash(M) == W$