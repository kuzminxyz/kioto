# Threshold encryption with `shinobi`

`shinobi` provides an algorithm for _threshold_ en-/decryption scheme. This can be useful for POA blockchain network for implementing, for example, anti MEV transactions.

Provided threshold encryption scheme works on every curve support pairing operation:

```latex
E: G_1 × G_2 → G_T
```

## Definitions:
- `g1` - generator of `G1` group
- `g2` - generator of `G2` group
- `r` - random scalar
- `U` (or `u` in codebase) - equals to `r * g2`
- `M` - encryptable message (represents as raw bytes).
- `W` - encryptable message hash, for example `W = keccak256(M)`.
- `K` - symmetric key encryptable key
- `P` - participants aggregated public key, equals to `P = s * g2`
- `D_i` - decryption share, decryption share equals to `D_i = L_i * U`, where `L_i` is a _Lagrange coefficient_ at `0`:

```latex
L_i = y_i * ∏_{j ∈ S, j ≠ i}{(x_j) / (x_j - x_i)}
```

  where `S` is the set of decryption shares contributing to reconstruction, with at least `threshold` elements (`|S| >= threshold`).

## Algorithm

User:
1. Chose random scalar `r` and provide its encrypted version `U`.
2. User maps message hash to curve G1 point:

```latex
H = HashToG1(W)
```

3. User calculates:

```latex
K = e(H, P * r) = e(H, s * g_2 * r) = e(H, g_2)^{s * r}
```

4. User encrypts message `E = M ⊕ K` and provides three parameters: `{E, W, U}`.

Participants (required to have at least `threshold` decryption shares):
1. Combine `threshold` shares:

```latex
C = ∑{D_i} = ∑{L_i * U} = ∑{L_i * r * g_2} = r * g_2 * ∑{L_i} = r * g_2 * s
```

2. Recompute message hash point from the published `W`:

```latex
H = HashToG1(W)
```

3. Computes symmetric key:

```latex
K = e(H, C) = e(H, r * s * g_2) = e(H, g_2)^{s * r}
```

4. Decrypt message:

```latex
M = E ⊕ K = M ⊕ K ⊕ K = M
```

5. Verify statement `hash(M) == W`.
