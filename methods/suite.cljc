(ns post-quantum-compat.methods.suite
  "post_quantum-compat — pqh-v1 suite + migration-state SSoT (1:1 Clojure port of
  methods/suite.py, ADR-2606111300). The machine-readable registry of WHERE the
  substrate stands against the quantum/HNDL threat: which crypto layer runs which
  primitive, whether Shor or only Grover applies, what it migrated to, what stays
  gated. The paper's §7 table, as data — so coverage is asserted by tests.

  Pure stdlib. Non-eschatological framing (Charter §1.15): dated, measurable risk
  management (Mosca inequality), not prophecy. Maps use string keys/values (the
  data IS \":ns/name\" keyword-strings, mirroring the Python dicts)."
  (:require [clojure.string :as str]))

;; ── suite registry (FIPS 203/204 + RFC 9106 constants) ──────────────────────
(def SUITES
  {":suite/pqh-v1"
   (array-map
    ":suite/id" "pqh-v1"
    ":suite/adr" "ADR-2606111300"
    ":suite/kem" (array-map
                  ":kem/classical" "X25519"
                  ":kem/pq" "ML-KEM-768"
                  ":kem/pq-fips" "FIPS 203"
                  ":kem/combiner" "HKDF-SHA256 transcript-bound (X-Wing pattern)"
                  ":kem/pq-public-bytes" 1184
                  ":kem/pq-ciphertext-bytes" 1088
                  ":kem/shared-secret-bytes" 32
                  ":kem/pq-multicodec" 0x120C)
    ":suite/sig" (array-map
                  ":sig/classical" "Ed25519"
                  ":sig/pq" "ML-DSA-65"
                  ":sig/pq-fips" "FIPS 204"
                  ":sig/composition" "dual signature, verifier requires both (AND)"
                  ":sig/pq-public-bytes" 1952
                  ":sig/pq-signature-bytes" 3309
                  ":sig/pq-multicodec" 0x1211)
    ":suite/kdf" (array-map
                  ":kdf/id" "argon2id-v1"
                  ":kdf/rfc" "RFC 9106"
                  ":kdf/default-m-kib" 19456
                  ":kdf/default-t" 2
                  ":kdf/default-p" 1))})

;; ── layer migration registry (the paper's §7 table as data) ─────────────────
(def LAYERS
  [(array-map ":layer/id" ":layer/record-at-rest" ":layer/primitive" "XChaCha20-Poly1305-256"
              ":layer/quantum-attack" ":grover" ":layer/status" ":adequate" ":layer/adr" "ADR-2605181100")
   (array-map ":layer/id" ":layer/vault-at-rest" ":layer/primitive" "AES-256-GCM"
              ":layer/quantum-attack" ":grover" ":layer/status" ":adequate" ":layer/adr" "ADR-2605181100")
   (array-map ":layer/id" ":layer/hashes" ":layer/primitive" "SHA-256/Keccak-256/BLAKE2b"
              ":layer/quantum-attack" ":grover" ":layer/status" ":adequate" ":layer/adr" "ADR-2606111300")
   (array-map ":layer/id" ":layer/key-wrap" ":layer/primitive" "X25519"
              ":layer/quantum-attack" ":shor" ":layer/status" ":migrated"
              ":layer/suite" "pqh-v1" ":layer/adr" "ADR-2606111300" ":layer/pr" [1616 1621])
   (array-map ":layer/id" ":layer/did-signal-binding" ":layer/primitive" "Ed25519"
              ":layer/quantum-attack" ":shor" ":layer/status" ":migrated"
              ":layer/suite" "pqh-v1" ":layer/adr" "ADR-2606111300" ":layer/pr" [1616])
   (array-map ":layer/id" ":layer/did-doc-attestation" ":layer/primitive" "Ed25519"
              ":layer/quantum-attack" ":shor" ":layer/status" ":migrated"
              ":layer/suite" "pqh-v1" ":layer/adr" "ADR-2606111300" ":layer/pr" [1630]
              ":layer/note" "requirePq/expectedPqDidKey enforcement flip = operator step")
   (array-map ":layer/id" ":layer/password-kdf" ":layer/primitive" "PBKDF2-SHA256"
              ":layer/quantum-attack" ":grover" ":layer/status" ":migrated"
              ":layer/suite" "argon2id-v1" ":layer/adr" "ADR-2606111300" ":layer/pr" [1625]
              ":layer/note" "T3 implementation-layer hardening, not a quantum fix")
   (array-map ":layer/id" ":layer/production-pq-keys" ":layer/primitive" "ML-DSA-65 did:key"
              ":layer/quantum-attack" ":shor" ":layer/status" ":operator-pending"
              ":layer/suite" "pqh-v1" ":layer/adr" "ADR-2606111300"
              ":layer/note" "sign-diddoc.mjs --pq exists; key generation/publication is operator-held (no-server-key)")
   (array-map ":layer/id" ":layer/governance-signature" ":layer/primitive" "secp256k1-ECDSA"
              ":layer/quantum-attack" ":shor" ":layer/status" ":chain-blocked" ":layer/adr" "ADR-2606111300"
              ":layer/note" "Base L2 / ERC-4337 constraint; mitigation = key rotation + spend-before-z")
   (array-map ":layer/id" ":layer/libsignal-path" ":layer/primitive" "X25519-X3DH"
              ":layer/quantum-attack" ":shor" ":layer/status" ":upstream-pending"
              ":layer/note" "upstream PQXDH adoption via optional-dependency bump")
   (array-map ":layer/id" ":layer/passkey-signature" ":layer/primitive" "P-256-ES256"
              ":layer/quantum-attack" ":shor" ":layer/status" ":deferred"
              ":layer/note" "surface not live (future R2 federated training); WebAuthn PQ tracked")])

(def MIGRATION-DONE #{":migrated" ":adequate"})
(def GATED #{":operator-pending" ":chain-blocked" ":upstream-pending" ":deferred"})

;; ── math helpers (testable, from the survivability paper) ───────────────────
(defn grover-effective-bits
  "BBBV quadratic bound: brute force of an n-bit key costs 2^(n/2)."
  [key-bits]
  (quot key-bits 2))

(defn mosca
  "Mosca inequality: act now iff x + y > z. Returns the slack either way."
  [x-shelf-life-years y-migration-years z-crqc-years]
  (let [slack (- z-crqc-years (+ x-shelf-life-years y-migration-years))]
    {":mosca/act-now" (< slack 0) ":mosca/slack-years" slack}))

(defn shor-applies [layer]
  (= (get layer ":layer/quantum-attack") ":shor"))

(defn- round4 [x]
  (/ (Math/round (* 10000.0 (double x))) 10000.0))

;; ── coverage readout (DERIVED — computed on read, never stored) ─────────────
(defn coverage-report []
  (let [shor (filter shor-applies LAYERS)
        migrated (filter #(= (get % ":layer/status") ":migrated") shor)
        gated (filter #(contains? GATED (get % ":layer/status")) shor)
        done-or-gated (into MIGRATION-DONE GATED)
        unknown (filter #(not (contains? done-or-gated (get % ":layer/status"))) LAYERS)]
    (array-map
     ":coverage/layers-total" (count LAYERS)
     ":coverage/shor-vulnerable" (count shor)
     ":coverage/migrated" (count migrated)
     ":coverage/gated" (count gated)
     ":coverage/unknown" (count unknown)
     ":coverage/migrated-fraction" (round4 (/ (double (count migrated)) (count shor)))
     ":coverage/gated-ids" (vec (sort (map #(get % ":layer/id") gated))))))
