(define-constant ERR-UNAUTHORIZED (err u1000))
(define-constant ERR-ALREADY-REGISTERED (err u1001))
(define-constant ERR-NOT-REGISTERED (err u1002))
(define-constant ERR-INVALID-AGE (err u1003))
(define-constant ERR-INVALID-PROOF (err u1004))
(define-constant ERR-EXPIRED-PROOF (err u1005))
(define-constant ERR-INVALID-BRACKET (err u1006))
(define-constant ERR-INSUFFICIENT-REPUTATION (err u1007))
(define-constant ERR-ALREADY-ATTESTED (err u1008))
(define-constant ERR-ATTESTATION-NOT-FOUND (err u1009))
(define-constant ERR-INVALID-SCORE (err u1010))

(define-data-var admin principal tx-sender)
(define-data-var verifier-count uint u0)
(define-data-var attestation-count uint u0)
(define-data-var privacy-verification-count uint u0)

(define-map Verifiers 
  principal 
  {active: bool}
)

(define-map AgeProofs
  principal
  {
    birth-year: uint,
    proof-hash: (buff 32),
    last-verified: uint,
    verifier: principal
  }
)

(define-map VerificationRequests
  {requester: principal, subject: principal}
  {
    min-age: uint,
    request-time: uint,
    status: (string-ascii 20)
  }
)

(define-map PrivacyProofs
  principal
  {
    age-bracket: uint,
    proof-commitment: (buff 32),
    reputation-score: uint,
    last-updated: uint,
    verified-count: uint
  }
)

(define-map ReputationAttestations
  {attester: principal, subject: principal}
  {
    score: uint,
    attestation-time: uint,
    proof-hash: (buff 32)
  }
)

(define-map AgeBracketVerifications
  {verifier: principal, subject: principal, bracket: uint}
  {
    verified: bool,
    verification-time: uint,
    challenge-hash: (buff 32),
    response-hash: (buff 32)
  }
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-UNAUTHORIZED)
    (ok (var-set admin new-admin))))

(define-public (register-verifier (verifier-principal principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-UNAUTHORIZED)
    (asserts! (is-none (map-get? Verifiers verifier-principal)) ERR-ALREADY-REGISTERED)
    (map-set Verifiers verifier-principal {active: true})
    (var-set verifier-count (+ (var-get verifier-count) u1))
    (ok true)))

(define-public (deactivate-verifier (verifier-principal principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-UNAUTHORIZED)
    (asserts! (is-some (map-get? Verifiers verifier-principal)) ERR-NOT-REGISTERED)
    (map-set Verifiers verifier-principal {active: false})
    (ok true)))

(define-public (submit-age-proof 
    (subject principal) 
    (birth-year uint)
    (proof-hash (buff 32)))
  (begin
    (asserts! (is-some (map-get? Verifiers tx-sender)) ERR-UNAUTHORIZED)
    (asserts! (>= birth-year u1900) ERR-INVALID-AGE)
    (asserts! (<= birth-year (- stacks-block-height u0)) ERR-INVALID-AGE)
    (map-set AgeProofs subject
      {
        birth-year: birth-year,
        proof-hash: proof-hash,
        last-verified: stacks-block-height,
        verifier: tx-sender
      })
    (ok true)))

(define-public (request-age-verification 
    (subject principal)
    (min-age uint))
  (begin
    (asserts! (> min-age u0) ERR-INVALID-AGE)
    (map-set VerificationRequests 
      {requester: tx-sender, subject: subject}
      {
        min-age: min-age,
        request-time: stacks-block-height,
        status: "PENDING"
      })
    (ok true)))

(define-public (verify-age 
    (requester principal)
    (subject principal))
  (let (
    (proof (unwrap! (map-get? AgeProofs subject) ERR-NOT-REGISTERED))
    (request (unwrap! (map-get? VerificationRequests {requester: requester, subject: subject}) ERR-NOT-REGISTERED))
    (current-year (/ stacks-block-height u144))
    (age (- current-year (get birth-year proof))))
    (begin
      (asserts! (>= age (get min-age request)) ERR-INVALID-PROOF)
      (asserts! (<= (- stacks-block-height (get last-verified proof)) u52560) ERR-EXPIRED-PROOF)
      (map-set VerificationRequests 
        {requester: requester, subject: subject}
        {
          min-age: (get min-age request),
          request-time: (get request-time request),
          status: "VERIFIED"
        })
      (ok true))))

(define-read-only (get-verification-status 
    (requester principal)
    (subject principal))
  (map-get? VerificationRequests 
    {requester: requester, subject: subject}))

(define-read-only (is-active-verifier (verifier principal))
  (match (map-get? Verifiers verifier)
    proof (get active proof)
    false))

(define-read-only (get-verifier-count)
  (var-get verifier-count))

(define-public (submit-privacy-proof 
    (age-bracket uint)
    (proof-commitment (buff 32)))
  (let (
    (current-proof (map-get? PrivacyProofs tx-sender))
    (new-reputation-score (match current-proof
      proof (get reputation-score proof)
      u50)))
    (begin
      (asserts! (and (>= age-bracket u1) (<= age-bracket u8)) ERR-INVALID-BRACKET)
      (map-set PrivacyProofs tx-sender
        {
          age-bracket: age-bracket,
          proof-commitment: proof-commitment,
          reputation-score: new-reputation-score,
          last-updated: stacks-block-height,
          verified-count: u0
        })
      (var-set privacy-verification-count (+ (var-get privacy-verification-count) u1))
      (ok true))))

(define-public (attest-reputation 
    (subject principal)
    (score uint)
    (proof-hash (buff 32)))
  (let (
    (existing-attestation (map-get? ReputationAttestations {attester: tx-sender, subject: subject}))
    (subject-proof (map-get? PrivacyProofs subject)))
    (begin
      (asserts! (and (>= score u1) (<= score u100)) ERR-INVALID-SCORE)
      (asserts! (is-none existing-attestation) ERR-ALREADY-ATTESTED)
      (asserts! (is-some subject-proof) ERR-NOT-REGISTERED)
      (map-set ReputationAttestations 
        {attester: tx-sender, subject: subject}
        {
          score: score,
          attestation-time: stacks-block-height,
          proof-hash: proof-hash
        })
      (var-set attestation-count (+ (var-get attestation-count) u1))
      (ok true))))

(define-public (update-reputation-score (subject principal))
  (let (
    (subject-proof (unwrap! (map-get? PrivacyProofs subject) ERR-NOT-REGISTERED))
    (attestation-1 (map-get? ReputationAttestations {attester: (var-get admin), subject: subject}))
    (attestation-score-1 (match attestation-1 att (get score att) u0))
    (reputation-boost (if (> attestation-score-1 u0) u20 u0))
    (base-score (get reputation-score subject-proof))
    (verification-bonus (* (get verified-count subject-proof) u5))
    (new-score (+ base-score reputation-boost verification-bonus)))
    (begin
      (map-set PrivacyProofs subject
        {
          age-bracket: (get age-bracket subject-proof),
          proof-commitment: (get proof-commitment subject-proof),
          reputation-score: (if (<= new-score u100) new-score u100),
          last-updated: (get last-updated subject-proof),
          verified-count: (get verified-count subject-proof)
        })
      (ok true))))

(define-public (verify-age-bracket 
    (subject principal)
    (target-bracket uint)
    (challenge-hash (buff 32))
    (response-hash (buff 32)))
  (let (
    (subject-proof (unwrap! (map-get? PrivacyProofs subject) ERR-NOT-REGISTERED))
    (verifier-status (unwrap! (map-get? Verifiers tx-sender) ERR-UNAUTHORIZED))
    (subject-bracket (get age-bracket subject-proof))
    (subject-reputation (get reputation-score subject-proof)))
    (begin
      (asserts! (get active verifier-status) ERR-UNAUTHORIZED)
      (asserts! (and (>= target-bracket u1) (<= target-bracket u8)) ERR-INVALID-BRACKET)
      (asserts! (>= subject-reputation u30) ERR-INSUFFICIENT-REPUTATION)
      (asserts! (>= subject-bracket target-bracket) ERR-INVALID-PROOF)
      (map-set AgeBracketVerifications 
        {verifier: tx-sender, subject: subject, bracket: target-bracket}
        {
          verified: true,
          verification-time: stacks-block-height,
          challenge-hash: challenge-hash,
          response-hash: response-hash
        })
      (map-set PrivacyProofs subject
        {
          age-bracket: subject-bracket,
          proof-commitment: (get proof-commitment subject-proof),
          reputation-score: subject-reputation,
          last-updated: (get last-updated subject-proof),
          verified-count: (+ (get verified-count subject-proof) u1)
        })
      (ok true))))

(define-public (request-privacy-verification 
    (subject principal)
    (required-bracket uint))
  (let (
    (subject-proof (map-get? PrivacyProofs subject))
    (verification-record (map-get? AgeBracketVerifications 
      {verifier: tx-sender, subject: subject, bracket: required-bracket})))
    (begin
      (asserts! (and (>= required-bracket u1) (<= required-bracket u8)) ERR-INVALID-BRACKET)
      (asserts! (is-some subject-proof) ERR-NOT-REGISTERED)
      (match verification-record
        record (ok (get verified record))
        (ok false)))))

(define-public (challenge-age-proof 
    (subject principal)
    (challenge-nonce uint)
    (expected-response (buff 32)))
  (let (
    (subject-proof (unwrap! (map-get? PrivacyProofs subject) ERR-NOT-REGISTERED))
    (proof-commitment (get proof-commitment subject-proof))
    (combined-hash (keccak256 (concat proof-commitment (unwrap-panic (to-consensus-buff? challenge-nonce)))))
    (is-valid (is-eq combined-hash expected-response)))
    (begin
      (asserts! (is-some (map-get? Verifiers tx-sender)) ERR-UNAUTHORIZED)
      (if is-valid
        (begin
          (map-set PrivacyProofs subject
            {
              age-bracket: (get age-bracket subject-proof),
              proof-commitment: proof-commitment,
              reputation-score: (+ (get reputation-score subject-proof) u10),
              last-updated: stacks-block-height,
              verified-count: (get verified-count subject-proof)
            })
          (ok true))
        (ok false)))))

(define-read-only (get-privacy-proof (subject principal))
  (map-get? PrivacyProofs subject))

(define-read-only (get-reputation-attestation 
    (attester principal)
    (subject principal))
  (map-get? ReputationAttestations {attester: attester, subject: subject}))

(define-read-only (get-bracket-verification 
    (verifier principal)
    (subject principal)
    (bracket uint))
  (map-get? AgeBracketVerifications 
    {verifier: verifier, subject: subject, bracket: bracket}))

(define-read-only (calculate-age-bracket (birth-year uint))
  (let (
    (current-year (/ stacks-block-height u144))
    (age (- current-year birth-year)))
    (if (<= age u17) u1
      (if (<= age u24) u2
        (if (<= age u34) u3
          (if (<= age u44) u4
            (if (<= age u54) u5
              (if (<= age u64) u6
                (if (<= age u74) u7 u8)))))))))

(define-read-only (get-privacy-stats)
  {
    total-privacy-proofs: (var-get privacy-verification-count),
    total-attestations: (var-get attestation-count)
  })

(define-read-only (verify-bracket-eligibility 
    (subject principal)
    (target-bracket uint))
  (match (map-get? PrivacyProofs subject)
    proof (and 
      (>= (get age-bracket proof) target-bracket)
      (>= (get reputation-score proof) u30)
      (<= (- stacks-block-height (get last-updated proof)) u52560))
    false))