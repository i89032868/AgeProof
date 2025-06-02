(define-constant ERR-UNAUTHORIZED (err u1000))
(define-constant ERR-ALREADY-REGISTERED (err u1001))
(define-constant ERR-NOT-REGISTERED (err u1002))
(define-constant ERR-INVALID-AGE (err u1003))
(define-constant ERR-INVALID-PROOF (err u1004))
(define-constant ERR-EXPIRED-PROOF (err u1005))

(define-data-var admin principal tx-sender)
(define-data-var verifier-count uint u0)

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