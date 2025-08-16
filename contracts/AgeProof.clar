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
(define-constant ERR-TIME-LOCK-ACTIVE (err u1011))
(define-constant ERR-SCHEDULE-NOT-FOUND (err u1012))
(define-constant ERR-INVALID-TIME (err u1013))
(define-constant ERR-ALREADY-EXECUTED (err u1014))
(define-constant ERR-CONDITIONS-NOT-MET (err u1015))

(define-data-var admin principal tx-sender)
(define-data-var verifier-count uint u0)
(define-data-var attestation-count uint u0)
(define-data-var privacy-verification-count uint u0)
(define-data-var schedule-count uint u0)
(define-data-var timelock-count uint u0)

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

(define-map ScheduledVerifications
  {scheduler: principal, schedule-id: uint}
  {
    subject: principal,
    verification-type: (string-ascii 20),
    target-block: uint,
    min-age-requirement: uint,
    conditions: (string-ascii 50),
    executed: bool,
    created-at: uint
  }
)

(define-map TimeLocks
  {owner: principal, lock-id: uint}
  {
    subject: principal,
    unlock-block: uint,
    lock-type: (string-ascii 20),
    proof-data: (buff 32),
    conditions-met: bool,
    created-at: uint
  }
)

(define-map ConditionalVerifications
  {verifier: principal, condition-id: uint}
  {
    subject: principal,
    age-threshold: uint,
    time-window-start: uint,
    time-window-end: uint,
    verification-hash: (buff 32),
    auto-execute: bool,
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

(define-public (schedule-future-verification 
    (subject principal)
    (verification-type (string-ascii 20))
    (target-block uint)
    (min-age-requirement uint)
    (conditions (string-ascii 50)))
  (let (
    (new-schedule-id (+ (var-get schedule-count) u1)))
    (begin
      (asserts! (> target-block stacks-block-height) ERR-INVALID-TIME)
      (asserts! (> min-age-requirement u0) ERR-INVALID-AGE)
      (map-set ScheduledVerifications 
        {scheduler: tx-sender, schedule-id: new-schedule-id}
        {
          subject: subject,
          verification-type: verification-type,
          target-block: target-block,
          min-age-requirement: min-age-requirement,
          conditions: conditions,
          executed: false,
          created-at: stacks-block-height
        })
      (var-set schedule-count new-schedule-id)
      (ok new-schedule-id))))

(define-public (create-timelock 
    (subject principal)
    (unlock-block uint)
    (lock-type (string-ascii 20))
    (proof-data (buff 32)))
  (let (
    (new-lock-id (+ (var-get timelock-count) u1))
    (subject-proof (map-get? AgeProofs subject)))
    (begin
      (asserts! (> unlock-block stacks-block-height) ERR-INVALID-TIME)
      (asserts! (is-some subject-proof) ERR-NOT-REGISTERED)
      (map-set TimeLocks 
        {owner: tx-sender, lock-id: new-lock-id}
        {
          subject: subject,
          unlock-block: unlock-block,
          lock-type: lock-type,
          proof-data: proof-data,
          conditions-met: false,
          created-at: stacks-block-height
        })
      (var-set timelock-count new-lock-id)
      (ok new-lock-id))))

(define-public (unlock-timelock 
    (lock-id uint)
    (verification-proof (buff 32)))
  (let (
    (timelock (unwrap! (map-get? TimeLocks {owner: tx-sender, lock-id: lock-id}) ERR-SCHEDULE-NOT-FOUND))
    (subject-proof (unwrap! (map-get? AgeProofs (get subject timelock)) ERR-NOT-REGISTERED))
    (unlock-block (get unlock-block timelock))
    (proof-valid (is-eq (get proof-data timelock) verification-proof)))
    (begin
      (asserts! (>= stacks-block-height unlock-block) ERR-TIME-LOCK-ACTIVE)
      (asserts! (not (get conditions-met timelock)) ERR-ALREADY-EXECUTED)
      (asserts! proof-valid ERR-INVALID-PROOF)
      (map-set TimeLocks 
        {owner: tx-sender, lock-id: lock-id}
        {
          subject: (get subject timelock),
          unlock-block: unlock-block,
          lock-type: (get lock-type timelock),
          proof-data: (get proof-data timelock),
          conditions-met: true,
          created-at: (get created-at timelock)
        })
      (ok true))))

(define-public (execute-scheduled-verification 
    (schedule-id uint))
  (let (
    (schedule (unwrap! (map-get? ScheduledVerifications {scheduler: tx-sender, schedule-id: schedule-id}) ERR-SCHEDULE-NOT-FOUND))
    (subject-proof (unwrap! (map-get? AgeProofs (get subject schedule)) ERR-NOT-REGISTERED))
    (target-block (get target-block schedule))
    (min-age (get min-age-requirement schedule))
    (current-year (/ stacks-block-height u144))
    (subject-age (- current-year (get birth-year subject-proof))))
    (begin
      (asserts! (>= stacks-block-height target-block) ERR-INVALID-TIME)
      (asserts! (not (get executed schedule)) ERR-ALREADY-EXECUTED)
      (asserts! (>= subject-age min-age) ERR-CONDITIONS-NOT-MET)
      (map-set ScheduledVerifications 
        {scheduler: tx-sender, schedule-id: schedule-id}
        {
          subject: (get subject schedule),
          verification-type: (get verification-type schedule),
          target-block: target-block,
          min-age-requirement: min-age,
          conditions: (get conditions schedule),
          executed: true,
          created-at: (get created-at schedule)
        })
      (ok true))))

(define-public (setup-conditional-verification 
    (subject principal)
    (age-threshold uint)
    (time-window-start uint)
    (time-window-end uint)
    (verification-hash (buff 32))
    (auto-execute bool))
  (let (
    (new-condition-id (+ (var-get schedule-count) u1))
    (verifier-status (map-get? Verifiers tx-sender)))
    (begin
      (asserts! (is-some verifier-status) ERR-UNAUTHORIZED)
      (asserts! (> time-window-end time-window-start) ERR-INVALID-TIME)
      (asserts! (> time-window-start stacks-block-height) ERR-INVALID-TIME)
      (asserts! (> age-threshold u0) ERR-INVALID-AGE)
      (map-set ConditionalVerifications 
        {verifier: tx-sender, condition-id: new-condition-id}
        {
          subject: subject,
          age-threshold: age-threshold,
          time-window-start: time-window-start,
          time-window-end: time-window-end,
          verification-hash: verification-hash,
          auto-execute: auto-execute,
          status: "PENDING"
        })
      (ok new-condition-id))))

(define-public (trigger-conditional-verification 
    (condition-id uint))
  (let (
    (condition (unwrap! (map-get? ConditionalVerifications {verifier: tx-sender, condition-id: condition-id}) ERR-SCHEDULE-NOT-FOUND))
    (subject-proof (unwrap! (map-get? AgeProofs (get subject condition)) ERR-NOT-REGISTERED))
    (current-block stacks-block-height)
    (window-start (get time-window-start condition))
    (window-end (get time-window-end condition))
    (age-threshold (get age-threshold condition))
    (current-year (/ current-block u144))
    (subject-age (- current-year (get birth-year subject-proof)))
    (in-time-window (and (>= current-block window-start) (<= current-block window-end)))
    (age-met (>= subject-age age-threshold)))
    (begin
      (asserts! in-time-window ERR-INVALID-TIME)
      (asserts! age-met ERR-CONDITIONS-NOT-MET)
      (asserts! (is-eq (get status condition) "PENDING") ERR-ALREADY-EXECUTED)
      (map-set ConditionalVerifications 
        {verifier: tx-sender, condition-id: condition-id}
        {
          subject: (get subject condition),
          age-threshold: age-threshold,
          time-window-start: window-start,
          time-window-end: window-end,
          verification-hash: (get verification-hash condition),
          auto-execute: (get auto-execute condition),
          status: "EXECUTED"
        })
      (ok true))))

(define-public (batch-schedule-verification 
    (subjects (list 10 principal))
    (verification-type (string-ascii 20))
    (target-block uint)
    (min-age-requirement uint))
  (let (
    (base-schedule-id (var-get schedule-count)))
    (begin
      (asserts! (> target-block stacks-block-height) ERR-INVALID-TIME)
      (asserts! (> min-age-requirement u0) ERR-INVALID-AGE)
      (fold process-batch-schedule subjects base-schedule-id)
      (ok true))))

(define-private (process-batch-schedule 
    (subject principal)
    (current-id uint))
  (let (
    (new-id (+ current-id u1)))
    (begin
      (map-set ScheduledVerifications 
        {scheduler: tx-sender, schedule-id: new-id}
        {
          subject: subject,
          verification-type: "BATCH",
          target-block: (+ stacks-block-height u144),
          min-age-requirement: u18,
          conditions: "AUTO-GENERATED",
          executed: false,
          created-at: stacks-block-height
        })
      (var-set schedule-count new-id)
      new-id)))

(define-read-only (get-scheduled-verification 
    (scheduler principal)
    (schedule-id uint))
  (map-get? ScheduledVerifications {scheduler: scheduler, schedule-id: schedule-id}))

(define-read-only (get-timelock 
    (owner principal)
    (lock-id uint))
  (map-get? TimeLocks {owner: owner, lock-id: lock-id}))

(define-read-only (get-conditional-verification 
    (verifier principal)
    (condition-id uint))
  (map-get? ConditionalVerifications {verifier: verifier, condition-id: condition-id}))

(define-read-only (check-schedule-eligibility 
    (schedule-id uint)
    (scheduler principal))
  (match (map-get? ScheduledVerifications {scheduler: scheduler, schedule-id: schedule-id})
    schedule (and 
      (>= stacks-block-height (get target-block schedule))
      (not (get executed schedule)))
    false))

(define-read-only (check-timelock-eligibility 
    (lock-id uint)
    (owner principal))
  (match (map-get? TimeLocks {owner: owner, lock-id: lock-id})
    timelock (and 
      (>= stacks-block-height (get unlock-block timelock))
      (not (get conditions-met timelock)))
    false))

(define-read-only (get-scheduling-stats)
  {
    total-schedules: (var-get schedule-count),
    total-timelocks: (var-get timelock-count),
    current-block: stacks-block-height
  })

(define-read-only (calculate-time-until-unlock 
    (target-block uint))
  (if (> target-block stacks-block-height)
    (- target-block stacks-block-height)
    u0))


