;; Age-Gated Content Access System
;; Enables content creators to set age restrictions and automatically control access
;; based on verified age proofs while maintaining user privacy and regulatory compliance

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u2000))
(define-constant ERR-CONTENT-NOT-FOUND (err u2001))
(define-constant ERR-INSUFFICIENT-AGE (err u2002))
(define-constant ERR-CONTENT-SUSPENDED (err u2003))
(define-constant ERR-INVALID-ACCESS-POLICY (err u2004))
(define-constant ERR-SUBSCRIPTION-EXPIRED (err u2005))
(define-constant ERR-COMPLIANCE-VIOLATION (err u2006))
(define-constant ERR-INVALID-RATING (err u2007))
(define-constant ERR-ACCESS-DENIED (err u2008))
(define-constant ERR-INVALID-JURISDICTION (err u2009))
(define-constant ERR-PARENTAL-CONTROL-ACTIVE (err u2010))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var content-registry-count uint u0)
(define-data-var access-session-count uint u0)
(define-data-var compliance-report-count uint u0)
(define-data-var platform-count uint u0)

;; Content registry with age restrictions
(define-map content-registry
  uint
  {
    creator: principal,
    content-hash: (buff 32),
    title: (string-ascii 100),
    category: (string-ascii 50),
    min-age-required: uint,
    content-rating: (string-ascii 10),
    jurisdiction: (string-ascii 20),
    platform-id: uint,
    created-at: uint,
    last-accessed: uint,
    access-count: uint,
    status: (string-ascii 20),
    parental-override: bool,
    compliance-flags: (list 5 (string-ascii 30))
  }
)

;; Platform registration for content hosting
(define-map platform-registry
  uint
  {
    platform-owner: principal,
    platform-name: (string-ascii 50),
    jurisdiction: (string-ascii 20),
    compliance-level: uint,
    content-categories: (list 10 (string-ascii 30)),
    age-verification-required: bool,
    parental-control-support: bool,
    active: bool,
    registration-date: uint,
    last-compliance-check: uint
  }
)

;; User content access sessions
(define-map content-access-sessions
  uint
  {
    user: principal,
    content-id: uint,
    platform-id: uint,
    access-timestamp: uint,
    session-duration: uint,
    age-verified: bool,
    compliance-status: (string-ascii 20),
    parental-permission: bool,
    jurisdiction-compliance: bool,
    session-active: bool
  }
)

;; Age-based access policies
(define-map access-policies
  {platform-id: uint, jurisdiction: (string-ascii 20)}
  {
    min-age-general: uint,
    min-age-mature: uint,
    min-age-adult: uint,
    parental-consent-required: bool,
    identity-verification-level: uint,
    time-restrictions: (list 5 uint), ;; hours when access is allowed
    compliance-monitoring: bool,
    automatic-suspension: bool
  }
)

;; Parental control settings
(define-map parental-controls
  principal
  {
    parent: principal,
    child: principal,
    allowed-categories: (list 10 (string-ascii 50)),
    blocked-categories: (list 10 (string-ascii 50)),
    max-daily-access: uint, ;; in minutes
    time-window-start: uint, ;; hour of day
    time-window-end: uint, ;; hour of day
    require-approval: bool,
    active: bool,
    created-at: uint
  }
)

;; Compliance audit trail
(define-map compliance-reports
  uint
  {
    platform-id: uint,
    content-id: uint,
    user: principal,
    violation-type: (string-ascii 50),
    severity: uint,
    description: (string-ascii 200),
    reported-by: principal,
    report-timestamp: uint,
    investigated: bool,
    action-taken: (string-ascii 100),
    resolution-date: (optional uint)
  }
)

;; Content rating system
(define-map content-ratings
  (string-ascii 10)
  {
    rating-name: (string-ascii 10),
    min-age: uint,
    description: (string-ascii 100),
    jurisdiction-specific: bool,
    parental-guidance: bool
  }
)

;; User subscription and access tracking
(define-map user-subscriptions
  {user: principal, platform-id: uint}
  {
    subscription-type: (string-ascii 30),
    start-date: uint,
    expiry-date: uint,
    access-level: uint,
    age-verified: bool,
    parental-approved: bool,
    active: bool,
    total-access-time: uint,
    compliance-score: uint
  }
)

;; Geographic jurisdiction compliance
(define-map jurisdiction-rules
  (string-ascii 20)
  {
    jurisdiction-name: (string-ascii 20),
    min-age-digital-consent: uint,
    parental-consent-required-until: uint,
    restricted-content-types: (list 5 (string-ascii 30)),
    mandatory-age-verification: bool,
    time-based-restrictions: bool,
    compliance-reporting-required: bool
  }
)

;; Initialize standard content ratings
(define-private (init-standard-ratings)
  (begin
    (map-set content-ratings "G"
      {
        rating-name: "G",
        min-age: u0,
        description: "General Audiences - All ages admitted",
        jurisdiction-specific: false,
        parental-guidance: false
      })
    (map-set content-ratings "PG"
      {
        rating-name: "PG",
        min-age: u0,
        description: "Parental Guidance Suggested",
        jurisdiction-specific: false,
        parental-guidance: true
      })
    (map-set content-ratings "PG-13"
      {
        rating-name: "PG-13",
        min-age: u13,
        description: "Parents Strongly Cautioned - Some material may be inappropriate for children under 13",
        jurisdiction-specific: false,
        parental-guidance: true
      })
    (map-set content-ratings "R"
      {
        rating-name: "R",
        min-age: u17,
        description: "Restricted - Under 17 requires accompanying parent or adult guardian",
        jurisdiction-specific: false,
        parental-guidance: true
      })
    (map-set content-ratings "NC-17"
      {
        rating-name: "NC-17",
        min-age: u17,
        description: "No one 17 and under admitted",
        jurisdiction-specific: false,
        parental-guidance: false
      })
    (map-set content-ratings "M"
      {
        rating-name: "M",
        min-age: u18,
        description: "Mature Content - 18 and older",
        jurisdiction-specific: true,
        parental-guidance: false
      })
  )
)

;; Register a content platform
(define-public (register-platform
  (platform-name (string-ascii 50))
  (jurisdiction (string-ascii 20))
  (content-categories (list 10 (string-ascii 30)))
  (age-verification-required bool)
  (parental-control-support bool)
)
  (let
    (
      (platform-id (+ (var-get platform-count) u1))
    )
    (asserts! (> (len platform-name) u0) ERR-INVALID-ACCESS-POLICY)
    (asserts! (> (len jurisdiction) u0) ERR-INVALID-JURISDICTION)
    
    (map-set platform-registry platform-id
      {
        platform-owner: tx-sender,
        platform-name: platform-name,
        jurisdiction: jurisdiction,
        compliance-level: u75,
        content-categories: content-categories,
        age-verification-required: age-verification-required,
        parental-control-support: parental-control-support,
        active: true,
        registration-date: stacks-block-height,
        last-compliance-check: stacks-block-height
      })
    
    (var-set platform-count platform-id)
    (ok platform-id)
  )
)

;; Register age-gated content
(define-public (register-content
  (content-hash (buff 32))
  (title (string-ascii 100))
  (category (string-ascii 50))
  (content-rating (string-ascii 10))
  (platform-id uint)
  (parental-override bool)
)
  (let
    (
      (content-id (+ (var-get content-registry-count) u1))
      (platform-info (unwrap! (map-get? platform-registry platform-id) ERR-CONTENT-NOT-FOUND))
      (rating-info (unwrap! (map-get? content-ratings content-rating) ERR-INVALID-RATING))
      (min-age (get min-age rating-info))
    )
    (asserts! (is-eq tx-sender (get platform-owner platform-info)) ERR-UNAUTHORIZED)
    (asserts! (get active platform-info) ERR-CONTENT-SUSPENDED)
    (asserts! (> (len title) u0) ERR-INVALID-ACCESS-POLICY)
    
    (map-set content-registry content-id
      {
        creator: tx-sender,
        content-hash: content-hash,
        title: title,
        category: category,
        min-age-required: min-age,
        content-rating: content-rating,
        jurisdiction: (get jurisdiction platform-info),
        platform-id: platform-id,
        created-at: stacks-block-height,
        last-accessed: u0,
        access-count: u0,
        status: "active",
        parental-override: parental-override,
        compliance-flags: (list)
      })
    
    (var-set content-registry-count content-id)
    (ok content-id)
  )
)



;; Set up parental controls
(define-public (setup-parental-controls
  (child principal)
  (allowed-categories (list 10 (string-ascii 50)))
  (blocked-categories (list 10 (string-ascii 50)))
  (max-daily-access uint)
  (time-window-start uint)
  (time-window-end uint)
  (require-approval bool)
)
  (begin
    (asserts! (< time-window-start u24) ERR-INVALID-ACCESS-POLICY)
    (asserts! (< time-window-end u24) ERR-INVALID-ACCESS-POLICY)
    (asserts! (not (is-eq tx-sender child)) ERR-UNAUTHORIZED)
    
    (map-set parental-controls child
      {
        parent: tx-sender,
        child: child,
        allowed-categories: allowed-categories,
        blocked-categories: blocked-categories,
        max-daily-access: max-daily-access,
        time-window-start: time-window-start,
        time-window-end: time-window-end,
        require-approval: require-approval,
        active: true,
        created-at: stacks-block-height
      })
    (ok true)
  )
)

;; Configure platform access policies
(define-public (configure-access-policy
  (platform-id uint)
  (jurisdiction (string-ascii 20))
  (min-age-general uint)
  (min-age-mature uint)
  (min-age-adult uint)
  (parental-consent-required bool)
  (compliance-monitoring bool)
)
  (let
    (
      (platform-info (unwrap! (map-get? platform-registry platform-id) ERR-CONTENT-NOT-FOUND))
    )
    (asserts! (is-eq tx-sender (get platform-owner platform-info)) ERR-UNAUTHORIZED)
    (asserts! (>= min-age-mature min-age-general) ERR-INVALID-ACCESS-POLICY)
    (asserts! (>= min-age-adult min-age-mature) ERR-INVALID-ACCESS-POLICY)
    
    (map-set access-policies {platform-id: platform-id, jurisdiction: jurisdiction}
      {
        min-age-general: min-age-general,
        min-age-mature: min-age-mature,
        min-age-adult: min-age-adult,
        parental-consent-required: parental-consent-required,
        identity-verification-level: u2,
        time-restrictions: (list),
        compliance-monitoring: compliance-monitoring,
        automatic-suspension: true
      })
    (ok true)
  )
)


;; End content access session
(define-public (end-access-session (session-id uint))
  (let
    (
      (session-info (unwrap! (map-get? content-access-sessions session-id) ERR-CONTENT-NOT-FOUND))
      (session-duration (- stacks-block-height (get access-timestamp session-info)))
    )
    (asserts! (is-eq tx-sender (get user session-info)) ERR-UNAUTHORIZED)
    (asserts! (get session-active session-info) ERR-ACCESS-DENIED)
    
    (map-set content-access-sessions session-id
      (merge session-info {
        session-duration: session-duration,
        session-active: false
      }))
    
    ;; Update user subscription access time
    (update-subscription-access-time (get user session-info) (get platform-id session-info) session-duration)
    (ok true)
  )
)

;; Suspend content for compliance violation
(define-private (suspend-content (content-id uint))
  (let
    (
      (content-info (unwrap! (map-get? content-registry content-id) ERR-CONTENT-NOT-FOUND))
    )
    (map-set content-registry content-id
      (merge content-info {
        status: "suspended",
        compliance-flags: (unwrap-panic (as-max-len? (append (get compliance-flags content-info) "auto-suspended") u5))
      }))
    (ok true)
  )
)

;; Check parental permission for content access
(define-private (check-parental-permission 
  (content-info {creator: principal, content-hash: (buff 32), title: (string-ascii 100), category: (string-ascii 50), min-age-required: uint, content-rating: (string-ascii 10), jurisdiction: (string-ascii 20), platform-id: uint, created-at: uint, last-accessed: uint, access-count: uint, status: (string-ascii 20), parental-override: bool, compliance-flags: (list 5 (string-ascii 30))})
  (parental-controls-info (optional {parent: principal, child: principal, allowed-categories: (list 10 (string-ascii 50)), blocked-categories: (list 10 (string-ascii 50)), max-daily-access: uint, time-window-start: uint, time-window-end: uint, require-approval: bool, active: bool, created-at: uint}))
)
  (match parental-controls-info
    controls
    (let
      (
        (content-category (get category content-info))
        (blocked-categories (get blocked-categories controls))
        (allowed-categories (get allowed-categories controls))
      )
      (and
        (not (is-some (index-of blocked-categories content-category)))
        (or 
          (is-some (index-of allowed-categories content-category))
          (is-eq (len allowed-categories) u0))
        (check-time-window-access controls)
      )
    )
    true
  )
)

;; Check time window for access
(define-private (check-time-window-access 
  (controls {parent: principal, child: principal, allowed-categories: (list 10 (string-ascii 50)), blocked-categories: (list 10 (string-ascii 50)), max-daily-access: uint, time-window-start: uint, time-window-end: uint, require-approval: bool, active: bool, created-at: uint})
)
  (let
    (
      (current-hour (mod (/ stacks-block-height u6) u24)) ;; Approximate hour calculation
      (start-hour (get time-window-start controls))
      (end-hour (get time-window-end controls))
    )
    (if (< start-hour end-hour)
      (and (>= current-hour start-hour) (<= current-hour end-hour))
      (or (>= current-hour start-hour) (<= current-hour end-hour))
    )
  )
)



;; Update subscription access time
(define-private (update-subscription-access-time (user principal) (platform-id uint) (duration uint))
  (let
    (
      (subscription-info (map-get? user-subscriptions {user: user, platform-id: platform-id}))
    )
    (match subscription-info
      sub-info
      (map-set user-subscriptions {user: user, platform-id: platform-id}
        (merge sub-info {
          total-access-time: (+ (get total-access-time sub-info) duration)
        }))
      true
    )
  )
)

;; Read-only functions
(define-read-only (get-content-info (content-id uint))
  (map-get? content-registry content-id)
)

(define-read-only (get-platform-info (platform-id uint))
  (map-get? platform-registry platform-id)
)

(define-read-only (get-access-session (session-id uint))
  (map-get? content-access-sessions session-id)
)

(define-read-only (get-parental-controls (child principal))
  (map-get? parental-controls child)
)

(define-read-only (get-compliance-report (report-id uint))
  (map-get? compliance-reports report-id)
)

(define-read-only (get-content-rating-info (rating (string-ascii 10)))
  (map-get? content-ratings rating)
)

(define-read-only (check-content-access-eligibility 
  (user principal)
  (content-id uint)
  (user-age uint)
)
  (let
    (
      (content-info (map-get? content-registry content-id))
      (parental-controls-info (map-get? parental-controls user))
    )
    (match content-info
      content
      (let
        (
          (min-age-required (get min-age-required content))
          (content-active (is-eq (get status content) "active"))
        )
        {
          age-eligible: (>= user-age min-age-required),
          content-active: content-active,
          parental-permission: (check-parental-permission content parental-controls-info),
          overall-eligible: (and 
            (>= user-age min-age-required)
            content-active
            (check-parental-permission content parental-controls-info)
          )
        }
      )
      {
        age-eligible: false,
        content-active: false,
        parental-permission: false,
        overall-eligible: false
      }
    )
  )
)

(define-read-only (get-platform-content-stats (platform-id uint))
  (let
    (
      (platform-info (map-get? platform-registry platform-id))
    )
    {
      platform-active: (match platform-info info (get active info) false),
      total-registered-content: (var-get content-registry-count),
      total-access-sessions: (var-get access-session-count),
      total-compliance-reports: (var-get compliance-report-count)
    }
  )
)

(define-read-only (get-user-access-summary (user principal) (platform-id uint))
  (let
    (
      (subscription-info (map-get? user-subscriptions {user: user, platform-id: platform-id}))
      (parental-controls-info (map-get? parental-controls user))
    )
    {
      has-subscription: (is-some subscription-info),
      subscription-active: (match subscription-info sub (get active sub) false),
      parental-controls-active: (match parental-controls-info controls (get active controls) false),
      total-access-time: (match subscription-info sub (get total-access-time sub) u0)
    }
  )
)

;; Initialize the contract with standard ratings
(init-standard-ratings)
