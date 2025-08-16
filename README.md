# 🔐 AgeProof Smart Contract

A decentralized age verification system built on Stacks blockchain that enables privacy-preserving age verification.

## 🎯 Features

- ✨ Privacy-first age verification
- 🔒 Trusted verifier network
- ⚡ Real-time verification requests
- 🕒 Proof expiration management
- 👥 Multi-party verification flow

## 🚀 Getting Started

1. Install Clarinet
```bash
curl -L https://github.com/hirosystems/clarinet/releases/download/v1.0.0/clarinet-linux-x64.tar.gz | tar xz
```

2. Deploy the contract
```bash
clarinet deploy
```

## 📖 Usage Flow

1. Admin registers trusted verifiers
2. Verifiers submit age proofs for users
3. Third parties request age verification
4. Smart contract validates age requirements
5. Results returned while preserving privacy

## 🔧 Main Functions

- `register-verifier`: Add trusted verifiers
- `submit-age-proof`: Submit verified age proof
- `request-age-verification`: Request age check
- `verify-age`: Validate age requirements
- `get-verification-status`: Check verification status

## ⚠️ Requirements

- Clarinet 1.0.0 or higher
- Stacks blockchain connection
- Principal authorization


