# @qwed-ai/finance

TypeScript SDK for QWED-Finance - Deterministic verification for banking AI.

## Installation

```bash
npm install @qwed-ai/finance
```

**Prerequisite:** Python 3.11+ with `qwed-finance` installed:

```bash
pip install qwed-finance
```

## Usage

```typescript
import { FinanceVerifier, ComplianceGuard, UCPVerifier } from '@qwed-ai/finance';

// Verify NPV calculation
const verifier = new FinanceVerifier();
const npvResult = await verifier.verifyNPV([-1000, 300, 400, 500], 0.1, "$180");
console.log(npvResult.verified);  // true
console.log(npvResult.computed_value);  // "$180.42"

// Check AML compliance
const compliance = new ComplianceGuard();
const amlResult = await compliance.checkAML(15000, "US");
console.log(amlResult.needs_flagging);  // true (over $10k threshold)

// Verify payment token
const ucp = new UCPVerifier();
const paymentResult = await ucp.verifyPaymentToken({
  amount: 5000,
  currency: "USD",
  customer_country: "US",
  kyc_verified: true
});
console.log(paymentResult.can_proceed);  // true
```

## API

### FinanceVerifier

- `verifyNPV(cashflows, rate, llmOutput)` - Verify NPV calculation
- `verifyLoanPayment(principal, annualRate, months)` - Verify loan payment

### ComplianceGuard

- `checkAML(amount, countryCode)` - Check AML compliance

### UCPVerifier

- `verifyPaymentToken(tokenData)` - Verify payment token

## License

Apache 2.0
