/**
 * QWED-Finance TypeScript SDK
 * 
 * Bridges to the Python qwed-finance package for Node.js environments.
 * 
 * @example
 * ```typescript
 * import { FinanceVerifier, ComplianceGuard } from '@qwed-ai/finance';
 * 
 * const verifier = new FinanceVerifier();
 * const result = await verifier.verifyNPV([-1000, 300, 400], 0.1, "$180");
 * console.log(result.verified);
 * ```
 */

import { PythonShell, Options } from 'python-shell';

export interface VerificationResult {
    verified: boolean;
    computed_value?: string;
    violations?: string[];
    receipt_id?: string;
    input_hash?: string;
    timestamp?: string;
}

export interface AMLResult {
    needs_flagging: boolean;
    reason: string;
    verified: boolean;
}

export interface PaymentVerificationResult {
    can_proceed: boolean;
    status: 'approved' | 'blocked' | 'pending_review';
    violations: string[];
    receipt_ids: string[];
}

/**
 * Core finance verifier for NPV, IRR, and loan calculations
 */
export class FinanceVerifier {
    private pythonPath: string;

    constructor(pythonPath: string = 'python') {
        this.pythonPath = pythonPath;
    }

    /**
     * Verify NPV calculation
     */
    async verifyNPV(
        cashflows: number[],
        rate: number,
        llmOutput: string
    ): Promise<VerificationResult> {
        const script = `
from qwed_finance import OpenResponsesIntegration
import json

qwed = OpenResponsesIntegration()
result = qwed.handle_tool_call("calculate_npv", {
    "cashflows": ${JSON.stringify(cashflows)},
    "rate": ${rate}
})

print(json.dumps({
    "verified": result.receipt.verified if result.receipt else False,
    "computed_value": result.result.get("npv") if result.result else None,
    "receipt_id": result.receipt.receipt_id if result.receipt else None,
    "input_hash": result.receipt.input_hash if result.receipt else None
}))
`;

        return this.runPythonScript(script);
    }

    /**
     * Verify loan payment calculation
     */
    async verifyLoanPayment(
        principal: number,
        annualRate: number,
        months: number
    ): Promise<VerificationResult> {
        const script = `
from qwed_finance import OpenResponsesIntegration
import json

qwed = OpenResponsesIntegration()
result = qwed.handle_tool_call("calculate_loan_payment", {
    "principal": ${principal},
    "annual_rate": ${annualRate},
    "months": ${months}
})

print(json.dumps({
    "verified": result.receipt.verified if result.receipt else False,
    "computed_value": result.result.get("monthly_payment") if result.result else None,
    "receipt_id": result.receipt.receipt_id if result.receipt else None
}))
`;

        return this.runPythonScript(script);
    }

    private async runPythonScript(script: string): Promise<VerificationResult> {
        const options: Options = {
            mode: 'text',
            pythonPath: this.pythonPath,
            pythonOptions: ['-c'],
            args: [script]
        };

        return new Promise((resolve, reject) => {
            PythonShell.run(script, options).then(results => {
                if (results && results.length > 0) {
                    resolve(JSON.parse(results[0]));
                } else {
                    resolve({ verified: false });
                }
            }).catch(err => {
                reject(err);
            });
        });
    }
}

/**
 * Compliance guard for AML/KYC checks
 */
export class ComplianceGuard {
    private pythonPath: string;

    constructor(pythonPath: string = 'python') {
        this.pythonPath = pythonPath;
    }

    /**
     * Check AML compliance
     */
    async checkAML(
        amount: number,
        countryCode: string
    ): Promise<AMLResult> {
        const script = `
from qwed_finance import OpenResponsesIntegration
import json

qwed = OpenResponsesIntegration()
result = qwed.handle_tool_call("check_aml_compliance", {
    "amount": ${amount},
    "country_code": "${countryCode}"
})

print(json.dumps(result.result))
`;

        return new Promise((resolve, reject) => {
            const options: Options = {
                mode: 'text',
                pythonPath: this.pythonPath,
                pythonOptions: ['-c'],
                args: [script]
            };

            PythonShell.run(script, options).then(results => {
                if (results && results.length > 0) {
                    resolve(JSON.parse(results[0]));
                } else {
                    resolve({ needs_flagging: false, reason: 'Error', verified: false });
                }
            }).catch(err => {
                reject(err);
            });
        });
    }
}

/**
 * UCP integration for payment verification
 */
export class UCPVerifier {
    private pythonPath: string;

    constructor(pythonPath: string = 'python') {
        this.pythonPath = pythonPath;
    }

    /**
     * Verify a payment token
     */
    async verifyPaymentToken(tokenData: {
        amount: number;
        currency: string;
        customer_country: string;
        kyc_verified: boolean;
    }): Promise<PaymentVerificationResult> {
        const script = `
from qwed_finance import UCPIntegration
import json

ucp = UCPIntegration()
result = ucp.verify_payment_token(${JSON.stringify(tokenData)})

print(json.dumps({
    "can_proceed": result.can_proceed,
    "status": result.status.value,
    "violations": result.violations,
    "receipt_ids": [r.receipt_id for r in result.receipts]
}))
`;

        return new Promise((resolve, reject) => {
            const options: Options = {
                mode: 'text',
                pythonPath: this.pythonPath,
                pythonOptions: ['-c'],
                args: [script]
            };

            PythonShell.run(script, options).then(results => {
                if (results && results.length > 0) {
                    resolve(JSON.parse(results[0]));
                } else {
                    resolve({ can_proceed: false, status: 'blocked', violations: ['Error'], receipt_ids: [] });
                }
            }).catch(err => {
                reject(err);
            });
        });
    }
}

export default {
    FinanceVerifier,
    ComplianceGuard,
    UCPVerifier
};
