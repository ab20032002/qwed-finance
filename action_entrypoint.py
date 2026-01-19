# FILE: action_entrypoint.py
import sys
import os
import pandas as pd
from qwed_finance import FinanceVerifier

def main():
    # 1. Get the file path from action.yml inputs
    if len(sys.argv) < 2:
        print("❌ Error: No file path provided.")
        sys.exit(1)
        
    file_path = sys.argv[1] # Fixed: Accessing the first argument, not the whole list
    
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found at {file_path}")
        sys.exit(1)

    print(f"🔍 QWED Accountant is auditing: {file_path}")
    
    # 2. Initialize the Verifier (Source:)
    verifier = FinanceVerifier()
    
    # 3. Simulate checking a CSV (Simplified logic)
    # In real life, you loop through rows here
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")
        sys.exit(1)

    errors = 0
    
    for index, row in df.iterrows():
        # Example: Verify Loan EMI
        # We need to check if columns exist before verifying
        if "loan_amount" in row and "llm_output_emi" in row and "interest_rate" in row and "months" in row:
            try:
                result = verifier.verify_monthly_payment(
                    principal=row['loan_amount'],
                    annual_rate=row['interest_rate'],
                    months=row['months'],
                    llm_output=str(row['llm_output_emi']) # Ensure string for verifier
                )
                
                if not result.verified:
                    print(f"🛑 HALLUCINATION DETECTED at Row {index}:")
                    print(f"   AI Said: {result.llm_value}")
                    print(f"   QWED Proved: {result.computed_value}")
                    errors += 1
            except Exception as e:
                print(f"⚠️ Warning at Row {index}: Verification failed - {e}")
        
    
    # 4. The "Block" Logic
    if errors > 0:
        print(f"❌ Audit Failed. Found {errors} math errors.")
        sys.exit(1) # This fails the GitHub Action (Red Cross)
    else:
        print("✅ Audit Passed. All math is mathematically proven.")
        sys.exit(0) # This passes the GitHub Action (Green Check)

if __name__ == "__main__":
    main()
