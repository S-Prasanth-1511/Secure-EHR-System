from ai.predict import detect_anomaly

# Simulation: 20 failed attempts
print("Testing Normal (0 failures)...")
is_risk, score = detect_anomaly('test', 'DOWNLOAD', 'SUCCESS', failure_count=0)
print(f"Risk: {is_risk}, Score: {score:.2f}")

print("\nTesting Attack (20 failures)...")
is_risk, score = detect_anomaly('test', 'DOWNLOAD', 'FAILURE', failure_count=20)
print(f"Risk: {is_risk}, Score: {score:.2f}")

if is_risk: print("\n✅ SUCCESS: The AI detected the attack!")
else: print("\n❌ FAILURE: The AI missed the attack.")