from ai.predict import detect_anomaly

print("--- RATIO-BASED AI TEST ---")

# 1. Normal (0% Failures)
r, s = detect_anomaly('u', 'DOWNLOAD', 'SUCCESS', failure_ratio=0.0)
print(f"1. Perfect User (0%)  -> Risk: {r} (Score: {s:.2f}) [Should be Safe]")

# 2. Normal Mistake (10% Failures) - e.g., 2 fails in 20
r, s = detect_anomaly('u', 'DOWNLOAD', 'FAILURE', failure_ratio=0.10)
print(f"2. Clumsy User (10%)  -> Risk: {r} (Score: {s:.2f}) [Should be Safe]")

# 3. INTERLEAVED ATTACK (50% Failures) - e.g., 10 fails in 20
# Old system might miss this if they weren't consecutive.
# New system catches it because ratio is high.
r, s = detect_anomaly('u', 'DOWNLOAD', 'FAILURE', failure_ratio=0.50)
print(f"3. Attacker (50%)     -> Risk: {r} (Score: {s:.2f}) [Should be RISK]")

# 4. BRUTE FORCE (90% Failures)
r, s = detect_anomaly('u', 'DOWNLOAD', 'FAILURE', failure_ratio=0.90)
print(f"4. Brute Force (90%)  -> Risk: {r} (Score: {s:.2f}) [Should be RISK]")