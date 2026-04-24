def test_veto_logic(normal_prob_val, attack_probs_vals, is_anomaly=True):
    # Mocking variables from the actual code
    normal_prob = normal_prob_val
    top_attack_prob = max(attack_probs_vals)
    
    VETO_RATIO = 0.5
    is_attack = False
    
    print(f"Testing: Normal={normal_prob:.1f}%, Top Attack={top_attack_prob:.1f}%")
    
    if is_anomaly:
        if normal_prob > 5.0 and (top_attack_prob == 0 or (normal_prob / top_attack_prob) > VETO_RATIO):
            ratio = (normal_prob/top_attack_prob if top_attack_prob > 0 else float('inf'))
            print(f"  [VETO] Action: IGNORED. Ratio: {ratio:.2f}")
            is_attack = False
        else:
            print(f"  [ATTACK] Action: BLOCKED.")
            is_attack = True
    return is_attack

print("--- Scenario 1: Normal 6%, Attack 94% (Should NOT Veto anymore) ---")
test_veto_logic(6.0, [94.0, 0.0, 0.0, 0.0])

print("\n--- Scenario 2: Normal 40%, Attack 60% (Should Veto: 40/60 = 0.66 > 0.5) ---")
test_veto_logic(40.0, [60.0, 0.0, 0.0, 0.0])

print("\n--- Scenario 3: Normal 4%, Attack 96% (Should NOT Veto: normal_prob <= 5.0) ---")
test_veto_logic(4.0, [96.0, 0.0, 0.0, 0.0])

print("\n--- Scenario 4: Normal 20%, Top Attack 30% (Should Veto: 20/30 = 0.66 > 0.5) ---")
test_veto_logic(20.0, [30.0, 10.0, 5.0, 0.0])
