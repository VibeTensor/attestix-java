package io.vibetensor.attestix;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class SecurityBoundariesTest {
 @Test void ambiguousNormalizedKeysAreRejected() {
  Map<String,Object> value = new LinkedHashMap<>();
  value.put("\u00e9",1); value.put("e\u0301",2);
  assertThrows(IllegalArgumentException.class, () -> Attestix.canonicalize(value));
 }
 @Test void malformedExpiryFailsClosed() {
  for (Object expiry : new Object[]{null,false,123,"","invalid"}) {
   Map<String,Object> vc = new LinkedHashMap<>();
   vc.put("proof",Map.of("proofValue","invalid")); vc.put("expirationDate",expiry);
   assertFalse(Attestix.verifyCredential(vc,new byte[32],Instant.now()).notExpired());
  }
 }
 @Test void malformedKeyFailsClosed() {
  assertFalse(Attestix.verifyCredential(Map.of("proof",Map.of("proofValue","AQ==")),new byte[]{1},Instant.now()).verify());
 }
 @Test void missingExpiryRemainsUnlimited() {
  assertTrue(Attestix.verifyCredential(Map.of("proof",Map.of("proofValue","AQ==")),new byte[32],Instant.now()).notExpired());
 }
}
