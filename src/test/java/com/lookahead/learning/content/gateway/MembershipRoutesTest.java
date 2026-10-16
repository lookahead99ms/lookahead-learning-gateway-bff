package com.lookahead.learning.content.gateway;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class MembershipRoutesTest {
 @Test void testAccountsExposeOnlyListAndConfirmedReset() {
  String id="00000000-0000-0000-0000-000000000001";
  assertThat(GatewayController.membershipRoute("GET","/api/v1/admin/test-accounts")).isTrue();
  assertThat(GatewayController.membershipRoute("POST","/api/v1/admin/test-accounts/"+id+"/reset")).isTrue();
  for(String path:java.util.List.of("/internal/v1/test-accounts/seed","/api/v1/admin/test-accounts/not-id/reset","/api/v1/admin/test-accounts/"+id+"/passwords"))
   assertThat(GatewayController.membershipRoute("POST",path)).isFalse();
  assertThat(GatewayController.membershipRoute("DELETE","/api/v1/admin/test-accounts/"+id+"/reset")).isFalse();
 }
 @Test void summaryRoutesAreReadOnlyAndAccountBound(){
  String id="12345678-1234-1234-1234-123456789abc";
  assertThat(GatewayController.membershipRoute("GET","/api/v1/account/access-summary")).isTrue();
  assertThat(GatewayController.membershipRoute("GET","/api/v1/admin/accounts/"+id+"/access-summary")).isTrue();
  assertThat(GatewayController.membershipRoute("POST","/api/v1/account/access-summary")).isFalse();
  assertThat(GatewayController.membershipRoute("GET","/api/v1/admin/accounts/not-an-id/access-summary")).isFalse();
  assertThat(GatewayController.membershipRoute("GET","/api/v1/admin/accounts/"+id+"/access-summary/extra")).isFalse();
 }
 @Test void exactPublicAndWriteRoutes(){
  assertThat(GatewayController.membershipRoute("GET","/api/v1/membership/plans")).isTrue();
  assertThat(GatewayController.membershipRoute("GET","/api/v1/plans")).isFalse();
  assertThat(GatewayController.membershipRoute("POST","/api/v1/account/purchases")).isTrue();
  assertThat(GatewayController.membershipRoute("POST","/api/v1/account/purchases/quote")).isTrue();
  assertThat(GatewayController.membershipRoute("DELETE","/api/v1/account/purchases")).isFalse();
  assertThat(GatewayController.membershipRoute("POST","/api/v1/membership/plans")).isFalse();
  assertThat(GatewayController.membershipRoute("GET","/api/v1/admin/accounts/not-a-uuid/access-records")).isFalse();
 }
}
