package com.lookahead.learning.content.gateway;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class MembershipRoutesTest {
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
