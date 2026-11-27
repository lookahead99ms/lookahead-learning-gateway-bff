package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/** DLV-1015: the start-up refusal the gate's bean method held, now in the factory it calls (same type, same message). */
class DevAccessGateTest {
    @Test void theGateIsBuiltInTheDevEnvironmentOnly() {
        assertThat(DevAccessGate.freshSignIn(Clock.systemUTC(), "dev")).isNotNull();
        for (String environment : new String[]{"prod", "local", "DEV", "", null})
            assertThatThrownBy(() -> DevAccessGate.freshSignIn(Clock.systemUTC(), environment)).as(String.valueOf(environment))
                .isExactlyInstanceOf(IllegalStateException.class).hasMessage("DEV profile only").hasNoCause();
    }

    @Nested class FreshSignIn {
    final Instant now=Instant.parse("2026-10-14T12:00:00Z");
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    OidcUser signedIn(Map<String,Object> claims){
        var all=new HashMap<String,Object>(Map.of("sub","010b25a0-c0f1-709c-467f-06e036639814"));all.putAll(claims);
        var token=new OidcIdToken("synthetic-id-token",now.minusSeconds(5),now.plusSeconds(3600),all);
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),token);
    }
    @Test void gateOpensOnAFreshLookAheadSignInWithUsernameOrSubject() {
        // DLV-969: no directory call; the ID token's auth_time must be at most 120 s old and at most 30 s ahead.
        var gate=DevAccessGate.freshSignIn(Clock.fixed(now,ZoneOffset.UTC),"dev");
        var request=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");request.getSession().setAttribute("SPRING_SECURITY_CONTEXT","learner");
        gate.admit(request,signedIn(Map.of("cognito:username","author@lookahead.dev","auth_time",now.minusSeconds(120))));
        assertEquals(new DevAccessSession.State("author@lookahead.dev","010b25a0-c0f1-709c-467f-06e036639814",now),request.getSession().getAttribute(DevAccessSession.ATTRIBUTE));
        assertEquals("learner",request.getSession().getAttribute("SPRING_SECURITY_CONTEXT"));assertEquals(8*3600,request.getSession().getMaxInactiveInterval());
        var federated=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");
        gate.admit(federated,signedIn(Map.of("auth_time",now.plusSeconds(30))));
        assertEquals(new DevAccessSession.State("010b25a0-c0f1-709c-467f-06e036639814","010b25a0-c0f1-709c-467f-06e036639814",now),federated.getSession().getAttribute(DevAccessSession.ATTRIBUTE));
    }
    @Test void gateRefusesAStaleFutureOrMissingAuthTime() {
        var gate=DevAccessGate.freshSignIn(Clock.fixed(now,ZoneOffset.UTC),"dev");
        for(Map<String,Object> claims:List.<Map<String,Object>>of(Map.of("auth_time",now.minusSeconds(121)),Map.of("auth_time",now.plusSeconds(31)),Map.of())){
            var request=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");
            assertThrows(IllegalStateException.class,()->gate.admit(request,signedIn(claims)),claims.toString());
            assertNull(request.getSession(false),claims.toString());
        }
    }
    }
}
