package com.lookahead.gateway.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.lookahead.gateway.proxy.AccountMergeProxy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.WebUtils;

/**
 * DLV-1015: the controller holds the three account-merge routes and nothing else. Each route, reached through Spring
 * MVC, is one call to AccountMergeProxy with the method, the path part, the request, the response and who is signed in,
 * and the forwarder's answer goes back unchanged. What the forwarder does is tested in AccountMergeProxyTest; the
 * security chain in front of the routes in GatewayBffApplicationCloudIntegrationTest.
 */
class AccountMergeProxyControllerTest {
    static final String TOKEN = "synthetic-merge-token-0123456789abcdefghijklmnopqrstuvwxyz";
    final AccountMergeProxy proxy = mock(AccountMergeProxy.class);
    final MockMvc mvc = MockMvcBuilders.standaloneSetup(new AccountMergeProxyController(proxy)).build();
    final Authentication signedIn = UsernamePasswordAuthenticationToken.authenticated("synthetic-owner", "", List.of());
    final ArgumentCaptor<HttpServletRequest> request = ArgumentCaptor.forClass(HttpServletRequest.class);
    final ArgumentCaptor<HttpServletResponse> response = ArgumentCaptor.forClass(HttpServletResponse.class);

    static ResponseEntity<?> answer(int status, String code) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").header("X-From", "the forwarder")
                .contentType(MediaType.APPLICATION_JSON).body(Map.of("code", code));
    }

    void answered(MvcResult result, int status, String code) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getHeaderValues("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(result.getResponse().getHeader("X-From")).isEqualTo("the forwarder");
        assertThat(result.getResponse().getContentAsString()).isEqualTo("{\"code\":\"" + code + "\"}");
        // Spring MVC hands the forwarder the request it received and the response inside its own wrapper.
        assertThat(WebUtils.getNativeResponse(response.getValue(), MockHttpServletResponse.class)).isSameAs(result.getResponse());
    }

    @Test void askingForTheEmailIsOneCallWithPostAndTheRequestPath() throws Exception {
        doReturn(answer(291, "ANSWER_OF_REQUEST")).when(proxy).forward(any(), any(), any(), any(), any());
        var result = mvc.perform(post("/api/v1/account/merge/request").principal(signedIn)).andReturn();
        verify(proxy).forward(eq(HttpMethod.POST), eq("/request"), request.capture(), response.capture(), same(signedIn));
        verifyNoMoreInteractions(proxy);
        answered(result, 291, "ANSWER_OF_REQUEST");
        assertThat(request.getValue().getRequestURI()).isEqualTo("/api/v1/account/merge/request");
    }

    @Test void readingTheCandidatesIsOneCallWithGetAndTheTokenFromThePath() throws Exception {
        doReturn(answer(292, "ANSWER_OF_CANDIDATES")).when(proxy).forwardWithToken(any(), any(), any(), any(), any());
        var result = mvc.perform(get("/api/v1/account/merge/" + TOKEN).principal(signedIn)).andReturn();
        verify(proxy).forwardWithToken(eq(HttpMethod.GET), eq(TOKEN), request.capture(), response.capture(), same(signedIn));
        verifyNoMoreInteractions(proxy);
        answered(result, 292, "ANSWER_OF_CANDIDATES");
        assertThat(request.getValue().getRequestURI()).isEqualTo("/api/v1/account/merge/" + TOKEN);
    }

    @Test void mergingIsOneCallWithPostAndTheTokenFromThePath() throws Exception {
        doReturn(answer(293, "ANSWER_OF_MERGE")).when(proxy).forwardWithToken(any(), any(), any(), any(), any());
        var result = mvc.perform(post("/api/v1/account/merge/" + TOKEN).principal(signedIn).contentType(MediaType.APPLICATION_JSON).content("{\"accounts\":[]}")).andReturn();
        verify(proxy).forwardWithToken(eq(HttpMethod.POST), eq(TOKEN), request.capture(), response.capture(), same(signedIn));
        verifyNoMoreInteractions(proxy);
        answered(result, 293, "ANSWER_OF_MERGE");
        // The body is not read here: the forwarder reads it from the request it is given.
        assertThat(new String(request.getValue().getInputStream().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("{\"accounts\":[]}");
    }

    @Test void nobodySignedInIsHandedOverAsNobodyAndTheForwarderDecides() throws Exception {
        doReturn(answer(294, "ANSWER_WITHOUT_SIGN_IN")).when(proxy).forward(any(), any(), any(), any(), isNull());
        var result = mvc.perform(post("/api/v1/account/merge/request")).andReturn();
        verify(proxy).forward(eq(HttpMethod.POST), eq("/request"), any(), response.capture(), isNull());
        answered(result, 294, "ANSWER_WITHOUT_SIGN_IN");
    }

    @Test void onlyTheseThreeRoutesExist() throws Exception {
        // A GET of the fixed word is the candidates route with that word as its token; the forwarder's own shape check answers it.
        doReturn(answer(295, "ANSWER_OF_CANDIDATES")).when(proxy).forwardWithToken(any(), any(), any(), any(), any());
        mvc.perform(get("/api/v1/account/merge/request").principal(signedIn)).andReturn();
        verify(proxy).forwardWithToken(eq(HttpMethod.GET), eq("request"), any(), any(), same(signedIn));
        reset(proxy);
        assertThat(mvc.perform(put("/api/v1/account/merge/" + TOKEN)).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(delete("/api/v1/account/merge/" + TOKEN)).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(put("/api/v1/account/merge/request")).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(post("/api/v1/account/merge")).andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(mvc.perform(get("/api/v1/account/merge/" + TOKEN + "/more")).andReturn().getResponse().getStatus()).isEqualTo(404);
        verifyNoInteractions(proxy);
    }
}
