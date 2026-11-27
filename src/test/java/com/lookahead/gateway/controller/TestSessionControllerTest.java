package com.lookahead.gateway.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.lookahead.gateway.dto.TestSessionStart;
import com.lookahead.gateway.security.handler.TestSessionHandler;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.TestSessionAnswer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.WebUtils;

/**
 * DLV-1015: the controller holds the four test-session routes and nothing else. Each route, reached through Spring MVC,
 * is one call to its TestSessionHandler method with what the route was given (the request, the response, who is signed
 * in, the body read from JSON), and the handler's answer goes back unchanged. What the routes do is tested in
 * TestSessionHandlerTest; the security chain in front of them in TestSessionControllerIntegrationTest.
 */
class TestSessionControllerTest {
    static final String LEARNER = "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a";
    final TestSessionHandler handler = mock(TestSessionHandler.class);
    final MockMvc mvc = MockMvcBuilders.standaloneSetup(new TestSessionController(handler)).build();
    final Authentication signedIn = new TestSessionState.TestSession(LEARNER);
    final ArgumentCaptor<HttpServletRequest> request = ArgumentCaptor.forClass(HttpServletRequest.class);
    final ArgumentCaptor<HttpServletResponse> response = ArgumentCaptor.forClass(HttpServletResponse.class);

    void answered(MvcResult result, int status, String code) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getHeaderValues("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(result.getResponse().getContentType()).isEqualTo("application/json");
        assertThat(result.getResponse().getContentAsString()).isEqualTo("{\"code\":\"" + code + "\",\"message\":\"the handler's own answer\"}");
    }

    @Test void theAccountsRouteIsOneCallWithTheRequest() throws Exception {
        doReturn(TestSessionAnswer.failure(291, "ANSWER_OF_ACCOUNTS", "the handler's own answer")).when(handler).accounts(any());
        var result = mvc.perform(get("/bff/api/v1/auth/test-accounts").principal(signedIn)).andReturn();
        answered(result, 291, "ANSWER_OF_ACCOUNTS");
        verify(handler).accounts(request.capture());
        verifyNoMoreInteractions(handler);
        assertThat(request.getValue().getRequestURI()).isEqualTo("/bff/api/v1/auth/test-accounts");
    }

    @Test void theStatusRouteIsOneCallWithTheRequestAndWhoIsSignedIn() throws Exception {
        doReturn(TestSessionAnswer.failure(292, "ANSWER_OF_STATUS", "the handler's own answer")).when(handler).status(any(), any());
        answered(mvc.perform(get("/bff/api/v1/auth/test-session").principal(signedIn)).andReturn(), 292, "ANSWER_OF_STATUS");
        verify(handler).status(request.capture(), ArgumentMatchers.same(signedIn));
        verifyNoMoreInteractions(handler);
        assertThat(request.getValue().getRequestURI()).isEqualTo("/bff/api/v1/auth/test-session");
        // Signed out: the route hands over that nobody is signed in.
        reset(handler);
        doReturn(TestSessionAnswer.failure(292, "ANSWER_OF_STATUS", "the handler's own answer")).when(handler).status(any(), isNull());
        answered(mvc.perform(get("/bff/api/v1/auth/test-session")).andReturn(), 292, "ANSWER_OF_STATUS");
        verify(handler).status(any(), isNull());
    }

    @Test void theStartRouteIsOneCallWithTheBodyReadFromJsonOrNoBodyAtAll() throws Exception {
        doReturn(TestSessionAnswer.failure(293, "ANSWER_OF_START", "the handler's own answer")).when(handler).start(any(), any(), any(), any());
        var result = mvc.perform(post("/bff/api/v1/auth/test-session").principal(signedIn).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\"" + LEARNER + "\"}")).andReturn();
        answered(result, 293, "ANSWER_OF_START");
        var body = ArgumentCaptor.forClass(TestSessionStart.class);
        verify(handler).start(body.capture(), request.capture(), response.capture(), ArgumentMatchers.same(signedIn));
        verifyNoMoreInteractions(handler);
        // The browser's JSON binds as before: the one field is accountId.
        assertThat(body.getValue()).isEqualTo(new TestSessionStart(LEARNER));
        assertThat(request.getValue().getRequestURI()).isEqualTo("/bff/api/v1/auth/test-session");
        // Spring MVC hands in the response inside its own wrapper.
        assertThat(WebUtils.getNativeResponse(response.getValue(), MockHttpServletResponse.class)).isSameAs(result.getResponse());
        // The body is not required: without one the handler receives none and answers for itself.
        reset(handler);
        doReturn(TestSessionAnswer.failure(293, "ANSWER_OF_START", "the handler's own answer")).when(handler).start(isNull(), any(), any(), isNull());
        answered(mvc.perform(post("/bff/api/v1/auth/test-session").contentType(MediaType.APPLICATION_JSON)).andReturn(), 293, "ANSWER_OF_START");
        verify(handler).start(isNull(), any(), any(), isNull());
        // A field the record does not have is ignored, a missing one is null: the handler decides what that means.
        reset(handler);
        doReturn(TestSessionAnswer.failure(293, "ANSWER_OF_START", "the handler's own answer")).when(handler).start(any(), any(), any(), any());
        mvc.perform(post("/bff/api/v1/auth/test-session").contentType(MediaType.APPLICATION_JSON).content("{\"other\":1}")).andReturn();
        verify(handler).start(body.capture(), any(), any(), isNull());
        assertThat(body.getValue()).isEqualTo(new TestSessionStart(null));
    }

    @Test void theEndRouteIsOneCallWithTheRequestTheResponseAndWhoIsSignedIn() throws Exception {
        doReturn(TestSessionAnswer.failure(294, "ANSWER_OF_END", "the handler's own answer")).when(handler).end(any(), any(), any());
        var result = mvc.perform(post("/bff/api/v1/auth/test-session/end").principal(signedIn)).andReturn();
        answered(result, 294, "ANSWER_OF_END");
        verify(handler).end(request.capture(), response.capture(), ArgumentMatchers.same(signedIn));
        verifyNoMoreInteractions(handler);
        assertThat(request.getValue().getRequestURI()).isEqualTo("/bff/api/v1/auth/test-session/end");
        assertThat(WebUtils.getNativeResponse(response.getValue(), MockHttpServletResponse.class)).isSameAs(result.getResponse());
    }

    @Test void theFourRoutesAnswerTheirOwnMethodsAndNoOtherPath() throws Exception {
        assertThat(mvc.perform(post("/bff/api/v1/auth/test-accounts")).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(put("/bff/api/v1/auth/test-session").contentType(MediaType.APPLICATION_JSON).content("{}")).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(get("/bff/api/v1/auth/test-session/end")).andReturn().getResponse().getStatus()).isEqualTo(405);
        assertThat(mvc.perform(post("/bff/api/v1/auth/test-session/start")).andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(mvc.perform(get("/bff/api/v1/auth/test-sessions")).andReturn().getResponse().getStatus()).isEqualTo(404);
        verifyNoInteractions(handler);
    }
}
