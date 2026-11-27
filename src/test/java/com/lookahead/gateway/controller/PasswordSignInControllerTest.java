package com.lookahead.gateway.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.lookahead.gateway.security.handler.PasswordSignInHandler;
import com.lookahead.gateway.util.PasswordSignInAnswer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.WebUtils;

/**
 * DLV-1015: the controller holds the seven routes of our own sign-in and sign-up pages and nothing else. Each route,
 * reached through Spring MVC, is one call to its PasswordSignInHandler method with the request (and the response where
 * the route has it), and the handler's answer goes back unchanged. What the routes do is tested in
 * PasswordSignInHandlerTest; the security chain in front of them in the cloud integration tests.
 */
class PasswordSignInControllerTest {
    final PasswordSignInHandler handler = mock(PasswordSignInHandler.class);
    final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PasswordSignInController(handler)).build();

    /**
     * Each route's path, and the handler method behind it: called here to stub it, and again to verify it. The arguments
     * are asked for only where the method takes them, so a matcher is created for exactly the parameters it has.
     */
    interface Route { Object call(PasswordSignInHandler handler, Supplier<HttpServletRequest> request, Supplier<HttpServletResponse> response); }

    static Map<String, Route> routes() {
        var routes = new LinkedHashMap<String, Route>();
        routes.put("/sign-in", (handler, request, response) -> handler.signIn(request.get(), response.get()));
        routes.put("/challenge", (handler, request, response) -> handler.challenge(request.get(), response.get()));
        routes.put("/sign-up", (handler, request, response) -> handler.signUp(request.get()));
        routes.put("/sign-up/confirm", (handler, request, response) -> handler.confirm(request.get()));
        routes.put("/sign-up/resend", (handler, request, response) -> handler.resend(request.get()));
        routes.put("/password/forgot", (handler, request, response) -> handler.forgot(request.get()));
        routes.put("/password/reset", (handler, request, response) -> handler.reset(request.get(), response.get()));
        return routes;
    }

    @Test void eachRouteIsOneCallToItsHandlerMethodAndItsAnswerGoesBackUnchanged() throws Exception {
        int status = 290;
        for (var route : routes().entrySet()) {
            String path = "/bff/api/v1/auth/password" + route.getKey(), code = "ANSWER_OF_" + route.getKey();
            var answer = PasswordSignInAnswer.failure(++status, code);
            route.getValue().call(doReturn(answer).when(handler), () -> any(), () -> any());
            var result = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"priya@example.invalid\"}")).andReturn();
            assertThat(result.getResponse().getStatus()).as(path).isEqualTo(status);
            assertThat(result.getResponse().getHeaderValues("Cache-Control")).isEqualTo(List.of("no-store"));
            assertThat(result.getResponse().getContentAsString()).isEqualTo("{\"code\":\"" + code + "\"}");
            // The one call: this route's method and no other, with the request and the response Spring MVC handed in.
            var request = ArgumentCaptor.forClass(HttpServletRequest.class);
            var response = ArgumentCaptor.forClass(HttpServletResponse.class);
            route.getValue().call(verify(handler), request::capture, response::capture);
            verifyNoMoreInteractions(handler);
            assertThat(request.getValue().getRequestURI()).isEqualTo(path);
            assertThat(new String(request.getValue().getInputStream().readAllBytes())).isEqualTo("{\"email\":\"priya@example.invalid\"}");
            // Spring MVC hands in the response inside its own wrapper.
            if (!response.getAllValues().isEmpty())
                assertThat(WebUtils.getNativeResponse(response.getValue(), MockHttpServletResponse.class)).isSameAs(result.getResponse());
            assertThat(response.getAllValues()).hasSize(List.of("/sign-in", "/challenge", "/password/reset").contains(route.getKey()) ? 1 : 0);
            Mockito.reset(handler);
        }
        assertThat(status).isEqualTo(297);
    }

    @Test void theRoutesAnswerPostOnlyAndNoOtherPath() throws Exception {
        for (String route : routes().keySet())
            assertThat(mvc.perform(get("/bff/api/v1/auth/password" + route)).andReturn().getResponse().getStatus()).as(route).isEqualTo(405);
        assertThat(mvc.perform(post("/bff/api/v1/auth/password")).andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(mvc.perform(post("/bff/api/v1/auth/password/sign-out")).andReturn().getResponse().getStatus()).isEqualTo(404);
        verifyNoInteractions(handler);
    }
}
