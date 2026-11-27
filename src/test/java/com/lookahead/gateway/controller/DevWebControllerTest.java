package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.DevWebProxy;
import com.lookahead.gateway.util.DevServiceOrigins;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.*;
import org.springframework.web.client.RestClient;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** The fallback route of the DEV profile that serves the static Web: driven through the route; the forwarder itself is in DevWebProxyTest. */
class DevWebControllerTest {
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    MockEnvironment upstreams(){return new MockEnvironment().withProperty("app.oauth.domain-api-upstream","https://domain.lookahead-dev.internal:8443")
        .withProperty("app.gateway.web-upstream","https://web.lookahead-dev.internal:8443");}
    @Test void webProxyForwardsNoBrowserCredentialsOrQueries() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
            .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("Cookie"))
            .andRespond(withSuccess("<html>shell</html>",MediaType.TEXT_HTML));
        var request=new MockHttpServletRequest("GET","/learn");request.setQueryString("token=private");request.addHeader("Authorization","Bearer private");request.addHeader("Cookie","session=private");
        var result=new DevWebController(new DevWebProxy(builder.build(),DevServiceOrigins.from(upstreams()))).get(request);assertEquals(200,result.getStatusCode().value());assertEquals("no-store",result.getHeaders().getCacheControl());server.verify();
    }
    @Test void webProxyRefusesRedirectAndReservedRoutes() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn")).andRespond(withStatus(HttpStatus.FOUND).header("Location","https://elsewhere.example"));
        var proxy=new DevWebController(new DevWebProxy(builder.build(),DevServiceOrigins.from(upstreams())));assertEquals(502,proxy.get(new MockHttpServletRequest("GET","/learn")).getStatusCode().value());
        assertEquals(404,proxy.get(new MockHttpServletRequest("GET","/content/private")).getStatusCode().value());server.verify();
    }
}
