package com.lookahead.learning.content.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.springframework.test.web.client.ExpectedCount.manyTimes;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** Existing CSRF/frame tests retain real security filters with a bounded active-sign-in upstream fixture. */
@Configuration
class ActiveSignInTestConfiguration {
    final java.util.concurrent.atomic.AtomicInteger status = new java.util.concurrent.atomic.AtomicInteger(200);
    @Bean @Primary RestClient activeSignInHttp() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(manyTimes(), requestTo("http://domain-api:8080/api/v1/auth/me"))
                .andRespond(request -> org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.valueOf(status.get())).body("{}")
                        .contentType(MediaType.APPLICATION_JSON).createResponse(request));
        return builder.build();
    }
}
