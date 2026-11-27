package com.lookahead.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.lookahead.gateway.controller.DevSessionStatusController;
import com.lookahead.gateway.db.store.DevSessionStore;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;

/** DLV-1015: the DynamoDB connection of the DEV session status is one bean, read through by the store and closed by Spring. */
class DevSessionConfigurationTest {
    private static AnnotationConfigApplicationContext context(String... profiles) {
        var context = new AnnotationConfigApplicationContext();
        context.getEnvironment().setActiveProfiles(profiles);
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test",
                Map.of("app.dev-session.table", "synthetic-operations", "app.dev-session.region", "us-east-2")));
        context.register(DevSessionConfiguration.class, DevSessionStatusController.class);
        context.refresh();
        return context;
    }

    @Test @SuppressWarnings("unchecked")
    void theSdkClientIsOneBeanTheRouteReadsThroughItAndTheContextClosesItExactlyOnce() {
        var sdk = mock(DynamoDbClient.class);
        when(sdk.getItem(any(Consumer.class))).thenReturn(GetItemResponse.builder().item(Map.of()).build());
        var builder = mock(DynamoDbClientBuilder.class, Answers.RETURNS_SELF);
        when(builder.build()).thenReturn(sdk);
        try (var statics = mockStatic(DynamoDbClient.class)) {
            statics.when(DynamoDbClient::builder).thenReturn(builder);
            var context = context("lower-cost-dev");
            assertThat(context.getBeansOfType(DynamoDbClient.class)).containsOnlyKeys("devSessionDynamoDb");
            assertThat(context.getBean("devSessionDynamoDb")).isSameAs(sdk);
            verify(builder).region(Region.US_EAST_2);
            var store = context.getBean("devSessionStore", DevSessionStore.class);
            assertThat(ReflectionTestUtils.getField(store, "client")).isSameAs(sdk);
            assertThat(ReflectionTestUtils.getField(store, "table")).isEqualTo("synthetic-operations");
            assertThat(context.getBean(DevSessionStatusController.class).status().getStatusCode().value()).isEqualTo(200);
            verify(sdk, times(1)).getItem(any(Consumer.class));
            verify(sdk, never()).close();
            context.close();
            // Closed once, not once per bean that holds it (DLV-1015; before, the route closed it through the store).
            verify(sdk, times(1)).close();
        }
    }

    @Test void nothingIsBuiltOutsideTheDevProfile() {
        try (var statics = mockStatic(DynamoDbClient.class)) {
            try (var context = context("gateway")) {
                assertThat(context.getBeansOfType(DynamoDbClient.class)).isEmpty();
                assertThat(context.getBeansOfType(DevSessionStore.class)).isEmpty();
                assertThat(context.getBeansOfType(DevSessionStatusController.class)).isEmpty();
            }
            statics.verifyNoInteractions();
        }
    }
}
