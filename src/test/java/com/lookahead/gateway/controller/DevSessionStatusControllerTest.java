package com.lookahead.gateway.controller;

import com.lookahead.gateway.db.store.DevSessionStore;
import org.junit.jupiter.api.*;
import org.springframework.security.core.context.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** The DEV session status route: what it answers for a readable and for an unreadable row. The read and its log lines are in DevSessionStoreTest. */
class DevSessionStatusControllerTest {
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void unavailableStatusNeverInventsADeadline() {
        var client=mock(DynamoDbClient.class);
        doThrow(new IllegalStateException()).when(client).getItem(any(Consumer.class));
        var controller=new DevSessionStatusController(new DevSessionStore(client,"state"));assertEquals(503,controller.status().getStatusCode().value());
        // DLV-1015: the route no longer closes the SDK client; Spring does, exactly once (DevSessionConfigurationTest).
        verify(client,never()).close();
    }
    @Test void statusShowsWarningAndMaintenanceWithoutPrivateOperationId() {
        var client=mock(DynamoDbClient.class);
        var value=AttributeValue.builder().s(Instant.now().plusSeconds(60).toString()).build();
        doReturn(GetItemResponse.builder().item(Map.of("deadline",value,"operation",value)).build())
            .when(client).getItem(any(Consumer.class));
        var result=new DevSessionStatusController(new DevSessionStore(client,"state")).status();
        assertEquals(true,result.getBody().get("warning"));assertEquals(true,result.getBody().get("maintenance"));assertFalse(result.getBody().containsKey("operation"));
    }
}
