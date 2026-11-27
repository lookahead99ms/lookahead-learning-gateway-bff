package com.lookahead.gateway.config;

import com.lookahead.gateway.db.store.DevSessionStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/** The DynamoDB connection of the DEV session status and the store that reads through it. */
@Configuration
@Profile("lower-cost-dev")
public class DevSessionConfiguration {
    @Bean DevSessionStore devSessionStore(Environment env){
        var table=env.getRequiredProperty("app.dev-session.table");
        return new DevSessionStore(devSessionDynamoDb(env),table);
    }
    /** The SDK client. Spring closes it when the application stops: it is the only bean here with something to close. */
    @Bean DynamoDbClient devSessionDynamoDb(Environment env){
        return DevSessionStore.configured(DynamoDbClient.builder().region(Region.of(env.getRequiredProperty("app.dev-session.region")))
            .credentialsProvider(ContainerCredentialsProvider.builder().build())).build();
    }
}
