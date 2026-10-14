package com.lookahead.learning.content.gateway;
import java.time.*;
import java.util.*;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.env.Environment;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;

@RestController @Profile("lower-cost-dev")
public final class DevSessionStatus implements AutoCloseable {
    private final DynamoDbClient client;
    private final String table;
    @org.springframework.beans.factory.annotation.Autowired
    public DevSessionStatus(Environment env){
        table=env.getRequiredProperty("app.dev-session.table");
        client=DynamoDbClient.builder().region(software.amazon.awssdk.regions.Region.of(env.getRequiredProperty("app.admission.region")))
            .credentialsProvider(ContainerCredentialsProvider.builder().build())
            .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(2)).socketTimeout(Duration.ofSeconds(3)))
            .overrideConfiguration(c->c.apiCallTimeout(Duration.ofSeconds(4)).apiCallAttemptTimeout(Duration.ofSeconds(3))).build();
    }
    DevSessionStatus(DynamoDbClient client, String table) { this.client=client; this.table=table; }
    @GetMapping("/dev/session") ResponseEntity<Map<String,Object>> status(){
        try{
            var state=client.getItem(r->r.tableName(table).consistentRead(true).key(Map.of("id",AttributeValue.builder().s("dev").build()))).item();
            String deadline=state.containsKey("deadline")?state.get("deadline").s():"";
            boolean warning=!deadline.isEmpty()&&!Instant.now().isBefore(Instant.parse(deadline).minusSeconds(900));
            return ResponseEntity.ok().header("Cache-Control","no-store").body(Map.of("dev",true,"deadline",deadline,"warning",warning,"maintenance",state.containsKey("operation")));
        }catch(RuntimeException unavailable){return ResponseEntity.status(503).header("Cache-Control","no-store").body(Map.of("code","DEV_STATUS_UNAVAILABLE"));}
    }
    @Override public void close(){client.close();}
}
