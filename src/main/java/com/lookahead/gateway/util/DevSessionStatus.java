package com.lookahead.gateway.util;

import java.util.Map;
import org.springframework.http.ResponseEntity;

/**
 * What the DEV session status route tells the Web shell: the deadline as the operations table holds it (empty when none is
 * set), whether the warning before the deadline is on, and whether an operation is running.
 */
public record DevSessionStatus(String deadline, boolean warning, boolean maintenance) {
    /** The route's answer for {@code status}; for null (the status cannot be given: the store logged why) a 503. */
    public static ResponseEntity<Map<String,Object>> answer(DevSessionStatus status){
        if(status==null)return ResponseEntity.status(503).header("Cache-Control","no-store").body(Map.of("code","DEV_STATUS_UNAVAILABLE"));
        return ResponseEntity.ok().header("Cache-Control","no-store").body(Map.of("dev",true,"deadline",status.deadline(),"warning",status.warning(),"maintenance",status.maintenance()));
    }
}
