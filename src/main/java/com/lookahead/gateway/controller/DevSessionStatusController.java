package com.lookahead.gateway.controller;

import com.lookahead.gateway.db.store.DevSessionStore;
import com.lookahead.gateway.util.DevSessionStatus;
import java.util.*;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("lower-cost-dev")
public final class DevSessionStatusController {
  private final DevSessionStore store;

  public DevSessionStatusController(DevSessionStore store) {
    this.store = store;
  }

  @GetMapping("/dev/session")
  public ResponseEntity<Map<String, Object>> status() {
    return DevSessionStatus.answer(store.status());
  }
}
