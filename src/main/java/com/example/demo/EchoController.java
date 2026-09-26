package com.example.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EchoController {
    private final ObjectMapper mapper = new ObjectMapper();

    // Parses user-supplied JSON with Jackson -> jackson-databind is really USED
    @PostMapping("/echo")
    public JsonNode echo(@RequestBody String body) throws Exception {
        return mapper.readTree(body);
    }
}
