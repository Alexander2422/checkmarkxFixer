package com.example.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class EchoControllerTest {
    @Test
    void echoesJson() throws Exception {
        assertEquals("{\"a\":1}", new EchoController().echo("{\"a\":1}").toString());
    }
}
