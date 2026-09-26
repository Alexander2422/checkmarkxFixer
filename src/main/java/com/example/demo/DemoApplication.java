package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Step 2 of the walkthrough: to switch ActiveMQ off without touching the pom, use
// @SpringBootApplication(exclude = org.springframework.boot.autoconfigure.jms.activemq.ActiveMQAutoConfiguration.class)
@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
