package com.dns;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DnsApp {

    public static void main(String[] args) {
        SpringApplication.run(DnsApp.class, args);
    }

    // Starts the DNS listener on its own thread once Spring has fully booted,
    // so it doesn't block the main app / web server thread
    @Bean
    public CommandLineRunner startDnsServer(@Autowired DNSServer dnsServer) {
        return args -> new Thread(() -> {
            try {
                dnsServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}
