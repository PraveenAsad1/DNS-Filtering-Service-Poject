package com.dns;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.xbill.DNS.*;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

@Service
public class DNSServer {

    private static final int LISTEN_PORT = 1053;
    private static final String UPSTREAM_DNS = "8.8.8.8";
    private static final int UPSTREAM_PORT = 53;
    private static final int BUFFER_SIZE = 512;
    private static final int SINKHOLE_TTL = 300;

    @Value("${dns.filter.threat-threshold}")
    double threatThreshold;

    @Autowired
    private MLClient mlClient;

    @Autowired
    private QueryLogRepository queryLogRepository;

    // package-private (not private) so DNSServerTest can reference it directly
    static final List<String> BLOCKLIST = Arrays.asList(
            "badguy.com",
            "malware.example.com",
            "phishing-test.com"
    );

    public void start() throws Exception {
        DatagramSocket serverSocket = new DatagramSocket(LISTEN_PORT);
        System.out.println("DNS Server listening on UDP port " + LISTEN_PORT);

        byte[] receiveBuffer = new byte[BUFFER_SIZE];

        while (true) {
            DatagramPacket requestPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            serverSocket.receive(requestPacket);

            byte[] requestData = requestPacket.getData().clone();
            InetAddress clientAddress = requestPacket.getAddress();
            int clientPort = requestPacket.getPort();

            new Thread(() -> handleQuery(serverSocket, requestData, clientAddress, clientPort)).start();
        }
    }

    private void handleQuery(DatagramSocket serverSocket, byte[] requestData,
                              InetAddress clientAddress, int clientPort) {
        try {
            Message query = new Message(requestData);
            String rawDomain = query.getQuestion().getName().toString();
            String cleanDomain = cleanDomain(rawDomain);

            System.out.println("Query received for: " + cleanDomain);

            byte[] responseData;
            boolean blocked;
            double score = 0.0;
            String blockReason = null;

            if (isBlocklisted(cleanDomain)) {
                System.out.println("BLOCKED (blocklist): " + cleanDomain);
                responseData = buildSinkholeResponse(query);
                blocked = true;
                blockReason = "blocklist";

            } else {
                score = mlClient.analyzeDomain(cleanDomain);
                System.out.println("Heuristic score for " + cleanDomain + ": " + score);

                if (isAboveThreshold(score)) {
                    System.out.println("BLOCKED (heuristic score): " + cleanDomain);
                    responseData = buildSinkholeResponse(query);
                    blocked = true;
                    blockReason = "heuristic";
                } else {
                    responseData = forwardToUpstream(requestData);
                    blocked = false;
                }
            }

            queryLogRepository.save(new QueryLog(cleanDomain, blocked, score, blockReason));

            DatagramPacket responsePacket = new DatagramPacket(
                    responseData, responseData.length, clientAddress, clientPort
            );
            serverSocket.send(responsePacket);

        } catch (Exception e) {
            System.err.println("Error handling query: " + e.getMessage());
        }
    }

    // ---- Pure logic, extracted for unit testing (no I/O, deterministic) ----

    // dnsjava keeps the trailing dot (e.g. "badguy.com.") — strip it and lowercase for clean comparison
    static String cleanDomain(String rawDomain) {
        return rawDomain.replaceAll("\\.$", "").toLowerCase();
    }

    static boolean isBlocklisted(String cleanDomain) {
        return BLOCKLIST.contains(cleanDomain);
    }

    boolean isAboveThreshold(double score) {
        return score > threatThreshold;
    }

    // Builds a fake DNS response pointing the queried domain to 0.0.0.0
    byte[] buildSinkholeResponse(Message query) throws Exception {
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setFlag(Flags.RA);
        response.addRecord(query.getQuestion(), Section.QUESTION);

        Name queriedName = query.getQuestion().getName();
        ARecord sinkholeRecord = new ARecord(
                queriedName,
                DClass.IN,
                SINKHOLE_TTL,
                InetAddress.getByName("0.0.0.0")
        );
        response.addRecord(sinkholeRecord, Section.ANSWER);

        return response.toWire();
    }

    // ---- I/O ----

    private byte[] forwardToUpstream(byte[] queryData) throws Exception {
        DatagramSocket upstreamSocket = new DatagramSocket();
        InetAddress upstreamAddress = InetAddress.getByName(UPSTREAM_DNS);

        DatagramPacket upstreamRequest = new DatagramPacket(
                queryData, queryData.length, upstreamAddress, UPSTREAM_PORT
        );
        upstreamSocket.send(upstreamRequest);

        byte[] responseBuffer = new byte[BUFFER_SIZE];
        DatagramPacket upstreamResponse = new DatagramPacket(responseBuffer, responseBuffer.length);
        upstreamSocket.receive(upstreamResponse);

        upstreamSocket.close();

        byte[] result = new byte[upstreamResponse.getLength()];
        System.arraycopy(upstreamResponse.getData(), 0, result, 0, upstreamResponse.getLength());
        return result;
    }
}
