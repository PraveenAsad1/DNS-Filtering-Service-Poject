package com.dns;

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
    private static final int SINKHOLE_TTL = 300; // how long (seconds) clients should cache the fake answer

    // Hardcoded blocklist for now — Phase 2 first pass.
    // Later this could come from a file or a real threat-feed source.
    private static final List<String> BLOCKLIST = Arrays.asList(
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
            String domain = query.getQuestion().getName().toString();
            // dnsjava keeps the trailing dot (e.g. "badguy.com.") — strip it for clean comparison
            String cleanDomain = domain.replaceAll("\\.$", "").toLowerCase();

            System.out.println("Query received for: " + cleanDomain);

            byte[] responseData;

            if (BLOCKLIST.contains(cleanDomain)) {
                System.out.println("BLOCKED: " + cleanDomain);
                responseData = buildSinkholeResponse(query);
            } else {
                responseData = forwardToUpstream(requestData);
            }

            DatagramPacket responsePacket = new DatagramPacket(
                    responseData, responseData.length, clientAddress, clientPort
            );
            serverSocket.send(responsePacket);

        } catch (Exception e) {
            System.err.println("Error handling query: " + e.getMessage());
        }
    }

    // Builds a fake DNS response pointing the blocked domain to 0.0.0.0
    private byte[] buildSinkholeResponse(Message query) throws Exception {
        Message response = new Message(query.getHeader().getID()); // same query ID as the request
        response.getHeader().setFlag(Flags.QR); // mark this as a response, not a query
        response.getHeader().setFlag(Flags.RA); // recursion available (matches normal DNS server behavior)
        response.addRecord(query.getQuestion(), Section.QUESTION); // echo back the original question

        // Build the "answer": this domain name -> 0.0.0.0
        Name queriedName = query.getQuestion().getName();
        ARecord sinkholeRecord = new ARecord(
                queriedName,
                DClass.IN,
                SINKHOLE_TTL,
                InetAddress.getByName("0.0.0.0")
        );
        response.addRecord(sinkholeRecord, Section.ANSWER);

        return response.toWire(); // serialize back to raw bytes to send over UDP
    }

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
