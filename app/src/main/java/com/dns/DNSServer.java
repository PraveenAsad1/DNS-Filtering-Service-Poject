package com.dns;

import org.springframework.stereotype.Service;
import org.xbill.DNS.Message;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

@Service
public class DNSServer {

    private static final int LISTEN_PORT = 1053;       // port we listen for DNS queries on
    private static final String UPSTREAM_DNS = "8.8.8.8"; // Google DNS, used for forwarding
    private static final int UPSTREAM_PORT = 53;         // standard DNS port
    private static final int BUFFER_SIZE = 512;          // standard max size for a DNS UDP message

    // Opens the UDP socket and loops forever, waiting for incoming DNS queries
    public void start() throws Exception {
        DatagramSocket serverSocket = new DatagramSocket(LISTEN_PORT);
        System.out.println("DNS Server listening on UDP port " + LISTEN_PORT);

        byte[] receiveBuffer = new byte[BUFFER_SIZE];

        while (true) {
            DatagramPacket requestPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            serverSocket.receive(requestPacket); // blocks here until a query arrives

            // copy the data out before handing off to a new thread,
            // since receiveBuffer gets reused on the next loop iteration
            byte[] requestData = requestPacket.getData().clone();
            InetAddress clientAddress = requestPacket.getAddress();
            int clientPort = requestPacket.getPort();

            // handle each query on its own thread so one slow lookup doesn't block others
            new Thread(() -> handleQuery(serverSocket, requestData, clientAddress, clientPort)).start();
        }
    }

    // Parses the query, forwards it upstream, and relays the response back to the client
    private void handleQuery(DatagramSocket serverSocket, byte[] requestData,
                              InetAddress clientAddress, int clientPort) {
        try {
            Message query = new Message(requestData); // dnsjava parses raw bytes into a structured object
            String domain = query.getQuestion().getName().toString();
            System.out.println("Query received for: " + domain);

            byte[] responseData = forwardToUpstream(requestData);

            // UDP has no persistent connection, so we must explicitly send back
            // to the original client's address + port
            DatagramPacket responsePacket = new DatagramPacket(
                    responseData, responseData.length, clientAddress, clientPort
            );
            serverSocket.send(responsePacket);

        } catch (Exception e) {
            System.err.println("Error handling query: " + e.getMessage());
        }
    }

    // Sends the raw query to Google DNS and returns the raw response bytes
    private byte[] forwardToUpstream(byte[] queryData) throws Exception {
        DatagramSocket upstreamSocket = new DatagramSocket(); // separate socket just for talking upstream
        InetAddress upstreamAddress = InetAddress.getByName(UPSTREAM_DNS);

        DatagramPacket upstreamRequest = new DatagramPacket(
                queryData, queryData.length, upstreamAddress, UPSTREAM_PORT
        );
        upstreamSocket.send(upstreamRequest);

        byte[] responseBuffer = new byte[BUFFER_SIZE];
        DatagramPacket upstreamResponse = new DatagramPacket(responseBuffer, responseBuffer.length);
        upstreamSocket.receive(upstreamResponse); // blocks until Google DNS replies

        upstreamSocket.close();

        // trim the buffer down to the actual response length before returning
        byte[] result = new byte[upstreamResponse.getLength()];
        System.arraycopy(upstreamResponse.getData(), 0, result, 0, upstreamResponse.getLength());
        return result;
    }
}
