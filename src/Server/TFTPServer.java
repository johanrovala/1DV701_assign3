package Server;


import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TFTPServer {
    public static final int TFTPPORT = 4970;
    public static final int BUFSIZE = 516;
    public static final String READDIR = "src/read/";
    public static final String WRITEDIR = "/Users/johanrovala/IdeaProjects/NetworkAssign3/src/write";
    public static final int OP_RRQ = 1;
    public static final int OP_WRQ = 2;
    public static final int OP_DAT = 3;
    public static final int OP_ACK = 4;
    public static final int OP_ERR = 5;

    public static void main(String[] args) {
        if (args.length > 0) {
            System.err.printf("usage: java %s\n", TFTPServer.class.getCanonicalName());
            System.exit(1);
        }
        try {
            TFTPServer server= new TFTPServer();
            server.start();
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private void start() throws IOException {
        byte[] buf= new byte[BUFSIZE];

		/* Create socket */
        DatagramSocket socket= new DatagramSocket(null);

		/* Create local bind point */
        SocketAddress localBindPoint= new InetSocketAddress(TFTPPORT);
        socket.bind(localBindPoint);

        System.out.printf("Listening at port %d for new requests\n", TFTPPORT);

        while(true) {        /* Loop to handle various requests */

            final InetSocketAddress clientAddress=
                    receiveFrom(socket, buf);
            if (clientAddress == null) /* If clientAddress is null, an error occurred in receiveFrom()*/
                continue;

            final StringBuffer requestedFile= new StringBuffer();
            final int reqtype = ParseRQ(buf, requestedFile);
            System.out.println("Requested file : " + requestedFile.toString());
            System.out.println("OPCODE: " + reqtype);

            new Thread() {
                public void run() {
                    try {
                        DatagramSocket sendSocket= new DatagramSocket(0);

                        System.out.printf("%s request from %s using port %d\n",
                                (reqtype == OP_RRQ)?"Read":"Write",
                                clientAddress.getHostName(), clientAddress.getPort());

                        if (reqtype == OP_RRQ) {      /* read request */
                            requestedFile.insert(0, READDIR);
                            HandleRQ(sendSocket, requestedFile.toString(), OP_RRQ);
                        }
                        else {                       /* write request */
                            requestedFile.insert(0, WRITEDIR);
                            HandleRQ(sendSocket,requestedFile.toString(),OP_WRQ);
                        }
                        sendSocket.close();
                    } catch (SocketException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        }
    }
    /**
     * Reads the first block of data, i.e., the request for action (read or write).
     * @param socket socket to read from
     * @param buf where to store the read data
     * @return the Internet socket address of the client
     */

    private InetSocketAddress receiveFrom(DatagramSocket socket, byte[] buf) throws IOException {
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);
        InetSocketAddress inet = new InetSocketAddress(packet.getAddress(), packet.getPort());
        return inet;
    }

    private int ParseRQ(byte[] buf, StringBuffer requestedFile) {
        ByteBuffer wrap = ByteBuffer.wrap(buf);
        short OPCODE = wrap.getShort();
        requestedFile.append(new String(buf, 2, buf.length-2));
        return OPCODE;
    }

    /*
     * Splitta strängen så vi får ut filename, opcode och mode.
     */

    private void HandleRQ(DatagramSocket sendSocket, String string, int opRrq) throws IOException {
        String[] args = string.split("\0");
        String fileName = args[0];
        String mode = args[1];
        short opVal = (short) opRrq;
        byte[] respSize = new byte[BUFSIZE];
        System.out.println(respSize.length);
        byte[] respData = Files.readAllBytes(Paths.get(fileName));
        System.out.println(respData.length);

        DatagramPacket sendPacket = new DatagramPacket(respData, respSize.length);
        System.out.println(sendPacket.getAddress());
        System.out.println(sendPacket.getPort());
        sendSocket.connect(sendPacket.getAddress(), sendPacket.getPort());
        sendSocket.send(sendPacket);
    }
}
