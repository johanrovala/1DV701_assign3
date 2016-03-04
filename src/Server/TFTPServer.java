package Server;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.Channels;
import java.nio.channels.DatagramChannel;
import java.nio.channels.WritableByteChannel;
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
    public static InetSocketAddress clientAddress;

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

            clientAddress=
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
                        sendSocket.connect(clientAddress);

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
        byte[] buf = new byte[BUFSIZE-4];
        int blockNumber = 1;
        FileInputStream fileInputStream = new FileInputStream(new File(fileName));
        System.out.println(mode);
        if(!mode.equals("octet")){
            SendError(sendSocket, buf);
        }

        while(!ReadRQ(sendSocket, buf, blockNumber, fileInputStream)){
            blockNumber++;
        }
    }

    // just nu så funkar inte acknowledgement packet. Vi får samma problem som tidigare att
    // samma packet skickas allt för många gånger dvs chapter 11.
    // när vi får transfer timed out så får vi ut sout-komm i ReadRQ. 

    private boolean ReadRQ(DatagramSocket sendSocket, byte[] buf, int blockNumber, FileInputStream fileInputStream) throws IOException {
        int length = fileInputStream.read(buf);

        ByteBuffer wrap = ByteBuffer.allocate(BUFSIZE);
        wrap.putShort((short) 3);
        wrap.putShort((short) blockNumber );
        wrap.put(buf);

        DatagramPacket data = new DatagramPacket(wrap.array(), wrap.array().length);

        sendSocket.send(data);
        byte[] rec = new byte[BUFSIZE];
        DatagramPacket receiveSocket = new DatagramPacket(rec, rec.length);
        short comp = getAcknowledgment(receiveSocket);
        if(comp == (short) blockNumber){
            System.out.println("comp = blockNumber");
            return length < 512;
        }
        return false;
    }

    private short getAcknowledgment(DatagramPacket packet){
        ByteBuffer buffer = ByteBuffer.wrap(packet.getData());
        if(buffer.getShort() == OP_ERR){
            System.out.println("MADDAFACKA");
            return -1;
        }
        return buffer.getShort();
    }

    private void SendError(DatagramSocket sendSocket, byte[] buf) throws IOException {
        ByteBuffer wrap = ByteBuffer.allocate(BUFSIZE);
        wrap.putShort((short) 5);
        wrap.putShort((short) 4);
        buf = new String("Invalid mode").getBytes();
        wrap.put(buf);

        DatagramPacket errorPacket = new DatagramPacket(wrap.array(), wrap.array().length);
        sendSocket.send(errorPacket);
    }
}
