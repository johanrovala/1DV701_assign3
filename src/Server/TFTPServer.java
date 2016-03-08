package Server;


import java.io.*;
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
                        System.out.println("Connection established with " + clientAddress.getHostName() + " " + clientAddress.getPort());

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
                        System.out.println("Should close socket now");
                        sendSocket.close();
                    } catch (SocketException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (InterruptedException e) {
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

    /**
     * Parses the Request sent from the client and returns the Operation code.
     * @param buf
     * @param requestedFile
     * @return The Operation Code from requestedFile
     */


    private int ParseRQ(byte[] buf, StringBuffer requestedFile) {
        ByteBuffer wrap = ByteBuffer.wrap(buf);
        short OPCODE = wrap.getShort();
        requestedFile.append(new String(buf, 2, buf.length-2));
        return OPCODE;
    }

    /**
     * Reads the requested file and keeps sending it back to the client until
     * the last packet reaches a size smaller than 512.
     * @param sendSocket
     * @param string
     * @param opRrq
     * @throws IOException
     * @throws InterruptedException
     */

    private void HandleRQ(DatagramSocket sendSocket, String string, int opRrq) throws IOException, InterruptedException {
        String[] args = string.split("\0");
        String fileName = args[0];
        String mode = args[1];
        short opVal = (short) opRrq;
        byte[] buf = new byte[BUFSIZE-4];
        int blockNumber = 1;
        System.out.println(mode);

        if(!mode.equals("octet")){ SendError(sendSocket, buf);}
        if (opVal == 1){
            FileInputStream fileInputStream = new FileInputStream(new File(fileName));
            while(!ReadRQ(sendSocket, buf, blockNumber, fileInputStream)){ blockNumber++;}
        }
        else if (opVal == 1){
            FileOutputStream fileOutputStream = new FileOutputStream(string);
            WriteRQ(sendSocket, buf, blockNumber, fileOutputStream);
        }
        else{
            SendError(sendSocket, buf);
        }

    }

    private boolean WriteRQ(DatagramSocket receiveSocket, byte[] buf, int blockNumber, FileOutputStream fileOutputStream) throws IOException {
        fileOutputStream.write(buf);

        return true;
    }

    /**
     * Sends the Read Request back to the Client.
     * @param sendSocket
     * @param buf
     * @param blockNumber
     * @param fileInputStream
     * @return
     * @throws IOException
     * @throws InterruptedException
     */

    private boolean ReadRQ(DatagramSocket sendSocket, byte[] buf, int blockNumber, FileInputStream fileInputStream) throws IOException, InterruptedException {
        int length = fileInputStream.read(buf);

        ByteBuffer wrap = ByteBuffer.allocate(BUFSIZE);
        wrap.putShort((short) OP_DAT);
        wrap.putShort((short) blockNumber);
        wrap.put(buf);


        DatagramPacket data = new DatagramPacket(wrap.array(), wrap.array().length);

        sendSocket.send(data);
        byte[] rec = new byte[BUFSIZE];

        DatagramPacket receivePacket = new DatagramPacket(rec, rec.length);
        sendSocket.receive(receivePacket);
        short comp = getAcknowledgment(receivePacket);


        /*
         * Should retransmit if no acknowledgment packet is sent
         */

        while (comp == 0){
            Thread.sleep(1000);
            blockNumber--;
            System.out.println("No Acknowledgment packet trying to send again.");
            ReadRQ(sendSocket, buf, blockNumber, fileInputStream);
        }

        if(comp == (short) blockNumber){
            System.out.println("comp: " + comp + " block: " + blockNumber);
            System.out.println("Length of sent packet: " + length);
            return length < 512;
        }
        /*
         * Should retransmit if acknowledgment and blocknumber are not equal
         * add counter to make sure that
         */

        else {
            blockNumber--;
            ReadRQ(sendSocket, buf, blockNumber, fileInputStream);
        }
        return true;
    }

    /**
     * Gets the acknowlegdement packet from the client.
     * @param packet
     * @return short
     * @throws IOException
     */

    private short getAcknowledgment(DatagramPacket packet) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(packet.getData());
        if(buffer.getShort() == OP_ERR){
            System.out.println("Something went wrong");
            return -1;
        }
        System.out.println("Acknowledgment code: " + buffer.get(1));
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
