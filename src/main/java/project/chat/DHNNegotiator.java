package project.chat;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

public class DHNNegotiator<U extends Comparable> {
    private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    List<U> userList;
    U me;

    int myRank;
    U myPeer;

    DHNSend sender;
    DHNReceive receiver;

    DHNNegotiator(U me, List<U> users, DHNSend sender, DHNReceive receiver){
        this.me = me;
        userList = users;
        userList.sort(Comparator.naturalOrder());
        myRank = userList.indexOf(me);
        myPeer = userList.get( (myRank<userList.size()-1)?myRank+1:0 );

        this.sender = sender;
        this.receiver = receiver;
    }
    public boolean amMainUser(){return myRank == 0;}
    public byte[] negotiate(boolean waitForMainUser) throws Exception {
        DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(dhParams, new SecureRandom());
        // The same discussion as before with this fixed random ...

        // set up
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();

        keyAgree.init(aPair.getPrivate());

        Key myKey = aPair.getPublic();

        System.out.println("Me:"+me+"("+myRank+") Peer:"+myPeer);

        boolean ended = false;
        boolean hasSentFirstKey = false;

        //send my key to peer (next on list)
        if(myRank == 0 || !waitForMainUser){
            byte[] data = makeNegotiationMessage(me, keyToBytes(myKey));
            sender.send(data, myPeer);
            System.out.println("Sending public key. (as host)");
            hasSentFirstKey = true;
        }

        Key interkey;
        while(!ended){
            byte[] rdata = receiver.receive();
            NMessage nm = readNegotiationMessage(rdata);

            if(!hasSentFirstKey){
                byte[] data = makeNegotiationMessage(me, keyToBytes(myKey));
                System.out.println("Sending public key.");
                sender.send(data, myPeer);
                hasSentFirstKey = true;
            }

            if(nm.id.compareTo(myPeer) == 0)ended = true;
            System.out.println("Received key ("+nm.id+") and is "+(ended?"final":"not final"));
            interkey = keyAgree.doPhase(bytesToKey(nm.key), ended);

            if(!ended){
                byte[] data = makeNegotiationMessage(nm.id, keyToBytes(interkey));
                sender.send(data, myPeer);
            }
        }

        byte[] secret = keyAgree.generateSecret();
        System.out.println("Finished: "+javax.xml.bind.DatatypeConverter.printHexBinary(secret));
        return secret;
    }

    class NMessage{
        U id;
        byte[] key;
    }

    private byte[] makeNegotiationMessage(U id, byte[] key) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutputStream osw = new ObjectOutputStream(os);
        osw.writeObject(id);
        osw.writeInt(key.length);
        osw.write(key);
        osw.close();
        byte[] data = os.toByteArray();
        return data;
    }

    private NMessage readNegotiationMessage(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream is = new ByteArrayInputStream(data);
        ObjectInputStream isr = new ObjectInputStream(is);
        NMessage nm = new NMessage();
        nm.id = (U)isr.readObject();
        int keyLen = isr.readInt();
        nm.key = new byte[keyLen];
        isr.read(nm.key);
        isr.close();
        return nm;
    }

    private static byte[] keyToBytes(Key k) throws IOException {
        return k.getEncoded();
    }
    private static Key bytesToKey(byte[] k) throws IOException, ClassNotFoundException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH","BC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(k);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    public interface DHNSend<U>{abstract public void send(byte[] data, U to) throws Exception;}
    public interface DHNReceive{abstract public byte[] receive() throws Exception;}

    ///TEST
    public static void main(String[] args){
        try {
            int users[] = {22000};

            LinkedList<Integer> userList = new LinkedList<Integer>();
            for(int i:users)userList.add(i);

            DatagramSocket socket = new DatagramSocket(new Integer(args[0]));

            DHNNegotiator<Integer> test = new DHNNegotiator<Integer>(new Integer(args[0]), userList, (data, u)->{
                Integer peer = (Integer) u;
                DatagramPacket npack = new DatagramPacket(data, data.length, InetAddress.getLocalHost(), peer);
                socket.send(npack);
            }, ()->{
                byte[] rdata = new byte[30000];
                DatagramPacket p = new DatagramPacket(rdata, rdata.length);
                socket.receive(p);
                return rdata;
            });
            test.negotiate(true);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }


}
