package project.chat;

// labs.MulticastChat.java
// Objecto que representa um chat Multicast

import project.config.GroupConfig;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;

public class MulticastChat extends Thread {


  // Identifica uma op. de JOIN ao chat multicast  //
  public static final int JOIN = 1;

  // Identifica uma op. de LEAVE do chat multicast  //
  public static final int LEAVE = 2;

  // Identifica uma op. de processamento de uma MENSAGEM normal //
  public static final int MESSAGE = 3;

  // Identifica uma op. de processamento de uma key do DH //
  public static final int DHKEY = 4;

  // Identifica uma op. de READY para o protocolo DH //
  public static final int DHREADY = 5;

  // N. Magico que funciona como Id unico do Chat
  public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

  // numero de milisegundos no teste de pooling de terminacao  //
  public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

  // Multicast socket used to send and receive multicast protocol PDUs
  // Socket Multicast usado para enviar e receber mensagens
  // no ambito das operacoes que tem lugar no Chat
  protected MulticastSocket msocket;

  // Username / User-Nick-Name do Chat
  protected String username;

  // Users list -- Must keep track of all users for DH key negotiation
  Set<String> users;

  // Grupo IP Multicast utilizado
  protected InetAddress group;

  // Listener de eventos enviados por Multicast
  protected MulticastChatEventListener listener;

  protected GroupConfig groupConfig;

  // Controlo  - thread de execucao

  protected boolean isActive;

  protected boolean inGroup = false;

  public MulticastChat(String username, InetAddress group, int port, int ttl, MulticastChatEventListener listener, GroupConfig groupConfig) throws IOException {

    this.username = username;
    this.group = group;
    this.listener = listener;
    this.groupConfig = groupConfig;
    isActive = true;

    users = new TreeSet<>();

    String path = group.getHostAddress().toString();
    // create & configure multicast socket
    try {
      msocket = new SecureMulticastSocket(port, groupConfig);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidParameterSpecException e) {
      e.printStackTrace();
    }
    msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
    msocket.setTimeToLive(ttl);
    msocket.joinGroup(group);

    // start receive thread and send multicast join message
    start();
    sendJoin();
  }

  /**
   * Request de terminacao assincrona da thread de execucao,
   * e envio de uma mensagem de LEAVE
   */

  public void terminate() throws IOException {
    isActive = false;
    sendLeave();
  }

  // Issues an error message
  protected void error(String message) {
    System.err.println(new java.util.Date() + ": labs.MulticastChat: "
                       + message);
  }

  // Envio de mensagem na op. de JOIN
  //
  protected void sendJoin() throws IOException {
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(JOIN);
    dataStream.writeUTF(username);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
    ((SecureMulticastSocket)msocket).sendWithKnownEncryption(packet);
  }

  // Processamento de um JOIN ao grupo multicast com notificacao
  //
  protected void processJoin(DataInputStream istream, InetAddress address, int port) throws IOException {
    String name = istream.readUTF();

    try {
      if(!users.contains(name)){
        //new user wants to join
        users.add(name);
        listener.chatParticipantJoined(name, address, port);
        if(inGroup){
          //re broadcast my ID to new chat members
          //old members will ignore
          sendJoin();
        }
        System.out.println(">> Updating user list.");
        recieveCurrentUsers();
        System.out.println(">> Updating user list. [  DONE  ]");
        negotiateKey();
      }

    } catch (Throwable e) {
      e.printStackTrace();
    }
    inGroup = true;
  }

  void recieveCurrentUsers() throws SocketException {
    byte[] buffer = new byte[65536];
    int oldTimeout = msocket.getSoTimeout();
    msocket.setSoTimeout(200);
    try {
      while (true) {
        try {
          DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
          msocket.receive(packet);
          DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));

          long magic = istream.readLong();
          if (magic != CHAT_MAGIC_NUMBER) {
            continue;
          }
          int opCode = istream.readInt();
          switch (opCode) {
            case JOIN:
              String name = istream.readUTF();
              users.add(name);
              break;
            default:
              error("(Updating Users)Cod de operacao desconhecido " + opCode + " enviado de "
                      + packet.getAddress() + ":" + packet.getPort());
          }

        } catch (InterruptedIOException e) {
          break;
        } catch (Throwable e) {
          e.printStackTrace();
        }
      }
    }finally {
      msocket.setSoTimeout(oldTimeout);
    }
  }

  // Envio de mensagem de LEAVE para o Chat
  protected void sendLeave() throws IOException {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(LEAVE);
    dataStream.writeUTF(username);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group, msocket.getLocalPort());
    msocket.send(packet);
  }

  // Processes a multicast chat LEAVE PDU and notifies listeners
  // Processamento de mensagem de LEAVE  //
  protected void processLeave(DataInputStream istream, InetAddress address, int port) throws IOException {

    String username = istream.readUTF();
    try {
      users.remove(username);
      listener.chatParticipantLeft(username, address, port);
      negotiateKey();
    } catch (Throwable e) {}
  }

  // Envio de uma mensagem normal
  //
  public void sendMessage(String message) throws IOException {

    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    dataStream.writeLong(CHAT_MAGIC_NUMBER);
    dataStream.writeInt(MESSAGE);
    dataStream.writeUTF(username);
    dataStream.writeUTF(message);
    dataStream.close();

    byte[] data = byteStream.toByteArray();
    DatagramPacket packet = new DatagramPacket(data, data.length, group,
                                               msocket.getLocalPort());
    msocket.send(packet);
  }


  // Processamento de uma mensagem normal  //
  //
  protected void processMessage(DataInputStream istream, InetAddress address, int port) throws IOException {
    String username = istream.readUTF();
    String message = istream.readUTF();
    try {
      listener.chatMessageReceived(username, address, port, message);
    } catch (Throwable e) {}
  }

  protected void negotiateKey(){

    System.out.println("Starting DH negotiation.");
    SecureMulticastSocket socket = (SecureMulticastSocket) msocket;
    List<String> ulist = new ArrayList<>(users);
    DHNNegotiator negotiator = new DHNNegotiator<String>(username, ulist, (data, usr)->{
      String to = (String) usr;
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      DataOutputStream dataStream = new DataOutputStream(byteStream);

      dataStream.writeLong(CHAT_MAGIC_NUMBER);
      dataStream.writeInt(DHKEY);
      dataStream.writeUTF(username);
      dataStream.writeUTF(to);
      dataStream.writeInt(data.length);
      dataStream.write(data);
      dataStream.close();

      byte[] pdata = byteStream.toByteArray();
      DatagramPacket packet = new DatagramPacket(pdata, pdata.length, group, msocket.getLocalPort());
      socket.sendWithKnownEncryption(packet);
    },()->{

      while (true){
        byte[] rdata = new byte[3000];
        DatagramPacket packet = new DatagramPacket(rdata, rdata.length);
        msocket.receive(packet);
        DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));

        long magic = istream.readLong();
        //System.out.println("Received packet");
        if (magic != CHAT_MAGIC_NUMBER) {
          continue;
        }
        int opCode = istream.readInt();
        switch (opCode) {
          case DHKEY:
            String from = istream.readUTF();
            String to = istream.readUTF();
            if(!to.equals(username))
              break;//this key is not for me
            int dataLen = istream.readInt();
            byte[] data = new byte[dataLen];
            istream.read(data);
            return data;
      }
    }
    }, groupConfig.getDiffieHellmanG(), groupConfig.getDiffieHellmanP(), groupConfig.getDiffieHellmanSize());
    try {
      //make sure everyone is ready
      if(negotiator.amMainUser()) {
        Thread.sleep(250);
        sendDHReady();
      }else {
        waitForDHReady();
      }

      byte[] key = negotiator.negotiate(true);

      int keySize = groupConfig.getSymmetricKeySize();

      byte[] croppedKey = new byte[keySize];
      System.arraycopy(key, 0, croppedKey, 0, (key.length>keySize)? keySize:key.length);

      SecretKeySpec keySpec = new SecretKeySpec(croppedKey, groupConfig.getSymmetricAlgorithm());
      groupConfig.setSymmetricEphemeralKeyValue(keySpec);
      listener.chatMessageReceived("DH", InetAddress.getLocalHost(), 1,
              "SET NEW KEY: "+javax.xml.bind.DatatypeConverter.printHexBinary(croppedKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void sendDHReady(){
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);
    try {
      dataStream.writeLong(CHAT_MAGIC_NUMBER);
      dataStream.writeInt(DHREADY);
      dataStream.close();

      byte[] data = byteStream.toByteArray();
      DatagramPacket packet = new DatagramPacket(data, data.length, group,
              msocket.getLocalPort());
      ((SecureMulticastSocket)msocket).sendWithKnownEncryption(packet);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  private void waitForDHReady(){
    try {
      while (true) {
        byte[] rdata = new byte[3000];
        DatagramPacket packet = new DatagramPacket(rdata, rdata.length);
        msocket.receive(packet);
        DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));
        long magic = istream.readLong();
        if (magic != CHAT_MAGIC_NUMBER) {
          continue;
        }
        int opCode = istream.readInt();
        if (opCode == DHREADY)
          break;
      }
    } catch (Exception e) {
    }
  }


  // Loops - recepcao e desmultiplexagem de datagramas de acordo com
  // as operacoes e mensagens
  //
  public void run() {
    byte[] buffer = new byte[65536];

    while (isActive) {
      try {

        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        msocket.receive(packet);


        DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));

        long magic = istream.readLong();

        if (magic != CHAT_MAGIC_NUMBER) {
          continue;
        }
        int opCode = istream.readInt();
        switch (opCode) {
        case JOIN:
          processJoin(istream, packet.getAddress(), packet.getPort());
          break;
        case LEAVE:
          processLeave(istream, packet.getAddress(), packet.getPort());
          break;
        case MESSAGE:
          processMessage(istream, packet.getAddress(), packet.getPort());
          break;
        case DHKEY:
          error("DH key negotiation received at the wrong time.");
          break;
        default:
          error("Cod de operacao desconhecido " + opCode + " enviado de "
                + packet.getAddress() + ":" + packet.getPort());
        }

      } catch (InterruptedIOException e) {

        /**
         * O timeout e usado apenas para forcar um loopback e testar
		 * o valor isActive
         */


      } catch (Throwable e) {
        e.printStackTrace();
        //error("Processing error: " + e.getClass().getName() + ": "
        //      + e.getMessage());
      }
    }

    try {
      msocket.close();
    } catch (Throwable e) {}
  }
}
