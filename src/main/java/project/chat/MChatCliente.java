package project.chat;// MChatCliente.java
// 

import project.cert_validation.TrustManager;
import project.config.GroupConfig;
import project.config.PBEConfig;
import project.config.TLSConfig;
import project.containers.AuthContainer;
import project.exceptions.*;
import project.exceptions.AccessControlException;
import project.parsers.GroupConfigParser;
import project.parsers.PBEConfigParser;
import project.parsers.TLSParser;
import project.pbe.PBEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;

// Interface para a sessao de chat swing-based
// e pode ir sendo melhorada pelos alunos para acomodar as
// diversas funcionalidades do trabalho 

public class MChatCliente extends JFrame implements MulticastChatEventListener {

	private static final int AUTH_FAILED = 1;
	private static final int AC_FAILED = 2;
	private static final int SUCCESS = 3;

	private GroupConfig groupConfig;

	// definicao de um objecto representando um "multicast chat"
	protected MulticastChat chat;

	// area de texto onde se mostram as mensagens das conversas ou a
	// mensagem qdo alguem se junta ao chat\
	protected JTextArea textArea;

	// Campo de texto onde se dara a entrada de mensagens
	protected JTextField messageField;

	// Campo de texto onde se dara a entrada do ficheiro a fazer download
	protected JTextField fileField;

	// Lista com utilizadores no chat
	protected DefaultListModel users;

	// Construtor para uma frame com do chat multicast  (inicializado em estado nao conectado)
	public MChatCliente(GroupConfig groupConfig) {
		super("labs.MulticastChat (modo: desconectado)");
		this.groupConfig = groupConfig;

		// Construct GUI components (iniciaizacao de sessao)
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setLineWrap(true);
		textArea.setBorder(BorderFactory.createLoweredBevelBorder());

		JScrollPane textAreaScrollPane = new JScrollPane(textArea,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		getContentPane().add(textAreaScrollPane, BorderLayout.CENTER);

		users = new DefaultListModel();
		JList usersList = new JList(users);
		JScrollPane usersListScrollPane = new JScrollPane(usersList,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
			public Dimension getMinimumSize() {
				Dimension d = super.getMinimumSize();
				d.width = 100;
				return d;
			}

			public Dimension getPreferredSize() {
				Dimension d = super.getPreferredSize();
				d.width = 100;
				return d;
			}
		};
		getContentPane().add(usersListScrollPane, BorderLayout.WEST);

		Box box = new Box(BoxLayout.Y_AXIS);
		box.add(Box.createVerticalGlue());
		JPanel messagePanel = new JPanel(new BorderLayout());

		messagePanel.add(new JLabel("Menssagem:"), BorderLayout.WEST);

		messageField = new JTextField();
		messageField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendMessage();
			}
		});
		messagePanel.add(messageField, BorderLayout.CENTER);

		JButton sendButton = new JButton("  ENVIAR ");
		sendButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendMessage();
			}
		});
		messagePanel.add(sendButton, BorderLayout.EAST);
		box.add(messagePanel);

		box.add(Box.createVerticalGlue());


		JPanel filePanel = new JPanel(new BorderLayout());

		filePanel.add(new JLabel("Not used"), BorderLayout.WEST);
		fileField = new JTextField();
		fileField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				downloadFile();
			}
		});
		filePanel.add(fileField, BorderLayout.CENTER);

		JButton downloadButton = new JButton("Not Impl.");
		downloadButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				downloadFile();
			}
		});
		filePanel.add(downloadButton, BorderLayout.EAST);
		box.add(filePanel);

		box.add(Box.createVerticalGlue());


		getContentPane().add(box, BorderLayout.SOUTH);

		// detect window closing and terminate multicast chat session
		// detectar o fecho da janela no termino de uma sessao de chat    // 
		addWindowListener(new WindowAdapter() {
			// Invocado na primeira vez que a janela e tornada visivel.
			public void windowOpened(WindowEvent e) {
				messageField.requestFocus();
			}

			// terminar o char a quando do fecho da janela
			public void windowClosing(WindowEvent e) {
				onQuit();
				dispose();
			}

			public void windowClosed(WindowEvent e) {
				System.exit(0);
			}
		});
	}

	/**
	 * Adiciona utilizador no interface do utilizador
	 */
	protected void uiAddUser(String userName) {
		users.addElement(userName);
	}

	/**
	 * Remove utilizador no interface do utilizador.
	 *
	 * @return Devolve true se utilizador foi removido.
	 */
	protected boolean uiRemUser(String userName) {
		return users.removeElement(userName);
	}

	/**
	 * Inicializa lista de utilizadores a partir de um iterador -- pode ser usado
	 * obtendo iterador de qualquer estrutura de dados de java
	 */
	protected void uiInitUsers(Iterator it) {
		users.clear();
		if (it != null)
			while (it.hasNext()) {
				users.addElement(it.next());
			}
	}

	/**
	 * Devolve um Enumeration com o nome dos utilizadores que aparecem no UI.
	 */
	protected Enumeration uiListUsers() {
		return users.elements();
	}

	// Configuracao do grupo multicast da sessao de chat na interface do cliente
	public void join(String username, InetAddress group, int port,
					 int ttl) throws IOException {
		setTitle("CHAT MulticastIP " + username + "@" + group.getHostAddress()
				+ ":" + port + " [TTL=" + ttl + "]");


		// Criar sessao de chat multicast
		chat = new MulticastChat(username, group, port, ttl, this, groupConfig);
	}

	protected void log(final String message) {
		java.util.Date date = new java.util.Date();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				textArea.append(message + "\n");
			}
		});
	}

	/**
	 * Envia mensagem. Chamado quando se carrega no botao de SEND ou se faz ENTER
	 * na linha da mensagem.
	 * Executa operacoes relacionadas com interface -- nao modificar
	 */
	protected void sendMessage() {
		String message = messageField.getText();
		messageField.setText("");
		doSendMessage(message);
		messageField.requestFocus();
	}

	/**
	 * Executa operacoes relativas ao envio de mensagens
	 */
	protected void doSendMessage(String message) {
		try {
			chat.sendMessage(message);
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this,
					"Erro ao enviar uma menssagem: "
							+ ex.getMessage(), "Chat Error",
					JOptionPane.ERROR_MESSAGE);
		}
	}


	/**
	 * Imprime mensagem de erro
	 */
	protected void displayMsg(final String str, final boolean error) {
		final JFrame f = this;

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				if (error)
					JOptionPane.showMessageDialog(f, str, "Chat Error", JOptionPane.ERROR_MESSAGE);
				else
					JOptionPane.showMessageDialog(f, str, "Chat Information", JOptionPane.INFORMATION_MESSAGE);
			}
		});
	}

	/**
	 * Pede downlaod dum ficheiro. Chamado quando se carrega no botao de SEND ou se faz ENTER
	 * na linha de download.
	 * Executa operacoes relacionadas com interface -- nao modificar
	 */
	protected void downloadFile() {
		final String file = fileField.getText();
		fileField.setText("");
		new Thread(new Runnable() {
			public void run() {
				doDownloadFile(file);
			}
		}).start();
		messageField.requestFocus();
	}

	/**
	 * Executa operacoes relativas ao envio de mensagens.
	 * <p>
	 * NOTA: Qualquer informacao ao utilizador deve ser efectuada usando
	 * o metodo "displayMsg".
	 */
	protected void doDownloadFile(String file) {
		// TODO: a completar
		System.err.println("Pedido download do ficheiro " + file);
	}

	/**
	 * Chamado quando o utilizador fechou a janela do chat
	 */
	protected void onQuit() {
		try {
			if (chat != null) {
				chat.terminate();
			}
		} catch (Throwable ex) {
			JOptionPane.showMessageDialog(this, "Erro no termino do chat:  "
							+ ex.getMessage(), "ERRO no Chat",
					JOptionPane.ERROR_MESSAGE);
		}
	}


	// Invocado quando s erecebe uma mensagem  // 
	public void chatMessageReceived(String username, InetAddress address,
									int port, String message) {
		log("MSG:[" + username + "@" + address.getHostName() + "] disse: " + message);
	}


	// Invocado quando um novo utilizador se juntou ao chat  // 
	public void chatParticipantJoined(String username, InetAddress address,
									  int port) {
		log("+++ NOVO PARTICIPANTE: " + username + " juntou-se ao grupo do chat a partir de " + address.getHostName()
				+ ":" + port);
	}

	// Invocado quando um utilizador sai do chat  // 
	public void chatParticipantLeft(String username, InetAddress address,
									int port) {
		log("--- ABANDONO: " + username + " ababdonou o grupo de chat, a partir de " + address.getHostName() + ":"
				+ port);
	}

	// Command-line invocation expecting three arguments
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException {
		if (args.length != 7) {
			System.err.println("Utilizar: MChatCliente "
					+ "<nickusername> <grupo IPMulticast> <porto> { <ttl> } <serverAddress> <serverPort> " +
					"<tlsconfigfile>");
			System.err.println("       - TTL default = 1");
			System.exit(1);
		}

		//System.setProperty("javax.net.debug", "all");

		String username = args[0];
		InetAddress group = null;
		int port = -1;
		int ttl = 1;

		try {
			group = InetAddress.getByName(args[1]);
		} catch (Throwable e) {
			System.err.println("Endereco de grupo multicast invalido: "
					+ e.getMessage());
			System.exit(1);
		}

		if (!group.isMulticastAddress()) {
			System.err.println("Argumento Grupo '" + args[1]
					+ "' nao e um end. IP multicast");
			System.exit(1);
		}

		try {
			port = Integer.parseInt(args[2]);
		} catch (NumberFormatException e) {
			System.err.println("Porto invalido: " + args[2]);
			System.exit(1);
		}

		if (args.length >= 4) {
			try {
				ttl = Integer.parseInt(args[3]);
			} catch (NumberFormatException e) {
				System.err.println("TTL invalido: " + args[3]);
				System.exit(1);
			}
		}

		GroupConfig groupConfig = serverHandshake(args[4], Integer.parseInt(args[5]), args[6], username, args[1]);

		try {
			MChatCliente frame = new MChatCliente(groupConfig);
			frame.setSize(800, 300);
			frame.setVisible(true);

			frame.join(username, group, port, ttl);
		} catch (Throwable e) {
			System.err.println("Erro ao iniciar a frame: " + e.getClass().getName()
					+ ": " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static GroupConfig serverHandshake(String serverAddress, int port, String tlsConfigPath, String username, String multicastAddress) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, KeyManagementException {
		String password = pwPrompt("Enter the password for "+username);//scanner.nextLine();
		//String password = "hashedpw";//pwPrompt("Enter the password for "+username);//scanner.nextLine();


		GroupConfig cryptoconf = null;

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");

			AuthContainer container = new AuthContainer(username, multicastAddress);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput oo = new ObjectOutputStream(bos);
			oo.writeObject(container);
			oo.close();
			byte[] containerBytes = bos.toByteArray();

			PBEConfigParser pbeConfigParser = new PBEConfigParser("src/main/java/project/cryptocfgfiles/" +
					multicastAddress + ".pbe");
			PBEConfig config = pbeConfigParser.parseFile();

			byte[] pwhash = md.digest(password.getBytes());
			PBEncryption pbEnc = new PBEncryption(Base64.getEncoder().encodeToString(pwhash), containerBytes, config);
			byte[] encryptedContainer = pbEnc.encryptFile();

			//Socket socket = new Socket("localhost", 9000);

			Socket socket = createTLSSocket(serverAddress, port, tlsConfigPath);

			ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

			oos.writeInt(encryptedContainer.length);
			oos.writeUTF(username);
			oos.writeUTF(multicastAddress);
			oos.writeUTF(Base64.getEncoder().encodeToString(pbEnc.getIv()));
			oos.write(encryptedContainer);
			oos.flush();

			int status = ois.readInt();

			if (status == AUTH_FAILED)
				throw new AuthenticationException("Username or password invalid");
			else if (status == AC_FAILED)
				throw new AccessControlException("You are not allowed in this room");
			else if (status == SUCCESS)
				System.out.println("Authentication complete. You can now enter the chat.");

			byte[] iv = Base64.getDecoder().decode(ois.readUTF());
			byte[] encryptedCrypto = Base64.getDecoder().decode(ois.readUTF());

			pbEnc = new PBEncryption(Base64.getEncoder().encodeToString(pwhash), encryptedCrypto, config);
			byte[] cryptoFile = pbEnc.decryptFile(iv);

			GroupConfigParser groupConfigParser = new GroupConfigParser(cryptoFile);
			cryptoconf = groupConfigParser.parseFile();

			ois.close();
			oos.close();

		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (AuthenticationException | AccessControlException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

		return cryptoconf;

	}
	public static String pwPrompt(String q){
		JPasswordField pwfield = new JPasswordField();
		int res = JOptionPane.showOptionDialog(null,
				pwfield, q, JOptionPane.NO_OPTION,
				JOptionPane.PLAIN_MESSAGE,null,
				new String[]{"OK","Cancel"},"OK" );
		if(res==0){
			return new String(pwfield.getPassword());
		}
		else
			return "";
	}

	private static Socket createTLSSocket(String host, int port, String tlsConfigPath) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, KeyManagementException {

		TLSConfig tlsConfig = new TLSParser(tlsConfigPath).parseFile();
		System.setProperty("javax.net.ssl.trustStore", tlsConfig.getTruststore());

		KeyStore keystore = tlsConfig.getPrivkeystore();
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keystore, tlsConfig.getKeystorepw());

		TrustManager tm[] = new TrustManager[]{new TrustManager()};

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tm, null);

		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);

		sslSocket.setEnabledProtocols(tlsConfig.getProtocols());
		sslSocket.setEnabledCipherSuites(tlsConfig.getCiphersuites());

		if (tlsConfig.getMode().equals("CLIENTE")) {
			sslSocket.setUseClientMode(false);
		}

		try {
			long startTime = System.nanoTime();
			sslSocket.startHandshake();
			long estimatedTime = System.nanoTime() - startTime;
			System.out.println("Time to establing tls connection: " + (double)estimatedTime / 1000000000.0);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return sslSocket;
	}

//	public static DHParameterSpec generateDHParams(int size) throws NoSuchAlgorithmException, InvalidParameterSpecException {
//		System.out.println("Generating DH parameters...");
//		AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DH");
//		generator.init(size);
//		AlgorithmParameters params = generator.generateParameters();
//		System.out.println("Finished generation of DH parameters.");
//		return params.getParameterSpec(DHParameterSpec.class);
//	}
//
//	public static KeyPair generateDHKeyPair(DHParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
//		KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
//		aliceKpairGen.initialize(params);
//		return aliceKpairGen.generateKeyPair();
//	}
//
//	public KeyAgreement generateDHKeyAgree(KeyPair keypair) throws InvalidKeyException, NoSuchAlgorithmException {
//		KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
//		keyAgree.init(keypair.getPrivate());
//		return keyAgree;
//	}
}
