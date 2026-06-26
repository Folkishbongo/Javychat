import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.security.MessageDigest;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * ChatClient — Swing GUI, AES-256-CBC encrypted, vanilla OpenJDK only.
 *
 * Run:  java ChatClient
 * Key must match HARDCODED_KEY in ChatServer.java.
 */
public class ChatClient extends JFrame {

    // ── Configuration ────────────────────────────────────────────────────────
    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final int    PORT         = 9876;
    static final String HARDCODED_KEY        = "MyS3cur3ChatK3y!MyS3cur3ChatK3y!";
    // ────────────────────────────────────────────────────────────────────────

    // ── Network state ────────────────────────────────────────────────────────
    private Socket          socket;
    private BufferedReader  in;
    private PrintWriter     out;
    private volatile boolean connected = false;

    // ── UI components ────────────────────────────────────────────────────────
    private final JTextArea   chatArea    = new JTextArea();
    private final JTextField  msgField    = new JTextField();
    private final JTextField  usernameField;
    private final JPasswordField keyField;
    private final JTextField  hostField;
    private final JButton     connectBtn  = new JButton("Connect");
    private final JButton     sendBtn     = new JButton("Send");
    private final JLabel      statusLabel = new JLabel("Disconnected");

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ChatClient().setVisible(true));
    }

    public ChatClient() {
        super("SecureChat");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(720, 540);
        setLocationRelativeTo(null);
        setBackground(Color.decode("#1e1e2e"));

        usernameField = new JTextField("Alice", 12);
        keyField      = new JPasswordField(HARDCODED_KEY, 20);
        hostField     = new JTextField(DEFAULT_HOST, 14);

        initUI();
        wireActions();
    }

    // ── Build the UI ─────────────────────────────────────────────────────────
    private void initUI() {
        Color bg      = Color.decode("#1e1e2e");
        Color surface = Color.decode("#313244");
        Color accent  = Color.decode("#cba6f7");
        Color fg      = Color.decode("#cdd6f4");
        Color subtle  = Color.decode("#6c7086");

        getContentPane().setBackground(bg);

        // ── Top connection bar ────────────────────────────────────────────
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        topBar.setBackground(surface);
        topBar.setBorder(new EmptyBorder(4, 8, 4, 8));

        topBar.add(styledLabel("Host:", subtle));
        topBar.add(styledField(hostField, bg, fg));

        topBar.add(styledLabel("Username:", subtle));
        topBar.add(styledField(usernameField, bg, fg));

        topBar.add(styledLabel("Key:", subtle));
        topBar.add(styledField(keyField, bg, fg));

        styleButton(connectBtn, accent, bg);
        topBar.add(connectBtn);

        // ── Chat area ─────────────────────────────────────────────────────
        chatArea.setEditable(false);
        chatArea.setBackground(bg);
        chatArea.setForeground(fg);
        chatArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        chatArea.setBorder(new EmptyBorder(8, 10, 8, 10));

        JScrollPane scroll = new JScrollPane(chatArea);
        scroll.setBorder(BorderFactory.createLineBorder(surface, 1));
        scroll.getViewport().setBackground(bg);

        // ── Bottom input bar ──────────────────────────────────────────────
        msgField.setBackground(surface);
        msgField.setForeground(fg);
        msgField.setCaretColor(fg);
        msgField.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        msgField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(subtle),
                new EmptyBorder(4, 8, 4, 8)));
        msgField.setEnabled(false);

        styleButton(sendBtn, accent, bg);
        sendBtn.setEnabled(false);

        JPanel bottomBar = new JPanel(new BorderLayout(8, 0));
        bottomBar.setBackground(bg);
        bottomBar.setBorder(new EmptyBorder(6, 10, 10, 10));
        bottomBar.add(msgField, BorderLayout.CENTER);
        bottomBar.add(sendBtn,  BorderLayout.EAST);

        // ── Status bar ────────────────────────────────────────────────────
        statusLabel.setForeground(subtle);
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statusLabel.setBorder(new EmptyBorder(2, 12, 4, 0));
        statusLabel.setBackground(bg);
        statusLabel.setOpaque(true);

        // ── Assemble ──────────────────────────────────────────────────────
        JPanel center = new JPanel(new BorderLayout());
        center.setBackground(bg);
        center.add(scroll,     BorderLayout.CENTER);
        center.add(statusLabel, BorderLayout.SOUTH);

        add(topBar,    BorderLayout.NORTH);
        add(center,    BorderLayout.CENTER);
        add(bottomBar, BorderLayout.SOUTH);
    }

    private void wireActions() {
        connectBtn.addActionListener(e -> {
            if (!connected) connectToServer();
            else            disconnect();
        });

        ActionListener sendAction = e -> sendMessage();
        sendBtn.addActionListener(sendAction);
        msgField.addActionListener(sendAction);

        addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { disconnect(); }
        });
    }

    // ── Networking ────────────────────────────────────────────────────────────
    private void connectToServer() {
        String username = usernameField.getText().trim();
        String key      = new String(keyField.getPassword()).trim();
        String host     = hostField.getText().trim();

        if (username.isEmpty()) { appendChat("[!] Enter a username."); return; }
        if (key.length() != 32) { appendChat("[!] Key must be exactly 32 characters (AES-256)."); return; }

        setStatus("Connecting…", Color.decode("#f9e2af"));

        new Thread(() -> {
            try {
                socket = new Socket(host, PORT);
                in  = new BufferedReader(new InputStreamReader(socket.getInputStream(),  StandardCharsets.UTF_8));
                out = new PrintWriter(    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

                // Send handshake: AUTH:<username>:<encrypt(sha256hex(key))>
                // The raw key never travels on the wire — only its hash does.
                String probe          = CryptoUtils.sha256hex(key);
                String encryptedProbe = CryptoUtils.encrypt(probe, key);
                out.println("AUTH:" + username + ":" + encryptedProbe);

                // Drain history lines (prefixed "[history] ") until we see "OK" or "ERR:*"
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.equals("OK")) break;
                    if (line.startsWith("ERR:")) {
                        final String errMsg = line;
                        SwingUtilities.invokeLater(() -> {
                            appendChat("[!] Server rejected connection: " + errMsg);
                            setStatus("Disconnected", Color.decode("#6c7086"));
                        });
                        socket.close();
                        return;
                    }
                    // History replay — decrypt and display with subtle style
                    try {
                        String past = CryptoUtils.decrypt(line, key);
                        appendChat(past);
                    } catch (Exception ignored) {}
                }
                if (line == null) { socket.close(); return; } // server closed early

                connected = true;
                SwingUtilities.invokeLater(() -> {
                    connectBtn.setText("Disconnect");
                    msgField.setEnabled(true);
                    sendBtn.setEnabled(true);
                    usernameField.setEnabled(false);
                    keyField.setEnabled(false);
                    hostField.setEnabled(false);
                    setStatus("Connected as " + username, Color.decode("#a6e3a1"));
                    appendChat("──────────── live ────────────");
                    msgField.requestFocus();
                });

                // ── Listen for live messages
                while ((line = in.readLine()) != null) {
                    try {
                        String plaintext = CryptoUtils.decrypt(line, key);
                        appendChat(plaintext);
                    } catch (Exception ex) {
                        appendChat("[!] Could not decrypt a message.");
                    }
                }

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        appendChat("[!] Connection error: " + ex.getMessage()));
            } finally {
                connected = false;
                SwingUtilities.invokeLater(() -> {
                    connectBtn.setText("Connect");
                    msgField.setEnabled(false);
                    sendBtn.setEnabled(false);
                    usernameField.setEnabled(true);
                    keyField.setEnabled(true);
                    hostField.setEnabled(true);
                    setStatus("Disconnected", Color.decode("#6c7086"));
                });
            }
        }, "receiver-thread").start();
    }

    private void sendMessage() {
        if (!connected) return;
        String text = msgField.getText().trim();
        if (text.isEmpty()) return;
        msgField.setText("");

        String key = new String(keyField.getPassword()).trim();
        try {
            String encrypted = CryptoUtils.encrypt(text, key);
            out.println(encrypted);
        } catch (Exception ex) {
            appendChat("[!] Encrypt error: " + ex.getMessage());
        }
    }

    private void disconnect() {
        connected = false;
        if (socket != null && !socket.isClosed()) {
            try {
                if (out != null) {
                    String key = new String(keyField.getPassword()).trim();
                    try { out.println(CryptoUtils.encrypt("/quit", key)); } catch (Exception ignored) {}
                }
                socket.close();
            } catch (IOException ignored) {}
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────
    private void appendChat(String text) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append(text + "\n");
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText("  " + text);
        statusLabel.setForeground(color);
    }

    private JLabel styledLabel(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setForeground(color);
        l.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        return l;
    }

    private JTextField styledField(JTextField field, Color bg, Color fg) {
        field.setBackground(bg);
        field.setForeground(fg);
        field.setCaretColor(fg);
        field.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.decode("#585b70")),
                new EmptyBorder(3, 6, 3, 6)));
        return field;
    }

    private void styleButton(JButton btn, Color bg, Color fg) {
        btn.setBackground(bg);
        btn.setForeground(fg);
        btn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(6, 16, 6, 16));
    }
}

// ── AES-256-CBC utility (same logic as server's CryptoUtil) ──────────────────
class CryptoUtils {
    private static final String ALGO = "AES/CBC/PKCS5Padding";

    static String encrypt(String plaintext, String key32) throws Exception {
        byte[] keyBytes = key32.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    static String decrypt(String encoded, String key32) throws Exception {
        byte[] combined   = Base64.getDecoder().decode(encoded);
        byte[] iv         = Arrays.copyOfRange(combined, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(combined, 16, combined.length);

        byte[] keyBytes = key32.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /** SHA-256 hex digest — used for the auth probe so the raw key never goes on the wire. */
    static String sha256hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
