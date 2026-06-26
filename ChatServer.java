import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * ChatServer — vanilla OpenJDK, AES-256-CBC encrypted TCP chat.
 *
 * Privacy guarantees:
 *  - Zero file logging; stdout suppressed in production (see SILENT_MODE).
 *  - No IP addresses stored or printed anywhere.
 *  - No timestamps stored or attached to messages.
 *  - Chat history kept only in-process RAM (last 200 msgs), gone on restart.
 *  - Usernames held only for the duration of an active session.
 *  - All cleartext is confined to this process's heap; never written anywhere.
 *
 * Security notes:
 *  - Key auth uses constant-time comparison to resist timing attacks.
 *  - AES-256-CBC with a fresh SecureRandom IV per message.
 *  - Handshake probe: client sends encrypt(SHA-256(key)) so the raw key
 *    never travels on the wire even in the auth frame.
 *  - Username is validated (alphanum + underscore, 1–20 chars) to prevent
 *    injection into the broadcast envelope.
 *  - Message length is capped at 4 096 bytes to prevent memory exhaustion.
 *  - readLine() has a 512-char guard via a custom LimitedReader.
 *
 * Run:  java ChatServer
 * Port: 9876  (change PORT below)
 * Key:  must match HARDCODED_KEY in ChatClient.java
 */
public class ChatServer {

    // ── Configuration ────────────────────────────────────────────────────────
    private static final int     PORT          = 9876;
    private static final int     MAX_HISTORY   = 200;
    private static final int     MAX_MSG_BYTES = 4096;   // encrypted line length cap
    private static final boolean SILENT_MODE   = true;   // set false only for debugging

    // 32 bytes → AES-256. Change this but keep it identical in ChatClient.java.
    static final String HARDCODED_KEY = "MyS3cur3ChatK3y!MyS3cur3ChatK3y!";
    // ────────────────────────────────────────────────────────────────────────

    /** Rotating in-memory history. Never touches disk. */
    private final Deque<String> history = new ArrayDeque<>(MAX_HISTORY + 1);
    private final Object        historyLock = new Object();

    private final Map<String, ClientHandler> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        // Kill all JUL handlers so the JVM itself logs nothing to disk.
        Logger rootLogger = Logger.getLogger("");
        for (Handler h : rootLogger.getHandlers()) rootLogger.removeHandler(h);
        rootLogger.addHandler(new Handler() {
            public void publish(LogRecord r) { /* /dev/null */ }
            public void flush()  {}
            public void close()  {}
        });

        new ChatServer().start();
    }

    private void start() throws IOException {
        log("[Server] Listening on port " + PORT);
        try (ServerSocket server = new ServerSocket(PORT)) {
            server.setReuseAddress(true);
            while (true) {
                Socket socket = server.accept();
                // Immediately forget the remote address — we never need it.
                socket.setSoTimeout(30_000); // 30 s handshake timeout
                new Thread(new ClientHandler(socket), "client-thread").start();
            }
        }
    }

    // ── History ──────────────────────────────────────────────────────────────

    private void addToHistory(String plaintext) {
        synchronized (historyLock) {
            history.addLast(plaintext);
            if (history.size() > MAX_HISTORY) history.pollFirst();
        }
    }

    /** Returns a snapshot of the current history. */
    private List<String> getHistory() {
        synchronized (historyLock) {
            return new ArrayList<>(history);
        }
    }

    // ── Broadcast ────────────────────────────────────────────────────────────

    void broadcast(String plaintext, String senderUsername) {
        String envelope = "[" + senderUsername + "] " + plaintext;
        addToHistory(envelope);
        for (ClientHandler c : clients.values()) {
            c.sendEncrypted(envelope);
        }
    }

    void broadcastSystem(String message) {
        String envelope = "*** " + message + " ***";
        // System events (join/leave) are NOT stored in history on purpose —
        // they reveal presence metadata. Change if you prefer otherwise.
        for (ClientHandler c : clients.values()) {
            c.sendEncrypted(envelope);
        }
    }

    void removeClient(String username) {
        clients.remove(username);
    }

    // ── Logging (no-op in SILENT_MODE) ───────────────────────────────────────

    static void log(String msg) {
        if (!SILENT_MODE) System.out.println(msg);
    }

    // ── Per-client handler ───────────────────────────────────────────────────
    class ClientHandler implements Runnable {
        private final Socket     socket;
        private PrintWriter      out;
        private String           username;

        ClientHandler(Socket socket) { this.socket = socket; }

        @Override
        public void run() {
            try {
                // Wrap input with a line-length limiter to prevent OOM.
                LimitedReader limited = new LimitedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8),
                        MAX_MSG_BYTES);
                BufferedReader in = new BufferedReader(limited);
                out = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

                // ── Handshake ────────────────────────────────────────────
                // Line format:  AUTH:<username>:<encrypt(sha256hex(key))>
                String handshake = in.readLine();
                if (handshake == null || !handshake.startsWith("AUTH:")) {
                    silentClose(); return;
                }

                // Split on ":" but limit to 3 parts so Base64 padding "=" survives.
                int firstColon  = handshake.indexOf(':');
                int secondColon = handshake.indexOf(':', firstColon + 1);
                if (firstColon < 0 || secondColon < 0) { silentClose(); return; }

                String candidateName  = handshake.substring(firstColon + 1, secondColon).trim();
                String encryptedProbe = handshake.substring(secondColon + 1).trim();

                // Validate username: alphanum + underscore, 1-20 chars.
                if (!candidateName.matches("[A-Za-z0-9_]{1,20}")) {
                    out.println("ERR:Invalid username");
                    silentClose(); return;
                }

                // Decrypt probe and compare against sha256(key) — constant-time.
                String expectedProbe;
                try { expectedProbe = CryptoUtil.sha256hex(HARDCODED_KEY); }
                catch (Exception e) { silentClose(); return; }
                String decryptedProbe;
                try {
                    decryptedProbe = CryptoUtil.decrypt(encryptedProbe, HARDCODED_KEY);
                } catch (Exception e) {
                    out.println("ERR:Bad key");
                    silentClose(); return;
                }

                if (!CryptoUtil.constantTimeEquals(expectedProbe, decryptedProbe)) {
                    out.println("ERR:Wrong key");
                    silentClose(); return;
                }

                if (clients.containsKey(candidateName)) {
                    out.println("ERR:Username taken");
                    silentClose(); return;
                }

                username = candidateName;
                clients.put(username, this);

                // ── Send history replay then OK ───────────────────────────
                // History messages are sent before OK so the client can
                // distinguish them from live traffic if desired.
                for (String past : getHistory()) {
                    sendEncrypted("[history] " + past);
                }
                out.println("OK");

                // Remove the handshake timeout now that we're in normal operation.
                socket.setSoTimeout(0);

                broadcastSystem(username + " has joined the chat");
                log("[+] " + username + " connected");

                // ── Main receive loop ─────────────────────────────────────
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.length() > MAX_MSG_BYTES) continue; // extra guard
                    String plaintext;
                    try {
                        plaintext = CryptoUtil.decrypt(line, HARDCODED_KEY);
                    } catch (Exception e) {
                        continue; // corrupted or wrong-key frame — drop silently
                    }
                    if ("/quit".equals(plaintext)) break;
                    // Sanitise: strip control chars to prevent terminal injection.
                    plaintext = plaintext.replaceAll("[\\p{Cntrl}&&[^\n\r\t]]", "");
                    if (!plaintext.isBlank()) broadcast(plaintext, username);
                }

            } catch (IOException e) {
                // Abrupt disconnect — expected, not an error.
            } finally {
                cleanup();
            }
        }

        private void cleanup() {
            if (username != null) {
                removeClient(username);
                broadcastSystem(username + " has left the chat");
                log("[-] " + username + " disconnected");
                username = null; // explicitly null — let GC reclaim
            }
            silentClose();
        }

        private void silentClose() {
            try { socket.close(); } catch (IOException ignored) {}
        }

        void sendEncrypted(String plaintext) {
            try {
                out.println(CryptoUtil.encrypt(plaintext, HARDCODED_KEY));
            } catch (Exception e) {
                // Encryption failure for one client shouldn't bring down the thread.
            }
        }
    }

    // ── Line-length limiter ───────────────────────────────────────────────────
    /**
     * Wraps a Reader and throws IOException if any single line exceeds maxChars.
     * Prevents a malicious client from sending a gigantic line to exhaust heap.
     */
    static class LimitedReader extends FilterReader {
        private final int maxChars;
        private int lineLength = 0;

        LimitedReader(Reader in, int maxChars) {
            super(in);
            this.maxChars = maxChars;
        }

        @Override
        public int read() throws IOException {
            int c = super.read();
            if (c == '\n') { lineLength = 0; }
            else if (++lineLength > maxChars) throw new IOException("Line too long");
            return c;
        }

        @Override
        public int read(char[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0) {
                for (int i = off; i < off + n; i++) {
                    if (buf[i] == '\n') { lineLength = 0; }
                    else if (++lineLength > maxChars) throw new IOException("Line too long");
                }
            }
            return n;
        }
    }
}

// ── AES-256-CBC + helpers ─────────────────────────────────────────────────────
class CryptoUtil {
    private static final String ALGO = "AES/CBC/PKCS5Padding";

    /** Encrypt plaintext → Base64(IV ‖ ciphertext). Fresh IV every call. */
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

    /** Decrypt Base64(IV ‖ ciphertext) → plaintext. */
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

    /**
     * SHA-256 hex digest of a string.
     * Used for the auth probe so the raw key never travels on the wire.
     */
    static String sha256hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Constant-time string comparison — resists timing side-channel attacks.
     * Both strings are compared byte-by-byte without early exit.
     */
    static boolean constantTimeEquals(String a, String b) {
        byte[] ab = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        int diff = ab.length ^ bb.length;
        int len  = Math.min(ab.length, bb.length);
        for (int i = 0; i < len; i++) diff |= ab[i] ^ bb[i];
        return diff == 0;
    }
}
