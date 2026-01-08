import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

public class TelemetryGenerator {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    // Edit these knobs whenever we want
    private static final int NUM_USERS = 10;
    private static final int SESSIONS_PER_USER = 20; // total sessions per user
    private static final double MALICIOUS_RATE = 0.10; // 10%
    private static final String OUT_FILE = "telemetry_raw.csv";

    private static final String[] DOMAIN_CATEGORIES = {
        "email", "shopping", "social", "news", "dev", "finance", "health", "travel"
    };

    // Column order = BoundaryOne schema
    private static final String CSV_HEADER
            = "user_id,session_id,timestamp,session_duration_sec,domain_category,domain_risk_score,redirect_count,"
            + "dwell_time_sec,download_flag,click_count,typing_events,login_failures,mfa_challenge,new_device_login,label_malicious";

    public static void main(String[] args) throws IOException {
        Random rng = new Random(67); // SIX SEVENNNN

        try (BufferedWriter w = new BufferedWriter(new FileWriter(OUT_FILE))) {

            // Write header once
            w.write(CSV_HEADER);
            w.newLine();

            int sessionCounter = 1;

            for (int u = 1; u <= NUM_USERS; u++) {
                String userId = String.format("user_%03d", u);

                // Give each user a "routine" so re-identification is possible later
                int preferredHour = pick(rng, new int[]{8, 9, 10, 13, 18, 20, 22});
                int avgSessionSec = pick(rng, new int[]{180, 300, 600, 900, 1200}); // 3m..20m

                for (int s = 0; s < SESSIONS_PER_USER; s++) {
                    String sessionId = "sess_" + String.format("%05d", sessionCounter++);

                    // timestamp around preferredHour with jitter
                    LocalDateTime ts = LocalDateTime.now()
                            .minusDays(rng.nextInt(7))
                            .withHour(preferredHour)
                            .withMinute(0)
                            .withSecond(0)
                            .plusMinutes(rng.nextInt(181) - 90); // -90..+90 min jitter

                    boolean malicious = rng.nextDouble() < MALICIOUS_RATE;

                    // baseline benign values
                    int sessionDurationSec = clamp((int) (avgSessionSec + rng.nextGaussian() * 120), 30, 3600);
                    String domainCategory = DOMAIN_CATEGORIES[rng.nextInt(DOMAIN_CATEGORIES.length)];
                    double domainRiskScore = round3(Math.pow(rng.nextDouble(), 2)); // skew low
                    int redirectCount = clamp((int) Math.round(rng.nextGaussian() * 1.5 + 1), 0, 10);
                    boolean downloadFlag = rng.nextDouble() < 0.03;
                    int clickCount = clamp((int) Math.round(rng.nextGaussian() * 6 + 18), 0, 80);
                    int typingEvents = clamp((int) Math.round(rng.nextGaussian() * 20 + 55), 0, 300);
                    int loginFailures = 0;
                    boolean mfaChallenge = false;
                    boolean newDeviceLogin = rng.nextDouble() < 0.05;

                    // dwell time: some portion of session duration
                    int dwellTimeSec = clamp((int) (sessionDurationSec * (0.25 + 0.3 * rng.nextDouble())), 1, sessionDurationSec);

                    // inject "malicious-ish" patterns
                    if (malicious) {
                        domainRiskScore = round3(0.7 + 0.3 * rng.nextDouble()); // 0.7..1.0
                        redirectCount = 3 + rng.nextInt(8); // 3..10
                        downloadFlag = true;
                        sessionDurationSec = 20 + rng.nextInt(101); // 20..120 sec (short)
                        dwellTimeSec = clamp(5 + rng.nextInt(30), 1, sessionDurationSec);
                        clickCount = clamp(1 + rng.nextInt(10), 0, 80);
                        typingEvents = clamp(1 + rng.nextInt(20), 0, 300);
                        loginFailures = 2 + rng.nextInt(7); // 2..8
                        mfaChallenge = rng.nextDouble() < 0.6;
                        newDeviceLogin = rng.nextDouble() < 0.3;
                    }

                    // If later you need nulls, set these wrappers to null instead of values:
                    Integer dwellTimeNullable = dwellTimeSec;
                    Boolean downloadNullable = downloadFlag;
                    Integer clickNullable = clickCount;
                    Integer typingNullable = typingEvents;

                    String csvRow = toCsvRow(
                            userId,
                            sessionId,
                            ts.format(ISO),
                            sessionDurationSec,
                            domainCategory,
                            domainRiskScore,
                            redirectCount,
                            dwellTimeNullable,
                            downloadNullable,
                            clickNullable,
                            typingNullable,
                            loginFailures,
                            mfaChallenge,
                            newDeviceLogin,
                            malicious ? 1 : 0
                    );

                    w.write(csvRow);
                    w.newLine();
                }
            }
        }

        System.out.println("Wrote " + OUT_FILE);
    }

    private static String toCsvRow(
            String userId,
            String sessionId,
            String timestamp,
            Integer sessionDurationSec,
            String domainCategory,
            Double domainRiskScore,
            Integer redirectCount,
            Integer dwellTimeSec,
            Boolean downloadFlag,
            Integer clickCount,
            Integer typingEvents,
            Integer loginFailures,
            Boolean mfaChallenge,
            Boolean newDeviceLogin,
            Integer labelMalicious
    ) {
        // CSV rules:
        // - null => empty field
        // - booleans => 0/1
        // - quote strings if they contain comma/quote/newline (not expected here, but safe)
        return joinCsv(
                csvStr(userId),
                csvStr(sessionId),
                csvStr(timestamp),
                csvNum(sessionDurationSec),
                csvStr(domainCategory),
                csvNum(domainRiskScore),
                csvNum(redirectCount),
                csvNum(dwellTimeSec),
                csvBool(downloadFlag),
                csvNum(clickCount),
                csvNum(typingEvents),
                csvNum(loginFailures),
                csvBool(mfaChallenge),
                csvBool(newDeviceLogin),
                csvNum(labelMalicious)
        );
    }

    private static String joinCsv(String... fields) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(fields[i]);
        }
        return sb.toString();
    }

    private static String csvNum(Number n) {
        return (n == null) ? "" : n.toString();
    }

    private static String csvBool(Boolean b) {
        if (b == null) {
            return "";
        }
        return b ? "1" : "0";
    }

    private static String csvStr(String s) {
        if (s == null) {
            return "";
        }
        // Escape if needed
        boolean needsQuoting = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        if (!needsQuoting) {
            return s;
        }
        String escaped = s.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private static int clamp(int x, int lo, int hi) {
        return Math.max(lo, Math.min(hi, x));
    }

    private static int pick(Random rng, int[] options) {
        return options[rng.nextInt(options.length)];
    }

    private static double round3(double x) {
        return Math.round(x * 1000.0) / 1000.0;
    }
}
