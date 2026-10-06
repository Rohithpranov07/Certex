// Java replay harness (java.util.regex.Pattern / Matcher.matches()).
// Docs: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/regex/Pattern.html
//
// Protocol (line based, hex so inputs may contain newlines):
//   line 1: hex(UTF-8 pattern)   line 2: per-input limit in seconds
//   lines 3..: hex(UTF-8 input), one per line (an empty line is the empty input)
// Output: one JSON line per input, flushed: {"len":n,"t":seconds} or {"len":n,"limit":true}
// (StackOverflowError inside the matcher). Stops after the first input over the limit.
// UNIX_LINES makes "." / "$" treat only "\n" as a line terminator, as Python does.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class ReplayMain {
    static String unhex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return new String(b, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String pat = unhex(in.readLine().trim());
        double limit = Double.parseDouble(in.readLine().trim());
        Pattern p;
        try {
            p = Pattern.compile(pat, Pattern.UNIX_LINES);
        } catch (Exception e) {
            System.out.println("{\"error\":\"compile\"}");
            return;
        }
        String line;
        while ((line = in.readLine()) != null) {
            String s = unhex(line.trim());
            long t0 = System.nanoTime();
            try {
                p.matcher(s).matches();
            } catch (StackOverflowError e) {
                System.out.println("{\"len\":" + s.length() + ",\"limit\":true}");
                System.out.flush();
                return;
            }
            double dt = (System.nanoTime() - t0) / 1e9;
            System.out.println("{\"len\":" + s.length() + ",\"t\":" + dt + "}");
            System.out.flush();
            if (dt > limit) {
                break;
            }
        }
    }
}
