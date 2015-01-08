package com.google.code.zaproxy;

import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;

public class Dump
{
    private static final Logger LOG = Logger.getLogger(Dump.class.getName());
    public static final Charset ENCODING;
    /**
     * Section 3.4.&nbsp;of RFC-3986.
     * <pre>
     * query = *(pchar / "/" / "?")
     * </pre>
     */
    public static final Pattern QUERY_PCHAR;
    public static final Pattern PCHAR;
    static {
        ENCODING = Charset.forName("UTF-8");
        // these are the definitions from RFC-3986
        // but scrapy deviates in the comma and parens
        // PCHAR       = Pattern.compile("(?:[A-Za-z]|[0-9]|[-\\._~]|[!$&'()*+,;=]|[:@]|/)");
        // QUERY_PCHAR = Pattern.compile("(?:[A-Za-z]|[0-9]|[-\\._~]|[!$&'()*+,;=]|[:@]|[/?])");
        PCHAR       = Pattern.compile("(?:[A-Za-z]|[0-9]|[-\\._~]|[!$&'*+;=]|[:@]|/)");
        QUERY_PCHAR = Pattern.compile("(?:[A-Za-z]|[0-9]|[-\\._~]|[!$&'*+;=]|[:@]|[/?])");
    }

    private static void usageAndDie(String msg) {
        System.err.println(msg);
        System.err.println("  Usage: $0 -check-sig verb url scrapy_cache_dir");
        System.err.println("            -dump hsqldb-filename");
        System.err.println("            -dump hsqldb-filename -url urn://...");
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usageAndDie("I require an action argument");
        }
        if ("-check-sig".equals(args[0])) {
            final String httpVerb = args[0];
            final String url = args[1];
            final String theDir = args[2];
            compareSignature(httpVerb, url, theDir);
        } else if ("-dump".equals(args[0])) {
            final String dbName = args[1];
            if (2 == args.length) {
                final int rc = dumpDatabase(dbName);
                if (0 != rc) {
                    System.exit(rc);
                }
            } else if (4 == args.length && "-url".equals(args[2])) {
                final String onlyUrl = args[3];
                System.out.printf("Restricting my dump to \"%s\"%n", onlyUrl);
                final int rc = dumpDatabase(dbName, onlyUrl);
                if (0 != rc) {
                    System.exit(rc);
                }
            }
        } else {
            usageAndDie("Unrecognized argument" + args[0]);
        }
    }

    public static void compareSignature(String verb, String url, String theDirectory) throws IOException {
        final File dir = new File(theDirectory);
        if (! dir.exists()) {
            throw new IOException(String.format(
                    "Your directory has gone 404: %s%n", dir));
        } else if (! dir.isDirectory()) {
            throw new IOException(String.format(
                    "Expected that path to be a directory: %s%n", dir));
        }
        SignatureParts sig = new SignatureParts();
        sig.setRequestMethod(verb);
        sig.setRequestUrl(url);
        FileInputStream fin = new FileInputStream(new File(dir, "response_body"));
        byte[] buffer = new byte[8096];
        int br;
        while (-1 != (br = fin.read(buffer))) {
            sig.write(buffer, 0, br);
        }
        fin.close();
        System.out.println("Signature := "+sig);
    }

    public static int dumpDatabase(final String databaseFilename) throws Exception {
        return dumpDatabase(databaseFilename, null);
    }

    @SuppressWarnings("ConstantConditions")
    public static int dumpDatabase(final String databaseFilename, final String onlyUrl)
        throws Exception {
        final String tsvFilename = format("%s.tsv", databaseFilename);
        final PrintStream out = new PrintStream(new FileOutputStream(tsvFilename));
        System.setProperty("jdbc.drivers", "org.hsqldb.jdbc.JDBCDriver");
        final Connection conn = DriverManager.getConnection(
                format("jdbc:hsqldb:%s", databaseFilename));
        final PreparedStatement st = conn.prepareStatement(
                "SELECT * FROM HISTORY" +
                        (onlyUrl == null ? "" : " WHERE URI = ?")
        );
        if (null != onlyUrl) {
            st.setString(1, onlyUrl);
        }
        final ResultSet rs = st.executeQuery();
        final ResultSetMetaData md = rs.getMetaData();
        final int columnCount = md.getColumnCount();
        final String[] columnNames = new String[columnCount];
        for (int i = 1; i <= columnCount; i++) {
            if (i != 1) {
                out.print("\t");
            }
            final String name = md.getColumnName(i);
            columnNames[i-1] = name;
            final String type = md.getColumnTypeName(i);
            out.printf("%s|%s", name, type);
        }
        out.printf("\t%s|%s", "FINGERPRINT", "VARCHAR");
        out.println();
        int found = 0;
        final int dataHistType = 1;
        while (rs.next()) {
            final SignatureParts sig = new SignatureParts();
            String id = null;
            int status = -1;
            long millis = -1;
            String resHeaders = null;
            String theSig = null;
            boolean capture = false;
            for (int i = 1; i <= columnCount; i++) {
                if (i != 1) {
                    out.print("\t");
                }
                final String name = columnNames[i-1];
                final String value;
                if ("HISTORYID".equals(name)) {
                    id = value = rs.getString(i);
                } else if ("HISTTYPE".equals(name)) {
                    value = rs.getString(i);
                    capture = (dataHistType == Integer.parseInt(value));
                } else if ("STATUSCODE".equals(name)) {
                    value = rs.getString(i);
                    status = rs.getInt(i);
                } else if ("TIMESENTMILLIS".equals(name)) {
                    value = rs.getString(i);
                    millis = rs.getLong(i);
                } else if ("TIMEELAPSEDMILLIS".equals(name)) {
                    value = rs.getString(i);
                    if (-1 == millis) {
                        throw new IllegalStateException("Expected to have seen millis");
                    }
                    millis += rs.getInt(i);
                } else if ("METHOD".equals(name)) {
                    value = rs.getString(i);
                    sig.setRequestMethod(value);
                } else if ("URI".equals(name)) {
                    value = rs.getString(i);
                    sig.setRequestUrl(value);
                } else if ("REQHEADER".equals(name)) {
                    value = rs.getString(i)
                            .replace("\r", "\\r")
                            .replace("\n", "\\n")
                            ;
                } else if ("REQBODY".equals(name)) {
                    final InputStream stream = rs.getBinaryStream(i);
                    if (null == stream) {
                        LOG.warning(format("%n%n%nSkipping NULL %s%n", name));
                        continue;
                    }
                    // no need to close the S.O.S. as it's not a real stream
                    final SignatureOutputStream sos = new SignatureOutputStream(sig);
                    streamOut(stream, sos);
                    stream.close();
                    value = sos.written ? "<<data>>" : "NULL";
                } else if ("RESHEADER".equals(name)) {
                    final String str = rs.getString(i);
                    value = str
                            .replace("\r", "\\r")
                            .replace("\n", "\\n")
                    ;
                    resHeaders = str.replaceFirst("HTTP/1.1[^\n]*\n", "");
                    // kill the extra "\r\n" at the end
                    if (! resHeaders.isEmpty()) {
                        resHeaders = resHeaders.substring(0, resHeaders.length()-2);
                    }
                } else if ("RESBODY".equals(name)) {
                    if (capture) {
                        value = "<<data>>";
                    final InputStream stream = rs.getBinaryStream(i);
                    if (null == stream) {
                        LOG.warning(format("%n%n%nSkipping NULL %s%n", name));
                        continue;
                    }
                    // this is because we won't have the fingerprint until
                    // after the bytes are written to *the file*
                    final File tmpFile = new File(format("%s.bin", System.nanoTime()));
                    final FileOutputStream fOut = new FileOutputStream(tmpFile);
                    streamOut(stream, fOut);
                    fOut.close();
                    stream.close();
                    LOG.finer(format("Wrote<%s> %s<%s> to %s%n",
                            id, sig.method, sig.uri, tmpFile.getName()));
                    theSig = sig.toString();
                    String dirName = theSig;
                    String hashPart = dirName.substring(0, 2);
                    final File outDir = new File(format(".scrapy/httpcache/%s/%s/%s", databaseFilename, hashPart, dirName));
                    if (! outDir.exists()) {
                        if (!outDir.mkdirs()) {
                            throw new IOException(format("Unable to create %s",outDir));
                        }
                    } else if (! outDir.isDirectory()) {
                        throw new IOException(format("Expected %s to be a directory", outDir));
                    }
                    final File res_body = new File(outDir, "response_body");
                    if (! tmpFile.renameTo(res_body)) {
                        throw new IOException(format("Unable to rename %s to %s", tmpFile, res_body));
                    }
                    if (null == resHeaders) {
                        throw new IOException(format(
                                "Expected to find response_headers on row %s but no", id));
                    }
                    if (resHeaders.isEmpty()) {
                        throw new IOException(format(
                                "Expected response_headers to be non-empty on row %s", id));
                    }
                    final File resHeadersF = new File(outDir, "response_headers");
                    final PrintWriter headOut = new PrintWriter(new FileWriter(resHeadersF));
                    headOut.write(resHeaders);
                    headOut.close();
                    final Map<String, Object> metadata = new HashMap<String, Object>(5);
                    metadata.put("url", sig.uri);
                    metadata.put("status", status);
                    metadata.put("method", sig.method);
                    metadata.put("timestamp", (float)millis);
                    metadata.put("response_url", sig.uri);
                    {
                        final File meta = new File(outDir, "meta.json");
                        final PrintWriter metaOut = new PrintWriter(new FileWriter(meta));
                        for (final Iterator<String> keyIt = metadata.keySet().iterator(); keyIt.hasNext(); ) {
                            final String key = keyIt.next();
                            final Object metaVal = metadata.get(key);
                            final Object val;
                            if (metaVal instanceof String) {
                                val = format("\"%s\"", metaVal);
                            } else {
                                val = metaVal;
                            }
                            metaOut.write(format("\"%s\": %s", key, val));
                            if (keyIt.hasNext()) {
                                metaOut.write(",");
                            }
                        }
                        metaOut.close();
                    }
                    {
                        /*
                        output from `pickletools.dis` for the binary, protocol 2 version
    0: \x80 PROTO      2
    2: }    EMPTY_DICT
    3: q    BINPUT     1
    5: (    MARK
    6: U        SHORT_BINSTRING 'url'
   11: q        BINPUT     2
   13: U        SHORT_BINSTRING 'facebook://108215512553828'
   41: q        BINPUT     3
   43: U        SHORT_BINSTRING 'status'
   51: q        BINPUT     4
   53: M        BININT2    404
   56: U        SHORT_BINSTRING 'method'
   64: q        BINPUT     5
   66: U        SHORT_BINSTRING 'GET'
   71: q        BINPUT     6
   73: U        SHORT_BINSTRING 'timestamp'
   84: q        BINPUT     7
   86: G        BINFLOAT   1393904644.079956
   95: U        SHORT_BINSTRING 'response_url'
  109: q        BINPUT     8
  111: h        BINGET     3
  113: u        SETITEMS   (MARK at 5)
  114: .    STOP

                        and that same thing for protocol 0 (entirely text based)
                        the "(" is MARK (as seen above),
                        "d" is the opcode for dictionary, and
                        "p1" is the normal "put in bucket 1" just like the other
                        "p[0-9]" actions. However, "(dp1" must appear on one line
                        for reasons I didn't look into.
                        Careful: "I" and "F" don't consume a "p" slot, and they are
                        terminated with "\ns".
(dp1
S'url'
p2
S'facebook://108215512553828'
p3
sS'status'
p4
I404
sS'response_url'
p5
g3
sS'method'
p6
S'GET'
p7
sS'timestamp'
p8
F1393904644.0799561
s.
                         */
                        final File pyMeta = new File(outDir, "pickled_meta");
                        final PrintWriter pyMetaOut = new PrintWriter(new FileWriter(pyMeta));
                        pyMetaOut.write("(d"); // dictionary creation on the stack
                        int p = 1;
                        for (final Iterator<String> keyIt = metadata.keySet().iterator();
                             keyIt.hasNext(); p += 2) {
                            final String key = keyIt.next();
                            // I doubt *very* seriously any keys would have quotes in them
                            final String quotedKey = key.replaceAll("'", "\\\\'");
                            // have to emit this first, to consume its "p" slot.
                            pyMetaOut.write(format(
                                    "p%d\n" +
                                    "S'%s'\n", p, quotedKey));
                            final Object metaVal = metadata.get(key);
                            final String val;
                            pyMetaOut.write(format(
                                    "p%d\n", p + 1));
                            if (metaVal instanceof String) {
                                final String quoted = metaVal == null ?
                                        null :
                                        ((String)metaVal).replaceAll("'", "\\\\'");
                                val = format("S'%s'\n", quoted);
                            } else if (metaVal instanceof Integer) {
                                val = format("I%s\n", metaVal);
                            } else if (metaVal instanceof Long) {
                                val = format("L%s\n", metaVal);
                            } else if (metaVal instanceof Double) {
                                val = format("F%f\n", (Double)metaVal);
                            } else if (metaVal instanceof Float) {
                                val = format("F%f\n", (Float)metaVal);
                            } else {
                                throw new IllegalArgumentException(format(
                                        "Unrecognized metadata type<%s>: %s",
                                        null == metaVal ? "NULL" : metaVal.getClass().getName(),
                                        metaVal));
                            }
                            pyMetaOut.write(val);
                            pyMetaOut.write("s"); // SET ITEM (consume k, v)
                        }
                        pyMetaOut.write(".\n");
                        pyMetaOut.close();
                    }
                        LOG.fine(format("Output is in %s%n%n", outDir));
                        found++;
                    } else {
                        value = "NULL";
                        LOG.fine(format("Skipping URI %s due to wrong HISTTYPE", sig.uri));
                    }
                } else {
                    value = rs.getString(i);
                }
                out.print(value);
            }
            out.print("\t");
            out.print(theSig);
            out.println();
        }
        int rc;
        if (0 == found) {
            if (null == onlyUrl) {
                System.err.println("It appears that database is empty; no rows in HISTORY");
            } else {
                System.err.printf("Unable to locate any URL like \"%s\" with HISTTYPE=%d%n",
                        onlyUrl, dataHistType);
            }
            rc = 1;
        } else {
            System.out.printf("Exported %d rows%n", found);
            rc = 0;
        }
        rs.close();
        st.close();
        conn.close();
        out.close();
        return rc;
    }

    static void streamOut(InputStream stream, OutputStream out) throws IOException {
        byte[] buffer = new byte[8096];
        int br;
        while (-1 != (br = stream.read(buffer))) {
            out.write(buffer, 0, br);
        }
        out.close();
    }

    static class SignatureOutputStream extends OutputStream
    {
        public boolean written;
        public SignatureOutputStream(SignatureParts sig) {
            _sig = sig;
        }

        @Override
        public void write(byte[] data, int start, int len) throws IOException {
            written = true;
            _sig.write(data, start, len);
        }
        @Override
        public void write(int b) throws IOException {
            written = true;
            _sig.write(new byte[] { (byte)(0xFF & b) }, 0, 1);
        }
        private SignatureParts _sig;
    }

    static class SignatureParts
    {
        public SignatureParts() {
            try {
                sha1 = MessageDigest.getInstance("SHA1");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Seriously?!", e);
            }
        }
        public void setRequestMethod(String method) {
            sha1.update(method.getBytes(ENCODING));
            this.method = method;
        }
        public void setRequestUrl(String url) {
            final String uri;
            try {
                uri = canonicalUrl(url);
                LOG.finest(format("Canonical<<%s>> := %s", url, uri));
                sha1.update(uri.getBytes(ENCODING));
            } catch (URISyntaxException e) {
                throw new RuntimeException("Unable to make a canonical URL", e);
            } catch (MalformedURLException e) {
                throw new RuntimeException("You gave me a bogus URL", e);
            }
            this.uri = uri;
        }
        public void write(byte[] bytes, int startAt, int length) {
            sha1.update(bytes, startAt, length);
        }
        public String toString() {
            final byte[] sig = sha1.digest();
            return toHexString(sig);
        }
        public String method;
        public String uri;
        private MessageDigest sha1;
    }

    /**
     Canonicalize the given url by applying the following procedures.

     - sort query arguments, first by key, then by value
     - percent encode paths and query arguments. non-ASCII characters are
     percent-encoded using UTF-8 (RFC-3986)
     - normalize all spaces (in query arguments) '+' (plus symbol)
     - normalize percent encodings case (%2f -> %2F)
     - remove query arguments with blank values (unless keep_blank_values is True)
     - remove fragments (unless keep_fragments is True)

     The url passed can be a str or unicode, while the url returned is always a
     str.
     */
    public static String canonicalUrl(String input) throws URISyntaxException, MalformedURLException {
        final URL u = new URL(input);
        final String scheme = u.getProtocol();
        final String host = u.getHost();
        final int port = u.getPort();

        String path = u.getPath();
        if (null ==  path || path.isEmpty()) {
            path = "/";
        }
        path = harmonizePChar(path);

        String query = u.getQuery();
        if (null != query && ! query.isEmpty()) {
            query = sortQueryString(query);
        }

        final int hash = input.indexOf('#');
        final String fragment;
        if (-1 != hash) {
            fragment = input.substring(hash+1);
        } else {
            fragment = null;
        }

        final String userinfo = u.getUserInfo();
        // final URI uri = new URI(scheme, userinfo, host.toLowerCase(), port, path, query, fragment);
        // we need to do this escape restoration or the uppercase escape
        // mechanism will only see %25 which is, of course, already uppercase
        String uriS = new URI(scheme, userinfo, host, port, path, query, fragment).toString();
                /* (
                scheme + "://" +
                (null == userinfo ? "" : userinfo) +
                host + (-1 == port ? "" : ":" + port) +
                path +
                (null == query ? "" : "?" + query) +
                (null == fragment ? "" : "#" + fragment)
                )*/
        // URI has helpfully(sic) escaped our escapes from the QS
        final String withPercents = uriS.replace("%25", "%");
        final int qMark = withPercents.indexOf('?');
        final String almost;
        if (-1 != qMark) {
            // URI seems to disagree with all instances of ","
            // but Scrapy permits it in the PATH only, not QUERY
            almost = withPercents.substring(0, qMark)
                    .replace("%2C", ",") +
                    withPercents.substring(qMark);
        } else {
            almost = withPercents.replace("%2C", ",");
        }
        //noinspection UnnecessaryLocalVariable
        final String result = upperEscapeCodes(almost);
        return result;
    }

    public static String harmonizeQueryPChar(String queryStringPart) {
        return escapeIfNotMatched(queryStringPart, QUERY_PCHAR);
    }

    /**
     * Harmonize the permitted characters in a path.
     * Thus spoke Appendix A:
     * <pre>
     * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
     * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
     * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
     * </pre>
     */
    public static String harmonizePChar(String path) {
        return escapeIfNotMatched(path, PCHAR);
    }

    private static String escapeIfNotMatched(String path, Pattern pat) {
        StringBuilder sb = new StringBuilder(path.length());
        for (int i = 0, len = path.length(); i < len; i++) {
            // percent encoded is as-is
            final char ch = path.charAt(i);
            if ('%' == ch) {
                sb.append('%')
                        .append(Character.toUpperCase(path.charAt(++i)))
                        .append(Character.toUpperCase(path.charAt(++i)))
                        ;
                continue;
            }
            final String str = Character.toString(ch);
            if (! pat.matcher(str).matches()) {
                byte[] bytes = str.getBytes(ENCODING);
                for (byte b : bytes) {
                    sb.append('%').append(toHexString(new byte[] { b }).toUpperCase());
                }
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    public static String upperEscapeCodes(String uri) {
        final String result;
        final Matcher ma = Pattern.compile("%[0-9A-Fa-f][0-9A-Fa-f]").matcher(uri);
        final ArrayList<Integer> starts = new ArrayList<Integer>();
        while (ma.find()) {
            starts.add(ma.start(0));
        }
        if (! starts.isEmpty()) {
            StringBuilder sb = new StringBuilder(uri);
            for (ListIterator<Integer> li = starts.listIterator(starts.size()); li.hasPrevious(); ) {
                int start = li.previous();
                final String upr = sb.subSequence(start, start+2).toString().toUpperCase();
                sb.replace(start, start+2, upr);
            }
            result = sb.toString();
        } else {
            result = uri;
        }
        return result;
    }

    public static String sortQueryString(String query) {
        final StringBuilder sb = new StringBuilder(query.length());
        if (query.startsWith("&")) {
            query = query.substring(1);
        }
        if (query.endsWith("&")) {
            query = query.substring(0, query.length()-1);
        }
        final String[] pairs = query.split("\\Q&");
        // this is actually a Set<> but we want to be able to sort on it
        final ArrayList<String> names = new ArrayList<String>();
        final HashMap<String, ArrayList<String>> kv = new HashMap<String, ArrayList<String>>();
        for (String pair : pairs) {
            final int equal = pair.indexOf('=');
            final String name;
            final String value;
            if (-1 == equal) {
                name = pair;
                value = "";
            } else {
                name = pair.substring(0, equal);
                value = pair.substring(equal+1);
            }
            if (! kv.containsKey(name)) {
                kv.put(name, new ArrayList<String>());
            }
            kv.get(name).add(value);
            if (! names.contains(name)) {
                names.add(name);
            }
        }
        Collections.sort(names);
        for (Iterator<String> it = names.iterator(); it.hasNext(); ) {
            final String name = it.next();
            final ArrayList<String> values = kv.get(name);
            Collections.sort(values);
            for (Iterator<String> vI = values.iterator(); vI.hasNext(); ) {
                final String value = vI.next();
                // turns out that URLEncode is not strong enough
                // and it lets British pound sign through unaltered
                final String encValue = harmonizeQueryPChar(value)
                        .replace("%20", "+");
                final String encName = harmonizeQueryPChar(name)
                        .replace("%20", "+");
                sb.append(encName).append('=').append(encValue);
                if (vI.hasNext()) {
                    sb.append('&');
                }
            }
            if (it.hasNext()) {
                sb.append('&');
            }
        }
        return sb.toString();
    }

    public static String toHexString(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (final byte b : digest) {
            final int i = (0xFF & b);
            if (i <= 0xF) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(i));
        }
        return sb.toString();
    }
}
