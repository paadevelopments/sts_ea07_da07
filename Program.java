import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class Program {
    private static final LocalDateTime baseDate = LocalDateTime.of(1993,1,1,0,0,0);

    public static void main(String[] args) {
        System.out.println("================= STS EA07 & DA07 ALGORITHM LOG =================");

        // Inputs
        String decoder_key_hex = "0ABC12DEF3456789";
        String data_block_bin = "0000101100011001111010110010001100000001000000001100001000000111";
        String data_class_bin = "00";
        System.out.println(" ");
        System.out.println("DECODER_KEY_HEX:  "+ decoder_key_hex);
        System.out.println("DATA_BLOCK_BIN:   "+ data_block_bin);
        System.out.println("DATA_BLOCK_HEX:   "+ binToHex(data_block_bin).toUpperCase());
        System.out.println("DATA_CLASS_BIN:   "+ data_class_bin);
        System.out.println("DATA_CLASS_HEX:   "+ binToHex(data_class_bin).toUpperCase());

        // VENDING PROCESS =====================================================================
        System.out.println(" ");
        System.out.println(" "); System.out.println("*** CUSTOM EA07 ENCRYPTION STARTS HERE ***");

        // Do 1s complement
        System.out.println("=== 1S COMPLEMENT ===");
        String dk01 = hexToBin(decoder_key_hex, 64);
        System.out.println("LOG__ODK_BIN: "+ dk01);
        String[] s_dk01 = dk01.split("");
        for (int a = 0; a < s_dk01.length; a++) {
            s_dk01[a] = Objects.equals(s_dk01[a], "0") ? "1" : "0";
        }
        String c_dk = String.join("", s_dk01);
        System.out.println("LOG__NDK_BIN: "+ c_dk);
        System.out.println("LOG__NDK_HEX: "+ binToHex(c_dk).toUpperCase());

        // Rotate 12 bits right
        System.out.println(" "); System.out.println("=== ROTATE 12-BITS RIGHT ===");
        String[] r_dk01 = c_dk.split("");
        rotateArrayToRight(r_dk01, 12, r_dk01.length);
        String r_dk = String.join("", r_dk01);
        System.out.println("LOG__RDK_BIN: "+ r_dk);
        System.out.println("LOG__RDK_HEX: "+ binToHex(r_dk).toUpperCase());

        // Encryption
        System.out.println(" "); System.out.println("=== SPKR16ROUNDS ===");
        String edb = new_doSPKR16Rounds(r_dk, data_block_bin, 0);
        System.out.println("LOG__ENCRYPTED_DB_BIN: "+ edb);
        System.out.println("LOG__ENCRYPTED_DB_HEX: "+ binToHex(edb).toUpperCase());
        System.out.println("*** CUSTOM EA07 ENCRYPTION ENDS HERE ***");
        System.out.println(" ");

        // Insert and transposition
        System.out.println(" "); System.out.println("=== INSERT & TRANSPOSITION ===");
        String iNt = insertAndTranspositionClassBits(edb, data_class_bin);
        System.out.println("LOG__66BIT_ENC_DB_BIN: "+ iNt);

        // Convert to 20 digit token number
        System.out.println(" "); System.out.println("=== 20-DIGIT TOKEN ===");
        String t20 = convertToTokenNumber(iNt);
        System.out.println("LOG__20_DIGIT_TOKEN_N: "+ t20);


        // METER PROCESS =======================================================================
        // Decode meter number
        System.out.println(" "); System.out.println("=== DECODE 20-DIGIT TOKEN ===");
        String dt20 = decode20DigitToken(t20);
        System.out.println("LOG__DECODED_20_DT_BIN: "+ dt20);

        // Transposition and removal
        System.out.println(" "); System.out.println("=== TRANSPOSITION & REMOVE ===");
        String tNr = transpositionAndRemoveClassBits(dt20);
        System.out.println("LOG__64BIT_DB_BIN: "+ tNr);

        // Decryption
        System.out.println(" ");
        System.out.println(" "); System.out.println("*** CUSTOM DA07 DECRYPTION STARTS HERE ***");
        String decoded = new_doPSKR16Rounds(hexToBin(decoder_key_hex, 64), edb, 0);
        System.out.println("LOG__DECRYPTED_DB_BIN: "+ decoded);
        System.out.println("*** CUSTOM DA07 DECRYPTION ENDS HERE ***");

        // Extract data
        System.out.println(" ");
        System.out.println(" "); System.out.println("=== DECODED DATA BELOW ===");
        extractTokenInfo(decoded);
        System.out.println(" ");
        System.out.println("================= STS EA07 & DA07 ALGORITHM LOG =================");
    }
    private static String new_doSPKR16Rounds(String key, String data, int rounds) {
        // substitution
        List<Integer> sub_tbl_1 = Arrays.asList(12, 10,  8,  4,  3, 15,  0,  2, 14,  1,  5, 13,  6,  9,  7, 11);
        List<Integer> sub_tbl_2 = Arrays.asList( 6,  9,  7,  4,  3, 10, 12, 14,  2, 13,  1, 15,  0, 11,  8,  5);
        List<String> chunk_dk = chunkString(key);
        List<String> chunk_db = chunkString(data);
        for (int i = 0; i < chunk_db.size(); i++) {
            int bi3 = Integer.parseInt( chunk_dk.get(i).split("")[0] );
            List<Integer> sub_tbl = bi3 == 1 ? sub_tbl_2 : sub_tbl_1;
            chunk_db.set( i, decToBin( sub_tbl.get( binToDec( chunk_db.get(i) ) ), 4 ) );
        }
        String s_res = String.join("", chunk_db);
        // permutation
        List<Integer> perm_tbl_for = Arrays.asList(
                29, 27, 34,  9, 16, 62, 55,  2, 40, 49, 38, 25, 33, 61, 30, 23,  1, 41, 21, 57, 42, 15,
                5, 58, 19, 53, 22, 17, 48, 28, 24, 39,  3, 60, 36, 14, 11, 52, 54, 12, 31, 51, 10, 26,
                0, 45, 37, 43, 44,  6, 59,  4,  7, 35, 56, 50, 13, 18, 32, 47, 46, 63, 20,  8
        );
        String[] p_t1 = s_res.split("");
        String[] p_t2 = new String[64];
        for (int i = 0; i < p_t1.length; i++) { p_t2[ perm_tbl_for.get(i) ] = p_t1[i]; }
        String p_res = String.join("", p_t2);
        // rotate 1-bit left
        String[] r1_1 = key.split("");
        rotateArrayToLeft(r1_1, r1_1.length);
        String r1_2 = String.join("", r1_1);
        // update counter
        rounds++;
        if (rounds < 16) return new_doSPKR16Rounds(r1_2, p_res, rounds);
        return p_res;
    }
    private static String new_doPSKR16Rounds(String key, String data, int rounds) {
        // permutation
        List<Integer> perm_tbl_rev = Arrays.asList(
                44, 16,  7, 32, 51, 22, 49, 52, 63,  3, 42, 36, 39, 56, 35, 21,  4, 27, 57, 24, 62, 18, 26, 15,
                30, 11, 43,  1, 29,  0, 14, 40, 58, 12,  2, 53, 34, 46, 10, 31,  8, 17, 20, 47, 48, 45, 60, 59,
                28,  9, 55, 41, 37, 25, 38,  6, 54, 19, 23, 50, 33, 13,  5, 61
        );
        String[] p_t1 = data.split("");
        String[] p_t2 = new String[64];
        for (int i = 0; i < p_t1.length; i++) { p_t2[ perm_tbl_rev.get(i) ] = p_t1[i]; }
        String p_res = String.join("", p_t2);
        // substitution
        List<Integer> sub_tbl_1 = Arrays.asList(12, 10,  8,  4,  3, 15,  0,  2, 14,  1,  5, 13,  6,  9,  7, 11);
        List<Integer> sub_tbl_2 = Arrays.asList( 6,  9,  7,  4,  3, 10, 12, 14,  2, 13,  1, 15,  0, 11,  8,  5);
        List<String> chunk_dk = chunkString(key);
        List<String> chunk_db = chunkString(p_res);
        for (int i = 0; i < chunk_dk.size(); i++) {
            int bi3 = Integer.parseInt( chunk_dk.get(i).split("")[3] );
            List<Integer> sub_tbl = bi3 == 1 ? sub_tbl_2 : sub_tbl_1;
            chunk_db.set( i, decToBin( sub_tbl.get( binToDec( chunk_db.get(i) ) ), 4 ) );
        }
        String s_res = String.join("", chunk_db);
        // rotate 1-bit right
        String[] r1_1 = key.split("");
        rotateArrayToRight(r1_1, 1, r1_1.length);
        String r1_2 = String.join("", r1_1);
        // update counter
        rounds++;
        if (rounds < 16) return new_doPSKR16Rounds(r1_2, s_res, rounds);
        return s_res;
    }
    public static void extractTokenInfo(String decryptedTokenBlock){
        System.out.println("Token subclass binary: "+ decryptedTokenBlock.substring(0,4));
        System.out.println("Token rnd binary:      "+ decryptedTokenBlock.substring(4,8));
        String tidBinary = decryptedTokenBlock.substring(8,32);
        int minutesSinceBaseDate = binToDec(tidBinary);
        LocalDateTime issueDate = baseDate.plusMinutes(minutesSinceBaseDate);
        System.out.println("Token tid binary:      "+ tidBinary);
        System.out.println("Token Date of Issue:   "+ issueDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        String amountBinary = decryptedTokenBlock.substring(32,48);
        double tokenAmount = binToDec(amountBinary)/10.0;
        System.out.println("Token amount binary:   "+ amountBinary);
        System.out.println("Token amount in Kwh:   "+ tokenAmount);
        System.out.println("Token crc binary:      "+ decryptedTokenBlock.substring(48,64));
    }
    private static String transpositionAndRemoveClassBits(String tokenNumberBinary) {
        String[] blockBits = tokenNumberBinary.split("");
        blockBits[tokenNumberBinary.length()-1-28]=blockBits[0];
        blockBits[tokenNumberBinary.length()-1-27]=blockBits[1];
        return String.join("",blockBits).substring(2);
    }
    private static String decode20DigitToken(String tokenNumber) {
        return getPaddedString(new BigInteger(tokenNumber.replaceAll("-","")).toString(2),66);
    }
    private static String convertToTokenNumber(String tokenBlock) {
        String tokenNumber = getPaddedString(new BigInteger(tokenBlock,2).toString(),20);
        StringBuilder builder = new StringBuilder();
        for(int i = 0; i < tokenNumber.length(); i += 4) {
            builder.append(tokenNumber, i, i + 4).append("-");
        }
        return builder.substring(0,builder.length()-1);
    }
    private static String insertAndTranspositionClassBits(String encryptedTokenBlock, String tokenClass) {
        String withClassBits = tokenClass+encryptedTokenBlock;
        String[] tokenClassBits = tokenClass.split("");
        String[] tokenBlockBits = withClassBits.split("");
        tokenBlockBits[withClassBits.length()-1-65]=tokenBlockBits[withClassBits.length()-1-28];
        tokenBlockBits[withClassBits.length()-1-64]=tokenBlockBits[withClassBits.length()-1-27];
        tokenBlockBits[withClassBits.length()-1-28]=tokenClassBits[0];
        tokenBlockBits[withClassBits.length()-1-27]=tokenClassBits[1];
        return String.join("",tokenBlockBits);
    }
    private static List<String> chunkString(String s) {
        List<String> chunks = new ArrayList<>();
        for (int i = 0; i < s.length(); i += 4) {
            chunks.add(s.substring(i, Math.min(s.length(), i + 4)));
        }
        return chunks;
    }
    private static void rotateArrayToRight(String[] arr, int d, int n) {
        while (d > n) {
            d = d - n;
        }
        String[] temp = new String[n - d];
        if (n - d >= 0) System.arraycopy(arr, 0, temp, 0, n - d);
        for (int i = n - d; i < n; i++) {
            arr[i - n + d] = arr[i];
        }
        if (n - d >= 0) System.arraycopy(temp, 0, arr, d, n - d);
    }
    private static void rotateArrayToLeft(String[] arr, int n) {
        String[] temp = new String[1];
        System.arraycopy(arr, 0, temp, 0, 1);
        for (int i = 1; i < n; i++) {
            arr[i - 1] = arr[i];
        }
        System.arraycopy(temp, 0, arr, n - 1, 1);
    }
    public static String getPaddedString(String binary, int minLength) {
        int length = binary.length();
        String result = binary;
        if (length < minLength) {
            result = padLeftZeros(binary, minLength);
        }
        return result;
    }
    public static String hexToBin(String hex, int numBits) {
        String bin = new BigInteger(hex, 16).toString(2);
        return getPaddedString(bin, numBits);
    }
    public static String binToHex(String binary) {
        return new BigInteger(binary, 2).toString(16);
    }
    public static String decToBin(int decimal, int numBits) {
        String binary = Integer.toBinaryString(decimal);
        return getPaddedString(binary, numBits);
    }
    public static int binToDec(String binary) {
        return Integer.parseUnsignedInt(binary, 2);
    }
    public static String padLeftZeros(String inputString, int length) {
        if (inputString.length() >= length) {
            return inputString;
        }
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append('0');
        }
        sb.append(inputString);

        return sb.toString();
    }
}
