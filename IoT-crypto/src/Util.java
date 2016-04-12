import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;


public class Util {

	/**
	 * Hex dump the data to Syste.out.
	 * @param data The data to dump.
	 */
	public static void hexDump(byte[] data) {
		System.out.println(Hex.encodeHexString(data));
	}

	/**
	 * Parse a hex encoded string to a byte array.
	 * @param h The hex encoded String to parse.
	 * @return A Byte-Array with the contents of the hex encoded String.
	 * @throws DecoderException When an invalid value is spotted.
	 */
	public static byte[] parseHex(String h) throws DecoderException {
		return Hex.decodeHex(h.toCharArray());
	}
	
	/**
	 * Read a file from the "res" directory of the application.
	 * @param filename Filename without the leading res/.
	 * @return Contents of the file as byte array.
	 * @throws IOException When a read error occours.
	 */
	public static byte[] readResFile(String filename) throws IOException {
		File f = new File("res/" + filename);
		if (!f.exists()) {
			throw new IOException("File " + filename + " does not exist");
		}
		long length = f.length();
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] result = new byte[(int) length];
		dis.readFully(result);
		dis.close();
		return result;
	}

}
