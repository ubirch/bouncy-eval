import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;


public class BoardExamples {

	// private RSAPrivateCrtKeyParameters priv;
	private RSAKeyParameters pub;
	
	/**
	 * Load a RSA public key encoded in ASN.1 DER format as described by RFC5280.
	 * 
	 * @param key The key to load as a byte array.
	 * @throws IOException When the key is incorrect.
	 */
	public void loadPublicKeyDER(byte[] key) throws IOException {
		/*
		 * SubjectPublicKeyInfo represents the corresponding field from RFC5280 
		 * https://tools.ietf.org/html/rfc5280
		 */
		SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(key);
		/*
		 * RSAKeyParameters is the key as it can be used by bouncycastle.
		 */
		RSAKeyParameters param =  (RSAKeyParameters) PublicKeyFactory.createKey(spki);
		this.pub = param;
	}
	
	/*
	public void loadPrivateKeyPEM(byte[] key) throws IOException {
		PEMParser pp = new PEMParser(new StringReader(new String(key)));
		PEMKeyPair kp = (PEMKeyPair) pp.readObject();
		pp.close();
		PrivateKeyInfo pki = kp.getPrivateKeyInfo();
		SubjectPublicKeyInfo spki = kp.getPublicKeyInfo();
		RSAPrivateCrtKeyParameters rsa = (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(pki);
		RSAKeyParameters rsaPub =  (RSAKeyParameters) PublicKeyFactory.createKey(spki.getEncoded());
		this.pub  = rsaPub;
		this.priv = rsa;
	}
	*/
	
	/*
	public void genKey() {
		RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
		kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
		AsymmetricCipherKeyPair keyPair = kpg.generateKeyPair();
		this.priv = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
		this.pub = (RSAKeyParameters) keyPair.getPublic();
	}
	*/
	
	/**
	 * Computes the SHA256 hash of a byte array and returns the hash as a byte array.
	 * @param message An message of arbitrary length that should be hashed.
	 * @return The SHA256 hash of the message in byte array form.
	 */
	public byte[] hashSha256(byte[] message) {
		SHA256Digest digest = new SHA256Digest();
		digest.update(message, 0, message.length);
		byte[] result = new byte[digest.getDigestSize()];
		digest.doFinal(result, 0);
		return result;
	}
	
	/*
	public byte[] sign(byte[] message) {
		RSAEngine rsaEngine = new RSAEngine();
		rsaEngine.init(true, priv);
		byte[] hash = hashSha256(message);
		return rsaEngine.processBlock(hash, 0, hash.length);
	}
	*/
	
	/**
	 * Takes a RSA Signature with PKCS1.5 padding and returnes the hash of the signed data.
	 * @param signature The signature to be verified.
	 * @return The Hash that was signed. No length checking of the hash is performed.
	 * @throws InvalidCipherTextException When the signature is malformed.
	 */
	public byte[] verifyGetHashFromSignature(byte[] signature) throws InvalidCipherTextException {
		/*
		 * RSA Engine for the actual cryptographic unwrap oeration.
		 */
		RSAEngine rsaEngine = new RSAEngine();
		/*
		 * PKCS1.5 Encoding unwrap.
		 */
		PKCS1Encoding pkcs1 = new PKCS1Encoding(rsaEngine);
		/*
		 * Init the engine with the public key and with encryption=false.
		 */
		pkcs1.init(false, pub);
		/*
		 * Get the HASH block.
		 */
		byte[] block = pkcs1.processBlock(signature, 0, signature.length);
		return block;
		
	}
	
	public static void main(String[] args) throws IOException, DecoderException, InvalidCipherTextException {
		BoardExamples be = new BoardExamples();
		
		String message = "We love things.\n0a1b2c3d4e5f6g7h8i9j-UBIRCH\n";
		String board_public_key = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100cc9cf89" + 
				"9f9b7f99dc05917d279e7d03514fa0ed10cbe314ccc9bb1dfee53b4027888873296546548" + 
				"9c20a351921ce408c6d926cef380dd1297aff1b0676aae768892f07a6b5e131414fbfc336" + 
				"19c170391f4202f85fef9ba394f05c1ef20d187f3b781f4d8df6bdf8e20be30d291aa7b3a" + 
				"be699dc46a5cfc5c091cde65a6d327802d10b0edfae445eba480fa1a1bb195092361ef558" + 
				"b4685b6410b0aea7172466393dee9fdf7f26c21462de23f3643063376f759dd1646f4e983" + 
				"fd7644008da37ea21157c36ca55703783cd439f71241231b71d1213e9191476f6d96a7692" + 
				"e0f8bacd006b033dc1ebcdbee55cef0ff187224eba133e7c745db11dbd8abdd62c7020301" + 
				"0001";
		String signature = "12e8ea2b502be98ce5f2f5b800d0f313eb706a70bf1e82f3940fecbac988450690f1d33cb" + 
				"a6f92cf023c6ef493dd258a8300fd0f29c762667010452db8696947e1f5bb987aaef4e074" + 
				"a0288aa903091788e1f924733cd36f6067725fb2cf6122f492d31ab4c300ef41929a4fed4" + 
				"c8355745c88c3e109edf21d66a78774518d51c2d587911e20fe05cfd6862d4d63d38ca1d6" + 
				"06dfa2225a4a0454b7f143b632664168e6e5b0221646a132e9ccfba91833b95264e577054" + 
				"514771979e96c93f7e0ef8a5fb4f0a37d97da56e40050a68d4334b6b1fd8b0f3e346e1680" + 
				"a06824346712b72586003183206894878db131d75d20436886d98f091388d0d1b957402dd" + 
				"b";

		byte[] board_public_key_byte = Util.parseHex(board_public_key);
		byte[] signature_byte = Util.parseHex(signature);

		be.loadPublicKeyDER(board_public_key_byte);

		try {
			byte[] hashFirst = be.hashSha256(message.getBytes());
			byte[] hashSecond = be.verifyGetHashFromSignature(signature_byte);
			dumpHashes(hashFirst, hashSecond);
			if (!Arrays.equals(hashFirst, hashSecond)) {
				throw new RuntimeException("Invalid hash");
			}
			System.out.println("Signature verified!");
		} catch (Exception e) {
			System.out.println("Signature not verified");
		}
		
	}

	/**
	 * For debugging, dump both hashes to System.out.
	 * 
	 * @param hashFirst First hash to dump.
	 * @param hashSecond Second hash to dump.
	 */
	private static void dumpHashes(byte[] hashFirst, byte[] hashSecond) {
		System.out.print("hash1: ");
		Util.hexDump(hashFirst);
		System.out.print("hash2: ");
		Util.hexDump(hashSecond);
	}

}
