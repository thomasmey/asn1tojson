package de.m3y3r.utility.asn1tojson;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * DER ASN.1 to JSON converter
 *
 * https://tools.ietf.org/html/rfc5280#section-3.1
 *
 * https://en.wikipedia.org/wiki/X.690
 * http://luca.ntop.org/Teaching/Appunti/asn1.html
 * https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
 *
 * google: ""-----BEGIN CERTIFICATE-----" filetype:pem"
 *
 * https://www.itu.int/en/ITU-T/asn1/Pages/Tools.aspx
 *
 * https://www.obj-sys.com/asn1tutorial/node10.html
 */
public class Converter implements Runnable {

	private static Logger log = Logger.getLogger(Converter.class.getName());

	class Id {
		int tagClass;
		boolean privateConstructed; // true = constructed
		int tagNumber;
	}

	@Override
	public void run() {
		try {
			Decoder decoder = Base64.getDecoder();
			ByteBuffer bb = ByteBuffer.allocate(8192);
			try(BufferedReader br = new BufferedReader(new InputStreamReader(
					this.getClass().getResourceAsStream("/test3.pem")))) {
				String l = "";
				while(l != null) {
					l = br.readLine();
					if(l.startsWith("-----BEGIN CERTIFICATE-----")) {
						continue;
					} else if(l.startsWith("-----END CERTIFICATE-----")) {
						break;
					}
					bb.put(decoder.decode(l));
				}
			}
			bb.flip();

			String json = process(bb, 0, null);
			log.log(Level.INFO, "json {0}", json);
		} catch (Exception e) {
			log.log(Level.SEVERE, "failed to process DER file", e);
		}
	}

	private String process(ByteBuffer bb, int attributeCounter, Id parent) {
		StringBuffer res = new StringBuffer();

		while(bb.hasRemaining()) {
			Id id = nextId(bb);
			int len = nextLength(bb);
			byte[] content = new byte[len];
			bb.get(content);

			String key;
			StringBuffer value = new StringBuffer();
			switch(id.tagClass) {
			case 0: // universal class
				switch(id.tagNumber) {
				case 1: // boolean
					key = "boolean-" + attributeCounter;
					value.append("" + (content[0] == 0));
					break;
				case 2:
					key = "integer-" + attributeCounter;
					BigInteger integer = new BigInteger(content);
					value.append(integer);
					break;
				case 3: // BIT STRING
					key = "bit-string-" + attributeCounter;
					value.append('\"');
					for(byte b: content) {
						value.append(String.format("%02x", b));
					}
					value.append('\"');
					break;
				case 4: // OCTET STRING (Model binary data whose length is a multiple of eight)
					key = "octet-string-" + attributeCounter;
					value.append('\"');
					for(byte b: content) {
						value.append(String.format("%02x", b));
					}
					value.append('\"');
					break;
				case 5:
					key = "null-" + attributeCounter;
					value.append("null");
					break;
				case 6: // oid
					key = "oid-" + attributeCounter;
					value.append('\"');
					value.append(oidToString(content));
					value.append('\"');
					break;
				case 12:
					key = "utf8-string-" + attributeCounter;
					value.append('\"');
					value.append(new String(content, StandardCharsets.UTF_8));
					value.append('\"');
					break;
				case 0x10: // sequence
					key = "sequence-" + attributeCounter;
					value.append('{');
					value.append(process(ByteBuffer.wrap(content), 0, id));
					value.append('}');
					break;
				case 17: // SET
					key = "set-" + attributeCounter;
					value.append('[');
					value.append(process(ByteBuffer.wrap(content), 0, id));
					value.append(']');
					break;
				case 19:
					key = "printable-string-" + attributeCounter;
					// TODO: below is just an approximation... - see https://en.wikipedia.org/wiki/PrintableString
					value.append('\"');
					value.append(new String(content, StandardCharsets.US_ASCII));
					value.append('\"');
					break;
				case 23:
					key = "UTC-time-" + attributeCounter;;
					// TODO: implement date parser
					value.append('\"');
					value.append("TODO: parse date");
					value.append('\"');
					break;
				default:
					throw new IllegalArgumentException("tag number " + id.tagNumber);
				}
				break;
			case 2: // Context-specific (type depends on the context (such as within a sequence, set or choice))
				key = "[" + id.tagNumber + "]-" + attributeCounter;
				value.append(process(ByteBuffer.wrap(content), 0, id));
				break;
			default:
				throw new IllegalArgumentException("tag class " + id.tagClass);
			}

			if(parent != null && parent.tagClass == 0 && parent.tagNumber == 0x10) {
				res.append("\"" + key + "\": ");
			}
			res.append(value);

			if(bb.hasRemaining()) {
				res.append(", ");
			}
			attributeCounter = attributeCounter + 1;
		}
		return res.toString();
	}

	private String oidToString(byte[] content) {
		String componentString = "";
		ByteBuffer bb = ByteBuffer.allocate(16);
		boolean firstComponent = true;
		for(byte b: content) {
			byte v = (byte)(b & 0b111_1111);
			boolean isLastByte = (b & 0x80) == 0;

			bb.put(v);
			if(isLastByte) {
				bb.flip();
				String component = processComponent(bb, firstComponent);
				firstComponent = false;
				bb.clear();
				componentString = componentString + '.' + component;
			}
		}
		return componentString;
	}

	private String processComponent(ByteBuffer bb, boolean firstComponent) {
		byte[] ba = new byte [bb.remaining()];
		bb.get(ba);
		compressBits(ba);
		BigInteger integer = new BigInteger(ba);
		if(firstComponent) {
			BigInteger v40 = BigInteger.valueOf(40);
			BigInteger[] xy = integer.divideAndRemainder(v40);
			return "" + xy[0] + '.' + xy[1];
		} else {
			return "" + integer;
		}
	}

	// FIXME: what happens when s > 7
	private void compressBits(byte[] ba) {
		for(int i = ba.length - 1, s = 1; i >= 0; i--, s++) {
			byte b = ba[i];
			byte p = 0;
			if(i > 0) {
				p = ba[i - 1];
				b = (byte)(((p & s) << 8 - s) | b);
				ba[i] = b;
				p = (byte)(p >>> s);
				ba[i - 1] = p;
			}
		}
	}

	private int nextLength(ByteBuffer bb) {
		int len = bb.get() & 0xff;
		if(len <= 127) {
			return len;
		}

		len = len & 0b1111111;
		if(len == 0) throw new IllegalStateException();// Indefinite ?!
		if(len == 127) throw new IllegalStateException(); // reserved
		if(len == 1) {
			return bb.get() & 0xff;
		} else if(len == 2) {
			return bb.getShort();
		} else if(len == 4) {
			return bb.getInt();
//		} else if(len == 8) {
//			return bb.getLong();
		} else {
			throw new UnsupportedOperationException("len=" + len);
		}
	}

	private Id nextId(ByteBuffer bb) {
		byte id = bb.get();
		Id i = new Id();
		i.tagNumber = id & 0b11111;
		i.privateConstructed = (id & 0b100000) == 1;
		i.tagClass = (id & 0b11000000) >>> 6;
		if(i.tagNumber == 0b11111) { // more
			moreId(i, bb, 5);
		}
		return i;
	}

	private void moreId(Id i, ByteBuffer bb, int shift) {
		byte id = bb.get();
		i.tagNumber = i.tagNumber << shift;
		i.tagNumber = i.tagNumber | (id & 0b1111111);
		while((id & 0b10000000) > 0) {
			moreId(i, bb, 7);
		}
	}

	public static void main(String[] args) {
		new Converter().run();
	}
}
