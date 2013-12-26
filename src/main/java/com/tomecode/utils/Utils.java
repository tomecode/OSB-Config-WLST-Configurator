package com.tomecode.utils;

import java.io.ByteArrayOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

/**
 * Utils
 * 
 * @author Tomas.FRASTIA - tomecode.com
 * 
 */
public final class Utils {

	public static final byte[] readJarEntryToBytes(JarInputStream jis, JarEntry entry) throws Exception {
		byte[] buffer = new byte[1024];
		int nrBytesRead;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while ((nrBytesRead = jis.read(buffer)) > 0) {
			baos.write(buffer, 0, nrBytesRead);
		}

		return baos.toByteArray();
	}
}
