/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security). it is written
 * for web applications, to resolve simply, access control problems. version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004 Charles GAY
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this library; if not, write to
 * the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *
 * jGuard project home page: http://sourceforge.net/projects/jguard/
 *
 */
package net.sf.jguard.core.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;

/**
 * this class is done originally by andy tagish, with his great jaas modules. you can reach it <a
 * href="http://free.tagish.net/jaas/index.jsp">on his website</a> the licence of the code provided by andy tagish is
 * also the LGPL. this class is loaded by the application server classloader.
 *
 * @author <a href="mailto:andy@tagish.com">Andy Armstrong</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author Lars Feistner
 */
public final class CryptUtils {

    private static final int MAX_POOL_SIZE = 10;
    private static ArrayBlockingQueue<MessageDigest> messageDigestPool = new ArrayBlockingQueue<MessageDigest>(MAX_POOL_SIZE);

    // by default, the NONE digestAlgorithm is provided
    private static final String NONE_ALGORITHM = "NONE";
    private static String digestAlgorithm = NONE_ALGORITHM;

    private static char[] salt = null;
    private static final int INT = 0xFF;

    private CryptUtils() {

    }

    /**
     * Turn a byte array into a char array containing a printable hex representation of the bytes. Each byte in the
     * source array contributes a pair of hex digits to the output array.
     *
     * @param src the source array
     * @return a char array containing a printable version of the source data
     */
    private static char[] hexDump(byte src[]) {
        char buf[] = new char[src.length * 2];
        for (int b = 0; b < src.length; b++) {
            String byt = Integer.toHexString(src[b] & INT);
            if (byt.length() < 2) {
                buf[(b * 2)] = '0';
                buf[b * 2 + 1] = byt.charAt(0);
            } else {
                buf[(b * 2)] = byt.charAt(0);
                buf[b * 2 + 1] = byt.charAt(1);
            }
        }
        return buf;
    }

    /**
     * Zero the contents of the specified array. Typically used to erase temporary storage that has held plaintext
     * passwords so that we don't leave them lying around in memory.
     *
     * @param pwd the array to zero
     */
    public static void smudge(char pwd[]) {
        if (null != pwd) {
            for (int b = 0; b < pwd.length; b++) {
                pwd[b] = 0;
            }
        }
    }

    /**
     * Zero the contents of the specified array.
     *
     * @param pwd the array to zero
     */
    private static void smudge(byte pwd[]) {
        if (null != pwd) {
            for (int b = 0; b < pwd.length; b++) {
                pwd[b] = 0;
            }
        }
    }

    /**
     * Perform message digest hashing on the supplied password and return a char array containing the encrypted password
     * as a printable string. The hash is computed on the low 8 bits of each character.
     *
     * @param pwd The password to encrypt
     * @return a character array containing a 32 character long hex encoded MD5 hash of the password
     * @throws NoSuchAlgorithmException
     */
    public static char[] cryptPassword(char[] pwd)
            throws NoSuchAlgorithmException {

        char[] newPwd = null;

        if (salt != null) {
            newPwd = saltPassword(pwd);
        } else {
            newPwd = pwd;
        }

        // if no algorithm is set, we don't crypt the char array
        if (digestAlgorithm.equals(NONE_ALGORITHM)) {
            return newPwd;
        }

        // messageDigest algorithm initialization
        MessageDigest messageDigest = null;
        char crypt[] = null;
        try {
            messageDigest = messageDigestPool.take();
            messageDigest.reset();

            // transform char array into byte array
            byte pwdb[] = new byte[newPwd.length];

            for (int b = 0; b < newPwd.length; b++) {
                pwdb[b] = (byte) newPwd[b];
            }

            // char crypt[] = hexDump(md.digest(pwdb));
            crypt = hexDump(messageDigest.digest(pwdb));
            smudge(pwdb);
        } catch (InterruptedException ex) {
            // should never happen, only if application is shutting down
            throw new IllegalStateException(ex);
        } finally {
            messageDigestPool.offer(messageDigest);
        }

        return crypt;
    }

    private static char[] saltPassword(char[] pwd) {
        // merge password and salt
        char[] merged = new char[pwd.length + salt.length];
        int mergedIndex = 0;
        for (char aPwd : pwd) {
            merged[mergedIndex] = aPwd;
            mergedIndex++;
        }
        for (char aSalt : salt) {
            merged[mergedIndex] = aSalt;
            mergedIndex++;
        }
        return merged;
    }

    /**
     * @return digestAlgorithm
     */
    public static String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * set the message digest algorithm. before to set, we verify if the algorithm is available with the current jvm.
     *
     * @param algorithm - digestAlgorithm
     * @throws NoSuchAlgorithmException
     */
    public static void setDigestAlgorithm(String algorithm) throws NoSuchAlgorithmException {
        if (NONE_ALGORITHM.equals(algorithm)) {
            digestAlgorithm = algorithm;
            return;
        }
        Set algorithmsSet = Security.getAlgorithms("MessageDigest");
        if (algorithmsSet.size() < 1) {
            throw new NoSuchAlgorithmException("no Message Digest algorithms implemented in this jvm ");
        }
        Iterator it = algorithmsSet.iterator();
        boolean algorithmImplemented = false;
        String algorithmTemp;

        while (it.hasNext()) {
            algorithmTemp = (String) it.next();
            if (algorithmTemp.equalsIgnoreCase(algorithm)) {
                algorithmImplemented = true;
                break;
            }
        }

        if (algorithmImplemented) {
            digestAlgorithm = algorithm;
        } else {
            throw new NoSuchAlgorithmException("Message Digest algorithm '" + algorithm + "' not implemented ");
        }
        initMessageDigestPool();
    }

    private static void initMessageDigestPool()
            throws NoSuchAlgorithmException {
        for (int i = 0; i < MAX_POOL_SIZE; i++) {
            messageDigestPool.add(MessageDigest.getInstance(digestAlgorithm));
        }
    }

    /**
     * define 'salt' for a better security. it protects against <a
     * href="http://en.wikipedia.org/wiki/Rainbow_table">'rainbow tables'</a>.
     *
     * @param saltCandidate
     * @return
     */
    public static boolean setSalt(char[] saltCandidate) {
        if (salt != null && saltCandidate != null && !String.valueOf(saltCandidate).equals("")) {
            return false;
        }
        char[] copy = new char[0];
        if (saltCandidate != null) {
            copy = new char[saltCandidate.length];
        }
        System.arraycopy(saltCandidate, 0, copy, 0, copy.length);
        CryptUtils.salt = copy;
        return true;

    }


}