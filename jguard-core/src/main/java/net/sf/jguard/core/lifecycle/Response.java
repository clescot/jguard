package net.sf.jguard.core.lifecycle;

/**
 * marker interface for specific technology.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface Response<T> {

    T get();
}
