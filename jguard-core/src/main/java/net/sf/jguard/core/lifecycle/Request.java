package net.sf.jguard.core.lifecycle;

/**
 * marker interface for specific technology.
 * it provides a unique Request interface for all underlying technologies.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface Request<T> {
    T get();
}
