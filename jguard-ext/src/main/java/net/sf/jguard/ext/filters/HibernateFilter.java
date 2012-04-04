/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/
package net.sf.jguard.ext.filters;

import net.sf.jguard.core.filters.Filter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hibernate {@link Filter} implementation which permits to support the <i>open
 * session in view filter</i> pattern.
 * it will open the Hibernate  (and begin an Hibernate Transaction) if not yet
 * opened when at doFilter begin method, and close the  Hibernate Session
 * (and commit the HIbernate Transaction) at the end.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HibernateFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(HibernateFilter.class.getName());
    private SessionFactory sessionFactory = null;

    public HibernateFilter(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public void doFilter(Request request, Response response, FilterChain chain) {
        Session session = null;
        Transaction tx = null;

        try {

            session = sessionFactory.getCurrentSession();
            tx = session.beginTransaction();
            logger.debug(" ##### before doFilter in HibernateFilter");
            chain.doFilter(request, response);
            logger.debug(" ##### after doFilter in HibernateFilter");
            tx.commit();
        } catch (Exception e) {
            if (tx != null) {
                tx.rollback();
                logger.error(e.getMessage());
                throw new RuntimeException(e);
            }

        } finally {
            if (session.isOpen()) {
                session.close();
            }
        }
    }

}
