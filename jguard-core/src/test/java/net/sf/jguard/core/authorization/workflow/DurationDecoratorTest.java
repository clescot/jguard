package net.sf.jguard.core.authorization.workflow;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.net.SocketPermission;
import java.util.Date;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class DurationDecoratorTest {
    private SocketPermission permission1;
    private SocketPermission permission2;
    private SocketPermission permission3;
    private DurationDecorator decorator1;
    private DurationDecorator decorator2;
    private DurationDecorator decorator3;
    private DurationDecorator decorator4;
    private DurationDecorator decorator5;
    private DurationDecorator decorator6;
    private DurationDecorator decorator7;
    private DurationDecorator decorator8;

    @Before
    public void setUp() {
        permission1 = new SocketPermission("localhost:1024-", "accept,connect,listen");
        permission2 = new SocketPermission("localhost:1024-", "accept,connect,listen");
        permission3 = new SocketPermission("localhost:1024-", "accept");

        Date now = new Date();
        long ms = now.getTime();
        Date future = new Date(ms + 500000);
        decorator1 = new DurationDecorator(permission1, now, future);
        decorator2 = new DurationDecorator(permission1, now, future);
        decorator3 = new DurationDecorator(permission2, now, future);
        decorator4 = new DurationDecorator(permission3, now, new Date(ms + 1));
        decorator5 = new DurationDecorator(permission1, new Date(ms + 5), future);
        decorator6 = new DurationDecorator(permission1, now, new Date(ms + 999999));
        decorator7 = new DurationDecorator(permission1, now, null);
        decorator8 = new DurationDecorator(permission1, null, future);
    }

    @Test
    public void testEquals() {
        Assert.assertTrue(decorator1.equals(decorator2));
        Assert.assertTrue(decorator2.equals(decorator1));
        Assert.assertTrue(decorator1.equals(decorator3));
        Assert.assertTrue(decorator3.equals(decorator1));
        Assert.assertFalse(decorator1.equals(decorator4));
        Assert.assertFalse(decorator1.equals(decorator5));
        Assert.assertFalse(decorator1.equals(decorator6));
        Assert.assertFalse(decorator7.equals(decorator1));
        Assert.assertFalse(decorator8.equals(decorator1));
    }

    @Test
    public void testImplies() {
        Assert.assertTrue(permission1.implies(permission2));
        Assert.assertTrue(permission2.implies(permission1));
        Assert.assertFalse(permission3.implies(permission1));
        Assert.assertTrue(permission1.implies(permission3));


        Assert.assertTrue(decorator1.implies(decorator2));
        Assert.assertTrue(decorator2.implies(decorator1));
        Assert.assertTrue(decorator1.implies(decorator3));
        Assert.assertTrue(decorator3.implies(decorator1));
        Assert.assertTrue(decorator1.implies(decorator4));
        Assert.assertFalse(decorator4.implies(decorator1));

        Assert.assertTrue(decorator6.implies(decorator1));
        Assert.assertTrue(decorator7.implies(decorator1));
        Assert.assertTrue(decorator8.implies(decorator1));
    }
}

