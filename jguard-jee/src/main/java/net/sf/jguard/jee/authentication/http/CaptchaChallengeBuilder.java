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
package net.sf.jguard.jee.authentication.http;

import com.octo.captcha.module.config.CaptchaModuleConfig;
import com.octo.captcha.service.AbstractManageableCaptchaService;
import com.octo.captcha.service.CaptchaService;
import net.sf.jguard.ext.SecurityConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Locale;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @since 1.0
 */
public class CaptchaChallengeBuilder {

    private static final Logger logger = LoggerFactory.getLogger(CaptchaChallengeBuilder.class);
    private static final String JPEG_FORMAT_NAME = "JPEG";
    private static final String CACHE_CONTROL = "Cache-Control";
    private static final String NO_STORE = "no-store";
    private static final String PRAGMA = "Pragma";
    private static final String NO_CACHE = "no-cache";
    private static final String EXPIRES = "Expires";
    private static final String IMAGE_JPEG = "image/jpeg";

    public static void buildCaptchaChallenge(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        CaptchaService service = (CaptchaService) session.getServletContext().getAttribute(SecurityConstants.CAPTCHA_SERVICE);
        if (service == null) {
            logger.debug("captcha service should be defined ");
            try {
                service = (CaptchaService) Thread.currentThread().getContextClassLoader().loadClass(CaptchaModuleConfig.getInstance().getServiceClass()).newInstance();
                session.getServletContext().setAttribute(SecurityConstants.CAPTCHA_SERVICE, service);
            } catch (InstantiationException e) {
                logger.error(e.getMessage());
            } catch (IllegalAccessException e) {
                logger.error(e.getMessage());
            } catch (ClassNotFoundException e) {
                logger.error(e.getMessage());
            }
            if (service != null) {
                logger.debug(" CAPTCHA SERVICE=" + service.getClass().getName() + " will be defined");
                if (service.getClass().isAssignableFrom(AbstractManageableCaptchaService.class)) {
                    ((AbstractManageableCaptchaService) service).emptyCaptchaStore();
                }
            }


        } else {
            logger.debug(" CAPTCHA SERVICE=" + service.getClass().getName());
        }
        byte[] captchaChallengeAsJpeg = buildCaptchaChallenge(session.getId(), request.getLocale(), service);


        // flush it in the response
        response.setHeader(CACHE_CONTROL, NO_STORE);
        response.setHeader(PRAGMA, NO_CACHE);
        response.setDateHeader(EXPIRES, 0);
        response.setContentType(IMAGE_JPEG);
        ServletOutputStream responseOutputStream;
        try {
            responseOutputStream = response.getOutputStream();
            responseOutputStream.write(captchaChallengeAsJpeg);
            responseOutputStream.flush();
            responseOutputStream.close();
        } catch (IOException e) {
            logger.error(" captcha cannot be generated", e);
        }
    }


    /**
     * build captcha challenge and return it as a byte array.
     *
     * @param captchaId
     * @param locale
     * @param service
     * @return
     * @throws IOException
     */
    private static byte[] buildCaptchaChallenge(String captchaId, Locale locale, CaptchaService service) throws IOException {

        byte[] captchaChallengeAsJpeg;
        // the output stream to render the captcha image as jpeg into
        ByteArrayOutputStream jpegOutputStream = new ByteArrayOutputStream();
        // get the session id that will identify the generated captcha.
        // the same id must be used to validate the response, the session id is a good candidate!
        logger.debug("sessionID=" + captchaId);
        // call the ImageCaptchaService getChallenge method
        BufferedImage challenge = (BufferedImage) service.getChallengeForID(captchaId, locale);
        logger.debug("challenge=" + service.getQuestionForID(captchaId, locale));
        logger.debug(" service=" + service);
        ImageIO.write(challenge, JPEG_FORMAT_NAME, jpegOutputStream);

        captchaChallengeAsJpeg = jpegOutputStream.toByteArray();
        return captchaChallengeAsJpeg;
    }

}
