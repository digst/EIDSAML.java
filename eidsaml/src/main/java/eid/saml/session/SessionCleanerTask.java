package eid.saml.session;

import eid.saml.service.EIDSAMLService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SessionCleanerTask is executed by the SessionCleanerService.
 * The purpose for SessionCleanerTask is removing EIDSAML sessions that has timed out,
 * but have not been removed by the SessionDestroyListener. *
 */
public class SessionCleanerTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(SessionCleanerTask.class);

    private long maxInactiveIntervalSeconds;

    public SessionCleanerTask(long maxInactiveIntervalSeconds) {
        this.maxInactiveIntervalSeconds = maxInactiveIntervalSeconds;
    }

    @Override
    public void run() {
        log.debug("Cleaning session data, time: {}, timeout: {}", System.currentTimeMillis(), maxInactiveIntervalSeconds * 1000);
        try {
            SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
            sessionHandler.cleanup(maxInactiveIntervalSeconds);
        } catch (Exception e) {
            log.warn("Failed removing old session data", e);
        }
    }
}
