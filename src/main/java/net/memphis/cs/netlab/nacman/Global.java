package net.memphis.cs.netlab.nacman;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Description:
 * <p>
 * Author: lei
 */

public abstract class Global {
  // ----------------------------------------------------------------------
  // Names

  public static final String LOCAL_HOME = "/local-home/NAC";
  public static final String DEVICE_PREFIX = "/local-home/device/android-app";
  public static final String APP_PREFIX = DEVICE_PREFIX + "/home-client";

  public static final String TMP_IDENTITY = "tmp-identity";

  public static final String SAMPLE = "/SAMPLE";
  public static final String LOCATION = "/location";
  public static final String TEMPERATURE = "/temperature";
  public static final String EKEY = "/E-KEY";
  public static final String DKEY = "/D-KEY";


  // ----------------------------------------------------------------------
  // Security Setting

  public static enum KeyType {
    RSA,
    ECDSA
  }

  public static final int DEFAULT_KEY_SIZE_2048 = 2048;
  public static final KeyType DEFAULT_KEY_TYPE = KeyType.ECDSA;

  // ----------------------------------------------------------------------
  // Networking

  public static final long DEFAULT_INTEREST_TIMEOUT_MS = 5000;
  public static final int DEFAULT_INTEREST_TIMEOUT_RETRY = 10;
  public static final int DEFAULT_FRESH_PERIOD_MS = 1000;

  // ----------------------------------------------------------------------
  // Storage

  public static final String CONSUMER_DB_PATH = ":memory:";

  // ----------------------------------------------------------------------
  // Threads

  public static final int THREAD_POOL_SIZE = 8;
  public static final ScheduledExecutorService SCHEDULED_EXECUTOR_SERVICE =
      Executors.newScheduledThreadPool(THREAD_POOL_SIZE);

  // ----------------------------------------------------------------------

  public static final Logger LOGGER = Logger.getLogger("common");

  static {
    for (Handler h : LOGGER.getHandlers()) {
      h.setLevel(Level.FINEST);
    }
  }

}
