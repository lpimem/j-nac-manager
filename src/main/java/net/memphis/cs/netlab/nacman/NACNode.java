package net.memphis.cs.netlab.nacman;

import net.named_data.jndn.*;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.memphis.cs.netlab.nacman.Global.DEFAULT_INTEREST_TIMEOUT_RETRY;


/**
 * Description:
 * <p>
 * Author: lei
 */

public class NACNode {
  private final static String TAG = NACNode.class.getName();
//  private static final Logger LOGGER = Logger.getLogger(TAG);
  private static final Logger LOGGER = Global.LOGGER;


  ////////////////////////////////////////////////////////
  // NDN Primitives Wrapper
  ////////////////////////////////////////////////////////

  // retry on Nack
  public void expressInterest(Name name,
                              final OnData onData) throws IOException {
    expressInterest(name, onData, null);
  }

  public void expressInterest(Name name,
                              final OnData onData,
                              final OnNetworkNack
                                  onNack) throws IOException {
    expressInterest(name, onData, onNack, DEFAULT_INTEREST_TIMEOUT_RETRY);
  }

  public void expressInterest(final Name interestName,
                              final OnData onData,
                              final OnNetworkNack onNack,
                              int maxRetry) throws IOException {
    final Interest interest = new Interest(interestName, Global.DEFAULT_INTEREST_TIMEOUT_MS);
    expressInterest(interest, onData, onNack, maxRetry);
  }

  // repeat on timeout
  public void expressInterest(final Interest interest,
                              final OnData onData,
                              final OnNetworkNack onNack,
                              int maxRetry) throws IOException {
    final int[] retry = {maxRetry};
    final OnTimeout[] onTimeouts = {null};
    final OnNetworkNack[] onNacks = {null};

    onTimeouts[0] = new OnTimeout() {
      @Override
      public void onTimeout(Interest interest) {
        if (retry[0]-- > 0) {
          final int retryIntervalSec = 1;
          LOGGER.log(Level.INFO,
              "Retry interest after " + retryIntervalSec + " second(s) " + retry[0]);
          try {
            TimeUnit.SECONDS.sleep(retryIntervalSec);
            m_face.expressInterest(interest, onData, onTimeouts[0], onNacks[0]);
          } catch (IOException | InterruptedException e) {
            e.printStackTrace();
          }
        }
      }
    };

    if (null == onNack) {
      onNacks[0] = new OnNetworkNack() {
        @Override
        public void onNetworkNack(Interest interest, NetworkNack networkNack) {
          onTimeouts[0].onTimeout(interest);
        }
      };
    } else {
      onNacks[0] = onNack;
    }

    LOGGER.info("[Interest] " + interest.toUri());
    m_face.expressInterest(interest, onData, onTimeouts[0], onNacks[0]);
  }


  // issue interest using default timeout
  // sign interest using default identity
  public void expressInterest(Name name,
                              OnData onData,
                              OnTimeout onTimeout,
                              OnNetworkNack onNac) throws IOException {
    Interest interest = new Interest(name, Global.DEFAULT_INTEREST_TIMEOUT_MS);
    try {
//      m_keychain.sign(interest);
      m_face.expressInterest(interest, onData, onTimeout, onNac);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void putData(Data d) {
    putData(d, new LinkedList<>());
  }

  public void nack(Name n){
    final Data nack =new Data();
    nack.setName(n);
    nack.setMetaInfo(new MetaInfo());
    nack.getMetaInfo().setFreshnessPeriod(1000);
    nack.getMetaInfo().setType(ContentType.NACK);
    putData(nack);
  }


  /**
   * publish data on NDN
   *
   * @param d              the data object
   * @param dataProcessors a list of processors to b applied before the data is sent out.
   */
  public void putData(Data d, List<DataProcessor> dataProcessors) {
    try {
      d = DataProcessors.applyProcessors(d, dataProcessors);

      if (null == d.getMetaInfo()) {
        d.setMetaInfo(new MetaInfo());
      }
//      if (d.getMetaInfo().getFreshnessPeriod() <= 0) {
        d.getMetaInfo().setFreshnessPeriod(Global.DEFAULT_FRESH_PERIOD_MS);
//      }
      if (null == d.getSignature()) {
        m_keychain.sign(d);
      }
      m_face.putData(d);

      final String tag = d.getMetaInfo().getType() == ContentType.NACK ? "NACK": "OUT";
      LOGGER.info(String.format(Locale.ENGLISH,
          "[%s] (%d) %s",
          tag,
          d.getContent().size(),
          d.getName().toUri()));
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "error putData", e);
    }
  }

  public void registerPrefix(final String prefix, final OnInterestCallback onInterest, final OnRegisterSuccess onSuccess){
    OnRegisterFailed onRegisterFailed = new OnRegisterFailed() {
      @Override
      public void onRegisterFailed(Name name) {
        System.err.println("Register failed: " + name.toUri());
      }
    };
    registerPrefix(new Name(prefix), onInterest, onRegisterFailed, onSuccess, DEFAULT_INTEREST_TIMEOUT_RETRY);
  }

  public void registerPrefix(final Name prefix,
                             final OnInterestCallback onInterest,
                             final OnRegisterFailed onFail,
                             final OnRegisterSuccess onSuccess,
                             int maxRetry) {
    final int[] retry = {maxRetry};

    final OnRegisterFailed[] onRetry = {null};
    onRetry[0] = new OnRegisterFailed() {
      @Override
      public void onRegisterFailed(Name prefix) {
        LOGGER.warning("error register cert prefix: " + prefix.toUri());
        if (retry[0]-- > 0) {
          LOGGER.info("retry... " + retry[0]);
          try {
            m_face.registerPrefix(prefix, onInterest, onRetry[0], onSuccess);
          } catch (IOException | SecurityException e) {
            LOGGER.log(Level.SEVERE, "error registerPrefix", e);
          }
        } else {
          if (onFail != null) {
            onFail.onRegisterFailed(prefix);
          }
        }
      }
    };
    LOGGER.info("[REG] " + prefix.toUri());
    try {
      m_face.registerPrefix(prefix, onInterest, onRetry[0], onSuccess);
    } catch (IOException | SecurityException e) {
      LOGGER.log(Level.SEVERE, "error registerPrefix", e);
    }
  }

  public Face getFace() {
    return m_face;
  }


  ////////////////////////////////////////////////////////
  // Access Control API
  ////////////////////////////////////////////////////////

  public interface OnRegisterIdentitySuccess {
    void onNewCertificate(IdentityCertificate cert);
  }

  // should
  //    1. publish self public key
  //    2. send public key to manager
  //    3. receive signed pub key and call onSuccess
  public void registerIdentity(final Name certName,
                               final Data cert,
                               final OnRegisterIdentitySuccess onSuccess) {
    Global.SCHEDULED_EXECUTOR_SERVICE.submit(new Runnable() {
      @Override
      public void run() {
        publishCert(certName, cert, new Runnable() {
          @Override
          public void run() {
            requestAddIdentity(certName, onSuccess);
          }
        });
      }
    });
  }


  public void requestGrantPermission(final Name consumerCert,
                                     final String dataType,
                                     final Runnable onSuccess,
                                     final Runnable onFail) {
    Global.SCHEDULED_EXECUTOR_SERVICE.submit(new Runnable() {
      @Override
      public void run() {
        doRequestPermission(consumerCert, dataType, onSuccess, onFail);
      }
    });
  }


  ////////////////////////////////////////////////////////
  // INIT KeyChain and Face
  ////////////////////////////////////////////////////////

  /**
   * Create application keychain, init default identity
   *
   * @param appPrefix Application prefix
   */
  public void init(Name appPrefix) {
    appPrefix = new Name(appPrefix);
    appPrefix.append(Global.TMP_IDENTITY);
    m_face = new Face("localhost");
    try {
      m_keychain = KeyChainHelper.makeKeyChain(appPrefix, m_face);
    } catch (SecurityException e) {
      throw new RuntimeException(e);
    }
    try {
      m_face.setCommandSigningInfo(
          m_keychain, m_keychain.getDefaultCertificateName());
    } catch (SecurityException ignored) {
      LOGGER.log(Level.SEVERE, "Cannot set command signing info : ", ignored);
      throw new RuntimeException(ignored);
    }
  }

  ////////////////////////////////////////////////////////
  //  Implementation of Access Control
  ////////////////////////////////////////////////////////

  // request manager to add this identity to its database/store.
  private void requestAddIdentity(Name cert, final OnRegisterIdentitySuccess onSuccess) {
    try {
      String api = Global.LOCAL_HOME + "/MANAGEMENT/identity/add" + cert.toUri();
      final OnData onData = new OnData() {
        @Override
        public void onData(Interest interest, Data data) {
          String certName = data.getContent().toString();
          fetchSignedCertitificate(certName, onSuccess);
        }
      };
      expressInterest(new Name(api), onData);
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "requestAddIdentity", e);
    }
  }

  private void fetchSignedCertitificate(final String certName, final OnRegisterIdentitySuccess onSuccess) {
    try {
      final String api = Global.LOCAL_HOME + "/IDENTITY/for" + certName;
      final Name finalCertName = new Name(certName);
      expressInterest(new Name(api), new OnData() {
        @Override
        public void onData(Interest interest, Data data) {
          try {
            data.setName(finalCertName);
            IdentityCertificate cert = new IdentityCertificate(data);
            onSuccess.onNewCertificate(cert);
          } catch (DerDecodingException e) {
            LOGGER.log(Level.SEVERE, "fetchSignedCertitificate->callback", e);
          }
        }
      }, new OnNetworkNack() {
        @Override
        public void onNetworkNack(Interest interest, NetworkNack networkNack) {
          // restart
          try {
            TimeUnit.SECONDS.sleep(2);
            // onFail, restart from add Identity
            requestAddIdentity(finalCertName, onSuccess);
          } catch (InterruptedException e) {
            e.printStackTrace();
          }
        }
      });
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "fetchSignedCertitificate", e);
    }
  }


  private void publishCert(final Name certName, final Data cert, final Runnable onSuc) {
    final OnInterestCallback onInterest = new OnInterestCallback() {
      @Override
      public void onInterest(Name prefix, Interest interest, Face face, long interestFilterId, InterestFilter filter) {
        try {
          Data result = new Data(cert);
          if (result.getMetaInfo() == null || result.getMetaInfo().getFreshnessPeriod() <= 0) {
            if (result.getMetaInfo() == null) {
              result.setMetaInfo(new MetaInfo());
            }
            result.getMetaInfo().setFreshnessPeriod(Global.DEFAULT_FRESH_PERIOD_MS);
          }
          face.putData(result);
        } catch (IOException e) {
          LOGGER.log(Level.SEVERE, "error satisfying cert interest", e);
        }
      }
    };
    final OnRegisterSuccess onRegSuc = new OnRegisterSuccess() {
      @Override
      public void onRegisterSuccess(Name prefix, long registeredPrefixId) {
        onSuc.run();
      }
    };
    registerPrefix(certName, onInterest, null, onRegSuc, DEFAULT_INTEREST_TIMEOUT_RETRY);
  }

  private void doRequestPermission(Name consumerCert,
                                   String dataType,
                                   final Runnable onSuccess,
                                   final Runnable onFail) {
    Name api = new Name(Global.LOCAL_HOME + "/MANAGEMENT/access/grant");
    String certName = consumerCert.toUri();
    api.append(certName);
    api.append(dataType);

    final OnData onData = new OnData() {
      @Override
      public void onData(Interest interest, Data data) {
        try {
          onSuccess.run();
        } catch (Exception e) {
          LOGGER.log(Level.SEVERE, "doRequestPermission->onData", e);
        }
      }
    };

    final OnNetworkNack onNack = new OnNetworkNack() {
      @Override
      public void onNetworkNack(Interest interest, NetworkNack networkNack) {
        onFail.run();
      }
    };

    try {
      expressInterest(api, onData, onNack, DEFAULT_INTEREST_TIMEOUT_RETRY);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  // start a separate thread to process NDN Face events
  public void startFaceProcessing() {
    if (m_prcessing) {
      return;
    }
    Global.SCHEDULED_EXECUTOR_SERVICE.submit(new Runnable() {
      @Override
      public void run() {
        try {
          // ms
          final long sleep = 50;
          while (true) {
            m_face.processEvents();
            TimeUnit.MILLISECONDS.sleep(sleep);
          }
        } catch (IOException | EncodingException | InterruptedException e) {
          LOGGER.log(Level.SEVERE, e.getMessage());
        } finally {
          m_prcessing = false;
        }
      }
    });
    m_prcessing = true;
  }

  private boolean m_prcessing = false;
  
  protected Face m_face;
  protected KeyChain m_keychain;
}
