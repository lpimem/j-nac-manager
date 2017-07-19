package net.memphis.cs.netlab.nacman;


import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.identity.*;


/**
 * Helper functions for keychain management
 */
public class KeyChainHelper {


  // Creates a keychain and default identity
  // The identity is created using default key parameters, which is
  //    RSA + 2048
  //
  // referencing https://github.com/zhtaoxiang/AccessManager/blob/master/app/src/main/java/net/named_data/accessmanager/util/Common.java#L83
  public static KeyChain makeKeyChain(final Name identity, Face face) throws SecurityException {

    final IdentityStorage identityStorage = new MemoryIdentityStorage();
    final PrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();

    return makeKeyChain(identity, face, identityStorage, privateKeyStorage);
  }


  public static KeyChain makeKeyChain(final Name identity,
                                      Face face,
                                      IdentityStorage idStorage,
                                      PrivateKeyStorage pkStorage) throws SecurityException {
    final KeyChain keyChain = new KeyChain(
        new IdentityManager(idStorage, pkStorage));
      // If the storage is not MemoryIdentityStorage but a persistant one.
      // this line prevents from re-creating the identity
      if (!idStorage.doesIdentityExist(identity)) {
        keyChain.createIdentityAndCertificate(identity);
        keyChain.getIdentityManager().setDefaultIdentity(identity);
      }
      keyChain.setFace(face);
    return keyChain;
  }

}
