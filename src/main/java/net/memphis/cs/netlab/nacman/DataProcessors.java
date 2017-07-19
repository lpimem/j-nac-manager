package net.memphis.cs.netlab.nacman;

import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;


/**
 * Description:
 * <p>
 * Author: lei
 */

public abstract class DataProcessors {

  public static DataProcessor newDataSigner(final KeyChain kc, final Name cert) {
    return new DataProcessor() {
      @Override
      public Data process(Data d) throws Exception {
        kc.sign(d, cert);
        return d;
      }
    };
  }

  public static Data applyProcessors(Data d, Iterable<DataProcessor> processors) throws Exception {
    if (null == processors) {
      return d;
    }
    for (DataProcessor proc : processors) {
      d = proc.process(d);
    }
    return d;
  }
}
