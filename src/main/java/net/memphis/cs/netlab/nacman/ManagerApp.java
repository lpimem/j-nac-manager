package net.memphis.cs.netlab.nacman;

import edu.memphis.cs.netlab.nacapp.InterestHandler;
import edu.memphis.cs.netlab.nacapp.NACNode;
import net.named_data.jndn.*;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.*;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.Certificate;
import net.named_data.jndn.util.Blob;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class ManagerApp {
	NACNode node = new NACNode();
	Face face = new Face();
	final String prefix = "/local-home/NAC";
	final String datatype = "/location/bedroom";
	KeyChain keychain = KeyChainHelper.makeKeyChain(new Name(prefix), face);
	GroupManager manager = new GroupManager(new Name(prefix),
		new Name(datatype),
		new Sqlite3GroupManagerDb(":memory:"),
		2048,
		0,
		keychain);

	Map<String, Data> dkeyStore = new HashMap<>();
	Map<String, Data> identityCertStore = new HashMap<>();
	Map<String, Schedule> scheduleStore = new HashMap<>();


	public ManagerApp() throws GroupManagerDb.Error, SecurityException {
		node.init(new Name(prefix));
	}

	private void registerPrefixes(Runnable onSuccess) {
		InterestHandler[] handlers = new InterestHandler[]{
			new OnRead(),
			new OnAddIdentity(),
			new OnIdentity(),
			new OnGrant()
		};
		node.registerPrefixes(handlers, onSuccess);
	}

	class OnRead implements InterestHandler {
		public final String path = "/READ";

		private void onGetEKey(Interest interest, Name dataType, Name args) {
			Exclude exc = interest.getExclude();
			String timeExpr = exc.get(0).getComponent().toEscapedString();
			double timeslot;
			try {
				timeslot = Schedule.fromIsoString(timeExpr);
			} catch (EncodingException e) {
				throw new RuntimeException(e);
			}
			try {
				List keys = manager.getGroupKey(timeslot);
				Data ekey = (Data) keys.get(0);
				for (int i = 1; i < keys.size(); i++) {
					Data dkey = (Data) keys.get(i);
					System.out.println(String.format("new d-key: %s", dkey.getName().toUri()));
					dkeyStore.put(dkey.getName().toUri(), dkey);
				}
				node.putData(ekey);
			} catch (GroupManagerDb.Error | SecurityException error) {
				throw new RuntimeException(error);
			}
		}

		private void onGetDKey(Interest interest, Name dataType, Name args) {
			// long timestamp = args.get(0).toTimestamp();
			String timestamp = args.get(0).toEscapedString();
			Name entity = args.getSubName(3);
			System.out.println("GET [D-Key] for " + entity.toUri());
			for (Map.Entry<String, Data> entry : dkeyStore.entrySet()) {
				String dkeyName = entry.getKey();
				System.out.println(String.format("found d-key in store: %s", dkeyName));
				if (dkeyName.contains(entity.toUri()) && dkeyName.contains(timestamp)) {
					node.putData(entry.getValue());
					return;
				}
			}
			System.err.println(String.format("Cannot find D-KEY for %s [at] %s", entity.toUri(), timestamp));
		}

		private Name[] parseUri(Name interestName) {
			if (interestName.size() < 1) {
				return new Name[]{null, null, null};
			}
			Name[] res = new Name[3];
			int i;
			for (i = 0; i < interestName.size(); i++) {
				Name.Component c = interestName.get(i);
				if (c.toEscapedString().equalsIgnoreCase("e-key")
					|| c.toEscapedString().equalsIgnoreCase("d-key")) {
					break;
				}
			}
			if (i >= interestName.size()) {
				return new Name[]{null, null, null};
			}
			res[0] = interestName.getSubName(3, i - 3);
			res[1] = interestName.getSubName(i, 1);
			res[2] = interestName.getSubName(i + 1);
			return res;
		}

		@Override
		public void onInterest(Name name,
							   Interest interest,
							   Face face,
							   long l,
							   InterestFilter interestFilter) {
			Name[] res = parseUri(interest.getName());
			Name dataType = res[0];
			Name.Component keyType = res[1].get(0);
			Name args = res[2];
			if (keyType.toEscapedString().equalsIgnoreCase("E-KEY")) {
				onGetEKey(interest, dataType, args);
			} else if (keyType.toEscapedString().equalsIgnoreCase("D-KEY")) {
				onGetDKey(interest, dataType, args);
			} else {
				throw new RuntimeException("invalid arg: " + keyType.toEscapedString());
			}
		}

		@Override
		public String path() {
			return path;
		}

		@Override
		public void onRegisterSuccess(Name name, long l) {

		}
	}

	class OnIdentity implements InterestHandler {
		public final String path = "/IDENTITY/for";

		@Override
		public void onInterest(Name name,
							   Interest interest,
							   Face face,
							   long l,
							   InterestFilter interestFilter) {
			Name entityName = interest.getName().getSubName(4);
			Data cert = identityCertStore.get(entityName.toUri());
			if (null == cert) {
				System.err.println(String.format("Cannot find certificate for %s", entityName.toUri()));
				node.nack(interest.getName());
				return;
			}
			Data resp = new Data(cert);
			resp.setName(interest.getName());
			node.putData(resp);
		}

		@Override
		public String path() {
			return path;
		}

		@Override
		public void onRegisterSuccess(Name name, long l) {

		}
	}

	class OnAddIdentity implements InterestHandler {
		public final String path = "/MANAGEMENT/identity/add";

		@Override
		public void onInterest(Name name,
							   Interest interest1,
							   Face face,
							   long l,
							   InterestFilter interestFilter) {
			Name entityName = interest1.getName().getSubName(5);

			OnData onGetIdentity = new OnData() {
				@Override
				public void onData(Interest interest2, Data data) {
					try {
						Certificate cert = new Certificate(data);
						Data resp = new Data();
						resp.setName(interest1.getName());
						// TODO: sign the certificate using manager's key
						// for now we just send it back without alterations.
						identityCertStore.put(entityName.toUri(), cert);
						System.out.println(String.format("Identity added: %s", entityName.toUri()));
						resp.setContent(new Blob(cert.getName().toUri()));
						node.putData(resp);
						System.out.println("OUT: " + resp.getName());
					} catch (DerDecodingException e) {
						throw new RuntimeException(e);
					}
				}
			};
			try {
				node.expressInterest(entityName, onGetIdentity);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		@Override
		public String path() {
			return path;
		}

		@Override
		public void onRegisterSuccess(Name name, long l) {

		}
	}

	class OnGrant implements InterestHandler {
		public final String path = "/MANAGEMENT/access/grant";

		private boolean dogrant(String id,
								String datatype,
								String startDate,
								String startHour,
								String endDate,
								String endHour) {
			double startD, endD;
			try {
				startD = Schedule.fromIsoString(startDate);
				endD = Schedule.fromIsoString(endDate);
			} catch (EncodingException e) {
				throw new RuntimeException(e);
			}
			int startH = Integer.valueOf(startHour);
			int endH = Integer.valueOf(endHour);
			if (!scheduleStore.containsKey(datatype)) {
				Schedule s = new Schedule();
				RepetitiveInterval interval =
					new RepetitiveInterval(startD, endD, startH, endH, 1, RepetitiveInterval.RepeatUnit.DAY);
				s.addWhiteInterval(interval);
				try {
					manager.addSchedule(datatype, s);
				} catch (GroupManagerDb.Error error) {
					System.err.println(String.format("OnGrant: %s", error.getMessage()));
					return false;
				}
				scheduleStore.put(datatype, s);
			}
			Data cert = identityCertStore.get(id);
			if (null == cert) {
				System.err.println(String.format("OnGrant: ID not found for %s", id));
				return false;
			}
			try {
				manager.addMember(datatype, cert);
				return true;
			} catch (GroupManagerDb.Error | DerDecodingException error) {
				System.err.println(String.format("OnGrant: ID not found for %s", id));
			}
			return false;
		}

		@Override
		public void onInterest(Name name,
							   Interest interest,
							   Face face,
							   long l,
							   InterestFilter interestFilter) {
			Name args = interest.getName().getSubName(5);
			String identity, dataType;
			try {
				identity = java.net.URLDecoder.decode(args.get(0).toEscapedString(), "UTF-8");
				dataType = java.net.URLDecoder.decode(args.get(1).toEscapedString(), "UTF-8");
			} catch (UnsupportedEncodingException e) {
				System.err.println(e.getMessage());
				return;
			}
			String startDate = "20170703T000000Z";
			String endDate = "20170730T000000Z";
			String startHour = "00";
			String endHour = "23";
			if (dogrant(identity, dataType, startDate, startHour, endDate, endHour)) {
				Data resp = new Data();
				resp.setName(interest.getName());
				node.putData(resp);
			} else {
				node.nack(interest.getName());
			}
		}

		@Override
		public String path() {
			return path;
		}

		@Override
		public void onRegisterSuccess(Name name, long l) {

		}
	}

	public static void main(String[] args) throws Throwable {
		ManagerApp a = new ManagerApp();

		a.registerPrefixes(new Runnable() {
			@Override
			public void run() {
				System.out.println("all registered.");
			}
		});

		a.node.startFaceProcessing();
	}
}
