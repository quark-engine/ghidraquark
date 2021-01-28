package quarkenginehelper;

import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.gson.stream.JsonReader;

import quarkenginehelper.QuarkReport.Bytecode;
import quarkenginehelper.QuarkReport.Crime;
import quarkenginehelper.QuarkReport.Invocation;
import quarkenginehelper.QuarkReport.MethodView;

public class ReportReader {

	public static QuarkReport parseReport(FileReader in) throws IOException {
		JsonReader reader = new JsonReader(in);
		QuarkReport report = new QuarkReport();

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "md5":
				report.md5 = reader.nextString();
				break;
			case "apk_filename":
				report.filename = reader.nextString();
				break;
			case "total_score":
				report.totalScore = reader.nextDouble();
				break;
			case "crimes":
				report.crimes = readCrimeArray(reader);
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		return report;
	}

	public static List<Crime> readCrimeArray(JsonReader reader) throws IOException {
		ArrayList<Crime> tempList = new ArrayList<Crime>(128);

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(readCrime(reader));
		reader.endArray();
		return tempList;
	}

	protected static Crime readCrime(JsonReader reader) throws IOException {
		Crime crime = new Crime();

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "crime":
				crime.description = reader.nextString();
				break;
			case "score":
				crime.score = reader.nextDouble();
				break;
			case "weight":
				crime.weight = reader.nextDouble();
				break;
			case "confidence":
				crime.confidence = reader.nextString();
				break;
			case "permissions":
				crime.permissions = readPermissionArray(reader);
				break;
			case "native_api":
			case "combination":
				crime.nativeApi = readMethodArray(reader);
				break;
			case "sequence":
			case "register":
				crime.sequence = readInvocationArray(reader);
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		return crime;
	}

	protected static String[] readPermissionArray(JsonReader reader) throws IOException {
		var tempList = new ArrayList<String>();

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(reader.nextString());
		reader.endArray();
		return tempList.toArray(new String[] {});
	}

	public static MethodView[] readMethodArray(JsonReader reader) throws IOException {
		var tempList = new ArrayList<MethodView>();

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(readMethod(reader));
		reader.endArray();
		return tempList.toArray(new MethodView[] {});
	}

	protected static MethodView readMethod(JsonReader reader) throws IOException {
		var methodView = new MethodView();

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			String value = reader.nextString();
			switch (name) {
			case "class":
				methodView.className = value;
			case "method":
				methodView.methodName = value;
			default:
			}
		}
		reader.endObject();

		return methodView;
	}

	protected static Bytecode readBytecode(JsonReader reader) throws IOException {
		var bytecode = new Bytecode();

		reader.beginArray();
		bytecode.mnenic = reader.nextString();
		List<String> registerList = new ArrayList<String>();
		while (reader.hasNext()) {
			registerList.add(reader.nextString());
		}
		bytecode.parameter = registerList.remove(registerList.size() - 1);
		bytecode.register = registerList.toArray(new String[] {});
		reader.endArray();

		return bytecode;
	}

	protected static Invocation[] readInvocationArray(JsonReader reader) throws IOException {
		var tempList = new ArrayList<Invocation>();

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(readInvocation(reader));
		reader.endArray();
		return tempList.toArray(new Invocation[] {});
	}

	protected static MethodView parseMethod(String fullname) throws IOException {
		var method = new MethodView();

		var pieces = fullname.split(" +", 3);
		if (pieces[1].length() == 0 || pieces[2].length() == 0)
			throw new IOException("Illegal Method Name %s".formatted(Arrays.toString(pieces)));

		// Class name
		var className = pieces[0].toCharArray();
		var newClassName = new char[className.length * 2];
		if (className[0] != 'L')
			throw new IOException("Illegal Method Name %s".formatted(Arrays.toString(pieces)));

		var index = 1; // The first char must is 'L'
		var newIndex = 0;
		while (index < className.length && newIndex < newClassName.length) {
			char c = className[index++];
			switch (c) {
			case '/':
				newClassName[newIndex++] = ':';
				newClassName[newIndex++] = ':';
				break;
			case ';':
				break;
			default:
				newClassName[newIndex++] = c;
			}
		}
		method.className = String.valueOf(newClassName).trim();

		// Method name
		method.methodName = pieces[1];

		// Descriptor
		method.descripter = pieces[2];
		return method;
	}

	protected static Invocation readInvocation(JsonReader reader) throws IOException {
		var invocation = new Invocation();

		reader.beginObject();
		String fullMethodName = reader.nextName();
		invocation.parent = parseMethod(fullMethodName);

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "first":
				invocation.first = readBytecode(reader);
				break;
			case "second":
				invocation.second = readBytecode(reader);
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		reader.endObject();

		return invocation;
	}

}
